// SQLite storage for registrations. Stores the minimum needed to deliver, and
// nothing identifying in the clear (schema v2):
//
//   registrations   user_idx  = HMAC(user pubkey)          lookup index
//                   token_hash = HMAC(platform, app, token) lookup index
//                   token_enc = AES-GCM(token)
//                   ident_enc = AES-GCM({user, relays, nwc})
//                   app, platform, apns_env, category bitmask, timestamps,
//                   validated_at (NULL = provisional: token not yet proven)
//   user_watermarks user_idx, ts                            replay state
//   notified_events HMAC(event id), hour bucket            restart-safe dedupe
//
// So the database file alone reveals counts, app ids/platforms, category
// bitmasks, timestamps and which rows share a (pseudonymous) user — not who
// the users are, their relays, NWC keys or tokens. With the key (held in a
// separate secret file) everything decrypts; pubkeys are decrypted into memory
// at load to build relay filters. Older plaintext databases are migrated in
// place on open (see migrateV1).
//
// Replay protection: newest-wins per (user, device) using the registration's
// `ts`, plus one replay watermark per user. Only live registrations are stored;
// removing one (unregister, dead token, eviction) deletes it and raises the
// user's watermark, so an older or replayed request for a device we don't hold
// can't (re)create it. The watermark table is bounded; when full, the watcher
// fails closed via a global watermark. Watermarks older than the registration
// timestamp window are moot and purged.
//
// Admission (see README "Capacity and admission"): per-user device cap, a
// budget of new users per hour, token validation before admission (done by the
// caller), and at capacity a validated newcomer may evict the oldest
// provisional registration; validated registrations are never evicted for
// capacity.
//
// The token HMAC covers (platform, app, token): a token registered under one
// app id can never affect the same token under another.

import Database from 'better-sqlite3';
import type { Limits } from './config.js';
import { log } from './log.js';
import type { Category, NwcConnection, Platform, RegistrationRequest } from './registration.js';
import { CATEGORIES } from './registration.js';
import { TokenCrypto } from './tokenCrypto.js';

export interface RegistrationSummary {
  user: string;
  tokenHash: string;
  app: string;
  platform: Platform;
  categories: Record<Category, boolean>;
  relays: string[];
  nwc: NwcConnection[];
}

export type ApnsEnv = 'production' | 'sandbox';

export interface Device {
  user: string;
  /** APNs environment the token was issued for (ignored for FCM). */
  apnsEnv: ApnsEnv;
  tokenHash: string;
  /** Registration version (its `ts`) — cleanup only removes this exact version. */
  ts: number;
  app: string;
  platform: Platform;
  token: string;
  categories: Record<Category, boolean>;
}

/** Operator view of a registration (admin CLI): never the token or its hash. */
export interface AdminRow {
  user: string;
  app: string;
  platform: Platform;
  categories: Record<Category, boolean>;
  relays: number;
  nwc: number;
  validated: boolean;
  updatedAt: number;
}

export type ApplyResult = 'registered' | 'updated' | 'unregistered' | 'stale' | 'limit' | 'invalid-token';

/**
 * Outcome of the token check made before admitting a new device:
 * undefined = not checked (provisional); 'unchecked' = the hourly check budget
 * was exhausted, so the device is refused rather than admitted unchecked.
 */
export type Validation = 'ok' | 'invalid' | 'unavailable' | 'unchecked';

const SCHEMA_VERSION = 2;
const HOUR = 3600;

const catMask = (c: Record<Category, boolean>): number =>
  CATEGORIES.reduce((m, k, i) => (c[k] ? m | (1 << i) : m), 0);
const maskCats = (m: number): Record<Category, boolean> =>
  Object.fromEntries(CATEGORIES.map((k, i) => [k, (m & (1 << i)) !== 0])) as Record<Category, boolean>;

interface Row {
  user_idx: string;
  token_hash: string;
  app: string;
  platform: Platform;
  token_enc: Buffer | null;
  ident_enc: Buffer;
  categories: number;
  ts: number;
  updated_at: number;
  apns_env: ApnsEnv | null;
  validated_at: number | null;
}

interface Ident {
  user: string;
  relays: string[];
  nwc: NwcConnection[];
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS registrations (
    user_idx TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    app TEXT NOT NULL,
    platform TEXT NOT NULL,
    token_enc BLOB,
    ident_enc BLOB NOT NULL,
    categories INTEGER NOT NULL DEFAULT 0,
    ts INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    apns_env TEXT,
    validated_at INTEGER,
    PRIMARY KEY (user_idx, token_hash)
  );
  CREATE INDEX IF NOT EXISTS registrations_updated ON registrations(updated_at);
  CREATE INDEX IF NOT EXISTS registrations_provisional ON registrations(validated_at, updated_at);
  CREATE TABLE IF NOT EXISTS notified_events (
    id TEXT PRIMARY KEY,
    at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS notified_events_at ON notified_events(at);
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS user_watermarks (user_idx TEXT PRIMARY KEY, ts INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0);
  CREATE INDEX IF NOT EXISTS user_watermarks_inactive ON user_watermarks(active, ts);
`;

export class Store {
  private readonly db: Database.Database;
  private readonly crypto: TokenCrypto;
  /** Fixed-window budget of new users admitted per hour (in memory). */
  private newUsers = { hour: -1, used: 0 };
  /** Fixed-window budget of provider token checks per hour (in memory). */
  private tokenChecks = { hour: -1, used: 0 };

  constructor(
    path: string,
    tokenKey: Buffer,
    private readonly limits: Limits,
    /** Fallback: app ids whose APNs tokens are sandbox tokens when a registration doesn't say. */
    private readonly sandboxApps: readonly string[] = [],
  ) {
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('secure_delete = ON');
    // The admin CLI may write while the watcher runs.
    this.db.pragma('busy_timeout = 5000');
    this.crypto = new TokenCrypto(tokenKey);
    if (this.columns('registrations').includes('user')) this.migrateV1();
    this.db.exec(SCHEMA);
    this.db.prepare(`INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', ?)`).run(SCHEMA_VERSION);
    // Every live user holds a reserved replay-watermark row (backfill).
    this.db.exec(`INSERT OR IGNORE INTO user_watermarks (user_idx, ts)
      SELECT DISTINCT user_idx, COALESCE((SELECT v FROM meta WHERE k = 'reject_new_before'), 0) FROM registrations`);
    this.reconcileWatermarks();
  }

  private columns(table: string): string[] {
    return (this.db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).map((c) => c.name);
  }

  /**
   * v1 -> v2: replace plaintext pubkeys, relays and NWC keys with the HMAC
   * index + encrypted identity blob, re-key watermarks by the index, and hash
   * notified event ids. One transaction; then VACUUM + WAL truncate so the
   * plaintext pages don't linger in the file (secure_delete zeroes freed pages).
   * Device tokens were already encrypted, with associated data that still
   * matches, so they are carried over as is.
   */
  private migrateV1(): void {
    let regs = 0;
    const tx = this.db.transaction(() => {
      const hasEnv = this.columns('registrations').includes('apns_env');
      this.db.exec(`DROP INDEX IF EXISTS registrations_updated; ALTER TABLE registrations RENAME TO registrations_v1;`);
      const wmCols = this.columns('user_watermarks');
      if (wmCols.length) this.db.exec(`DROP INDEX IF EXISTS user_watermarks_inactive; ALTER TABLE user_watermarks RENAME TO user_watermarks_v1;`);
      const hasNotified = this.columns('notified_events').length > 0;
      if (hasNotified) this.db.exec(`DROP INDEX IF EXISTS notified_events_at; ALTER TABLE notified_events RENAME TO notified_events_v1;`);
      this.db.exec(SCHEMA);

      const ins = this.db.prepare(`INSERT OR REPLACE INTO registrations
        (user_idx, token_hash, app, platform, token_enc, ident_enc, categories, ts, updated_at, apns_env, validated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`);
      const old = this.db
        .prepare(`SELECT user, token_hash, app, platform, token_enc, categories, relays, nwc, ts, updated_at${hasEnv ? ', apns_env' : ''} FROM registrations_v1`)
        .all() as {
        user: string;
        token_hash: string;
        app: string;
        platform: string;
        token_enc: Buffer | null;
        categories: number;
        relays: string;
        nwc: string;
        ts: number;
        updated_at: number;
        apns_env?: string | null;
      }[];
      for (const r of old) {
        const idx = this.uidx(r.user);
        const ident: Ident = { user: r.user, relays: JSON.parse(r.relays) as string[], nwc: JSON.parse(r.nwc) as NwcConnection[] };
        ins.run(idx, r.token_hash, r.app, r.platform, r.token_enc, this.sealIdent(idx, r.token_hash, ident), r.categories, r.ts, r.updated_at, r.apns_env ?? null);
        regs++;
      }
      this.db.exec(`DROP TABLE registrations_v1`);

      if (wmCols.length) {
        const wm = this.db.prepare(`INSERT OR REPLACE INTO user_watermarks (user_idx, ts, active) VALUES (?, ?, 0)`);
        for (const r of this.db.prepare(`SELECT user, ts FROM user_watermarks_v1`).all() as { user: string; ts: number }[]) {
          wm.run(this.uidx(r.user), r.ts);
        }
        this.db.exec(`DROP TABLE user_watermarks_v1`);
      }
      if (hasNotified) {
        const ne = this.db.prepare(`INSERT OR IGNORE INTO notified_events (id, at) VALUES (?, ?)`);
        for (const r of this.db.prepare(`SELECT id, at FROM notified_events_v1`).all() as { id: string; at: number }[]) {
          ne.run(this.eventKey(r.id), Math.floor(r.at / HOUR) * HOUR);
        }
        this.db.exec(`DROP TABLE notified_events_v1`);
      }
      this.db.prepare(`INSERT OR REPLACE INTO meta (k, v) VALUES ('schema_version', ?)`).run(SCHEMA_VERSION);
    });
    tx();
    this.db.exec('VACUUM');
    this.db.pragma('wal_checkpoint(TRUNCATE)');
    log.info('database migrated: identity columns encrypted', { schema: SCHEMA_VERSION, registrations: regs });
  }

  close(): void {
    this.db.close();
  }

  ping(): boolean {
    return this.db.prepare('SELECT 1 AS ok').get() !== undefined;
  }

  /** Keyed lookup index of a user pubkey (never stored in the clear). */
  private uidx(user: string): string {
    return this.crypto.index('user', user);
  }

  private eventKey(id: string): string {
    return this.crypto.index('event', id);
  }

  private tokenAad(user: string, tokenHash: string, app: string, platform: string): string {
    return `${user}|${tokenHash}|${app}|${platform}`;
  }

  private sealIdent(idx: string, tokenHash: string, ident: Ident): Buffer {
    return this.crypto.encryptRow(JSON.stringify(ident), `ident|${idx}|${tokenHash}`);
  }

  /** Decrypt a row's identity; throws on a wrong key / tampered row. */
  private openIdent(r: Pick<Row, 'user_idx' | 'token_hash' | 'ident_enc'>): Ident {
    const ident = JSON.parse(this.crypto.decryptRow(r.ident_enc, `ident|${r.user_idx}|${r.token_hash}`)) as Ident;
    if (this.uidx(ident.user) !== r.user_idx) throw new Error('identity does not match its index');
    return ident;
  }

  tokenHash(platform: string, app: string, token: string): string {
    return this.crypto.tokenHash(platform, app, token);
  }

  /**
   * The user's replay watermark. Users with their own row are ordered by it
   * alone; only users without one (never settled anything here) fall under
   * the global fail-closed watermark, so saturation can't touch existing users.
   */
  private watermark(idx: string): number {
    const u = this.db.prepare(`SELECT ts FROM user_watermarks WHERE user_idx = ?`).get(idx) as { ts: number } | undefined;
    if (u) return u.ts;
    return this.globalWatermark();
  }

  private hasLive(idx: string): boolean {
    return !!this.db.prepare('SELECT 1 FROM registrations WHERE user_idx = ? LIMIT 1').get(idx);
  }

  private globalWatermark(): number {
    return (this.db.prepare(`SELECT v FROM meta WHERE k = 'reject_new_before'`).get() as { v: number } | undefined)?.v ?? 0;
  }

  private raiseGlobal(ts: number): void {
    this.db
      .prepare(`INSERT INTO meta (k, v) VALUES ('reject_new_before', ?) ON CONFLICT(k) DO UPDATE SET v = MAX(v, excluded.v)`)
      .run(ts);
  }

  /**
   * Count of watermark rows whose user has no live registration. Maintained
   * incrementally (O(1) per request); fully recomputed only at startup and in
   * the hourly sweep, together with each row's `active` flag.
   */
  private inactive = 0;

  private reconcileWatermarks(): void {
    this.db.exec(`UPDATE user_watermarks SET active = EXISTS (SELECT 1 FROM registrations r WHERE r.user_idx = user_watermarks.user_idx)`);
    this.inactive = (this.db.prepare(`SELECT COUNT(*) AS n FROM user_watermarks WHERE active = 0`).get() as { n: number }).n;
  }

  /** Every user with a live registration holds an active row (reserved on admission). */
  private ensureRow(idx: string): void {
    const row = this.db.prepare(`SELECT active FROM user_watermarks WHERE user_idx = ?`).get(idx) as { active: number } | undefined;
    if (!row) {
      this.db.prepare(`INSERT INTO user_watermarks (user_idx, ts, active) VALUES (?, ?, 1)`).run(idx, this.globalWatermark());
    } else if (!row.active) {
      this.db.prepare(`UPDATE user_watermarks SET active = 1 WHERE user_idx = ?`).run(idx);
      this.inactive--;
    }
  }

  /** Call after removing a device: if it was the user's last, their row becomes inactive (and may be compacted). */
  private afterRemoval(idx: string): void {
    if (this.hasLive(idx)) return;
    if (this.db.prepare(`UPDATE user_watermarks SET active = 0 WHERE user_idx = ? AND active = 1`).run(idx).changes) this.inactive++;
    this.compactInactive();
  }

  /**
   * Remember that everything this user sent up to `ts` is settled.
   * Rows: live users always have one (bounded by maxRegistrations); users
   * without a live registration may hold at most maxWatermarkUsers rows in
   * total. Past that, fail closed: the ordering goes into the global
   * watermark with its full timestamp, which only applies to users without a
   * row (never to live users).
   */
  private raiseWatermark(idx: string, ts: number): void {
    if (this.db.prepare(`UPDATE user_watermarks SET ts = MAX(ts, ?) WHERE user_idx = ?`).run(ts, idx).changes) return;
    if (this.hasLive(idx)) {
      this.db.prepare(`INSERT INTO user_watermarks (user_idx, ts, active) VALUES (?, ?, 1)`).run(idx, Math.max(ts, this.globalWatermark()));
    } else if (this.inactive < this.limits.maxWatermarkUsers) {
      // A first row starts no lower than the global watermark, which may hold
      // ordering settled for this user while they had no row.
      this.db.prepare(`INSERT INTO user_watermarks (user_idx, ts, active) VALUES (?, ?, 0)`).run(idx, Math.max(ts, this.globalWatermark()));
      this.inactive++;
    } else {
      this.raiseGlobal(ts);
    }
  }

  /** Keep inactive rows within budget by folding the oldest excess into the global cutoff (indexed, no scan). */
  private compactInactive(): void {
    const excess = this.inactive - this.limits.maxWatermarkUsers;
    if (excess <= 0) return;
    const rows = this.db
      .prepare(`SELECT user_idx, ts FROM user_watermarks WHERE active = 0 ORDER BY ts ASC LIMIT ?`)
      .all(excess) as { user_idx: string; ts: number }[];
    for (const r of rows) {
      this.raiseGlobal(r.ts);
      this.db.prepare(`DELETE FROM user_watermarks WHERE user_idx = ?`).run(r.user_idx);
      this.inactive--;
    }
  }

  private deleteRow(idx: string, tokenHash: string): void {
    this.db.prepare('DELETE FROM registrations WHERE user_idx = ? AND token_hash = ?').run(idx, tokenHash);
  }

  /** Remove one exact registration version, settling its ts into the user's watermark. */
  private removeVersion(idx: string, tokenHash: string, ts: number): boolean {
    const live = this.db.prepare('SELECT 1 FROM registrations WHERE user_idx = ? AND token_hash = ? AND ts = ?').get(idx, tokenHash, ts);
    if (!live) return false;
    this.raiseWatermark(idx, ts);
    this.deleteRow(idx, tokenHash);
    this.afterRemoval(idx);
    return true;
  }

  private transact<T>(fn: () => T): T {
    try {
      return this.db.transaction(fn)();
    } catch (e) {
      this.reconcileWatermarks(); // the transaction rolled back; resync the in-memory count
      throw e;
    }
  }

  /**
   * True if `apply` would reject `req` as stale. Cheap pre-check, run before
   * the user's rate allowance is charged, so replays never consume it.
   */
  isStale(req: RegistrationRequest): boolean {
    const idx = this.uidx(req.user);
    const row = this.db
      .prepare('SELECT ts FROM registrations WHERE user_idx = ? AND token_hash = ?')
      .get(idx, this.tokenHash(req.platform, req.app, req.token)) as { ts: number } | undefined;
    return row ? req.ts <= row.ts : req.ts <= this.watermark(idx);
  }

  /** Would this register create a new device (so its token must be validated first)? */
  isNewDevice(req: RegistrationRequest): boolean {
    return (
      req.action === 'register' &&
      !this.db
        .prepare('SELECT 1 FROM registrations WHERE user_idx = ? AND token_hash = ?')
        .get(this.uidx(req.user), this.tokenHash(req.platform, req.app, req.token))
    );
  }

  private newUserBudgetOk(nowSec: number): boolean {
    const max = this.limits.maxNewUsersPerHour;
    if (max === 0) return true;
    const hour = Math.floor(nowSec / HOUR);
    if (this.newUsers.hour !== hour) this.newUsers = { hour, used: 0 };
    return this.newUsers.used < max;
  }

  /**
   * Take one provider token check from the hourly budget (4x the new-user
   * budget; unlimited if that is). Refused requests don't consume the new-user
   * budget, so without this, fresh keys with made-up tokens could trigger
   * unbounded provider requests and stall the (sequential) registration inbox.
   */
  takeTokenCheck(nowSec: number): boolean {
    const max = this.limits.maxNewUsersPerHour * 4;
    if (max === 0) return true;
    const hour = Math.floor(nowSec / HOUR);
    if (this.tokenChecks.hour !== hour) this.tokenChecks = { hour, used: 0 };
    if (this.tokenChecks.used >= max) return false;
    this.tokenChecks.used++;
    return true;
  }

  /**
   * Admission decision for a new device (no writes). `validated`: whether its
   * token passed the provider check. Returns the capacity victim to evict (a
   * provisional registration), null if there is room, or 'limit'.
   */
  private admission(
    idx: string,
    req: RegistrationRequest,
    validated: boolean,
    nowSec: number,
  ): { ownVictims: { token_hash: string; ts: number }[]; capVictim: { user_idx: string; token_hash: string; ts: number } | null } | 'limit' {
    // Per-user device cap: evict the least recently refreshed — keeping its
    // full ts as the watermark. An incoming device not newer than the one it
    // would evict is refused instead (ordering is never lowered).
    const devices = this.db
      .prepare('SELECT token_hash, ts FROM registrations WHERE user_idx = ? ORDER BY updated_at ASC')
      .all(idx) as { token_hash: string; ts: number }[];
    const excess = devices.length - this.limits.maxDevicesPerUser + 1;
    const ownVictims = excess > 0 ? devices.slice(0, excess) : [];
    if (ownVictims.some((v) => v.ts >= req.ts)) return 'limit';
    // A burst of fresh keys can only claim maxNewUsersPerHour slots per hour.
    if (devices.length === 0 && !this.newUserBudgetOk(nowSec)) return 'limit';
    let capVictim = null;
    if (ownVictims.length === 0 && this.countActive() >= this.limits.maxRegistrations) {
      // Full: only a validated newcomer may displace the oldest provisional
      // (never-validated, never-delivered) registration. Validated ones stay.
      if (!validated) return 'limit';
      capVictim =
        (this.db
          .prepare('SELECT user_idx, token_hash, ts FROM registrations WHERE validated_at IS NULL ORDER BY updated_at ASC LIMIT 1')
          .get() as { user_idx: string; token_hash: string; ts: number } | undefined) ?? null;
      if (!capVictim) return 'limit';
    }
    return { ownVictims, capVictim };
  }

  /**
   * Cheap pre-check (no writes) before spending a provider request on token
   * validation: false if a new device for this request would be refused even
   * with a valid token.
   */
  wouldAdmit(req: RegistrationRequest, nowSec: number): boolean {
    return this.admission(this.uidx(req.user), req, true, nowSec) !== 'limit';
  }

  /**
   * Newest-wins per (user, device token): `ts` must strictly increase.
   * Only live registrations are stored. Removing one (unregister, dead token,
   * device eviction) deletes the row and raises the user's replay watermark,
   * so no older request for a device we don't hold can (re)create it.
   *
   * `validation` is the token check for a new device: 'invalid' refuses it;
   * 'ok' admits it validated; 'unavailable'/undefined admits it provisionally.
   * Refusals settle `req.ts`, so a replay of the request is stale (rejected
   * before it can charge the rate allowance or trigger another token check).
   */
  apply(req: RegistrationRequest, nowSec: number, validation?: Validation): ApplyResult {
    const idx = this.uidx(req.user);
    const tokenHash = this.tokenHash(req.platform, req.app, req.token);
    return this.transact((): ApplyResult => {
      const existing = this.db
        .prepare('SELECT ts FROM registrations WHERE user_idx = ? AND token_hash = ?')
        .get(idx, tokenHash) as { ts: number } | undefined;
      if (existing ? req.ts <= existing.ts : req.ts <= this.watermark(idx)) return 'stale';

      if (req.action === 'unregister') {
        this.raiseWatermark(idx, req.ts); // while still live, the user's reserved row is used
        if (existing) {
          this.deleteRow(idx, tokenHash);
          this.afterRemoval(idx);
        }
        return 'unregistered';
      }

      if (!existing) {
        if (validation === 'invalid') {
          this.raiseWatermark(idx, req.ts);
          return 'invalid-token';
        }
        if (validation === 'unchecked') {
          this.raiseWatermark(idx, req.ts);
          return 'limit';
        }
        const isNewUser = !this.hasLive(idx);
        const adm = this.admission(idx, req, validation === 'ok', nowSec);
        if (adm === 'limit') {
          this.raiseWatermark(idx, req.ts);
          return 'limit';
        }
        for (const v of adm.ownVictims) {
          this.raiseWatermark(idx, v.ts);
          this.deleteRow(idx, v.token_hash);
        }
        if (adm.capVictim) this.removeVersion(adm.capVictim.user_idx, adm.capVictim.token_hash, adm.capVictim.ts);
        if (isNewUser && this.limits.maxNewUsersPerHour > 0) this.newUsers.used++;
      }

      const enc = this.crypto.encrypt(req.token, this.tokenAad(req.user, tokenHash, req.app, req.platform));
      const ident = this.sealIdent(idx, tokenHash, { user: req.user, relays: req.relays, nwc: req.nwc });
      const validatedAt = !existing && validation === 'ok' ? nowSec : null;
      this.db
        .prepare(
          `INSERT INTO registrations (user_idx, token_hash, app, platform, token_enc, ident_enc, categories, ts, updated_at, apns_env, validated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(user_idx, token_hash) DO UPDATE SET app = excluded.app, platform = excluded.platform,
             token_enc = excluded.token_enc, ident_enc = excluded.ident_enc, categories = excluded.categories,
             ts = excluded.ts, updated_at = excluded.updated_at, apns_env = excluded.apns_env,
             validated_at = COALESCE(excluded.validated_at, registrations.validated_at)`,
        )
        .run(idx, tokenHash, req.app, req.platform, enc, ident, catMask(req.categories), req.ts, nowSec, req.apnsEnv ?? null, validatedAt);
      if (!existing) this.ensureRow(idx); // reserve this live user's replay state
      return existing ? 'updated' : 'registered';
    });
  }

  /**
   * Invalid-token cleanup: remove exactly the registration version that was
   * sent (a newer one accepted meanwhile is left alone).
   */
  removeRegistration(user: string, tokenHash: string, ts: number): boolean {
    const idx = this.uidx(user);
    return this.transact(() => this.removeVersion(idx, tokenHash, ts));
  }

  /** A push to this registration was accepted: its token is proven (no longer provisional). */
  markValidated(user: string, tokenHash: string, ts: number, nowSec: number): void {
    this.db
      .prepare('UPDATE registrations SET validated_at = ? WHERE user_idx = ? AND token_hash = ? AND ts = ? AND validated_at IS NULL')
      .run(nowSec, this.uidx(user), tokenHash, ts);
  }

  /** Is this exact registration version still live with `category` on? (checked right before each send) */
  isCurrent(user: string, tokenHash: string, ts: number, category: Category): boolean {
    const row = this.db
      .prepare('SELECT categories FROM registrations WHERE user_idx = ? AND token_hash = ? AND ts = ?')
      .get(this.uidx(user), tokenHash, ts) as { categories: number } | undefined;
    return !!row && maskCats(row.categories)[category];
  }

  /** Rows whose identity can't be decrypted (wrong key, tampering) are unusable: drop them. */
  private dropUnreadable(r: Pick<Row, 'user_idx' | 'token_hash' | 'ts'>): void {
    try {
      this.transact(() => this.removeVersion(r.user_idx, r.token_hash, r.ts));
    } catch (e) {
      log.error('unreadable registration cleanup failed', { err: e as Error });
    }
  }

  /** Active registrations without tokens, identities decrypted — for the subscription plan and event routing. */
  listActive(): RegistrationSummary[] {
    const rows = this.db
      .prepare('SELECT user_idx, token_hash, app, platform, ident_enc, categories, ts FROM registrations WHERE token_enc IS NOT NULL')
      .all() as Row[];
    const out: RegistrationSummary[] = [];
    let unreadable = 0;
    for (const r of rows) {
      let ident: Ident;
      try {
        ident = this.openIdent(r);
      } catch {
        unreadable++;
        this.dropUnreadable(r);
        continue;
      }
      out.push({
        user: ident.user,
        tokenHash: r.token_hash,
        app: r.app,
        platform: r.platform,
        categories: maskCats(r.categories),
        relays: ident.relays,
        nwc: ident.nwc,
      });
    }
    if (unreadable) log.error('dropped registrations that could not be decrypted (wrong token key?)', { count: unreadable });
    return out;
  }

  /** Decrypted devices for a user (tokens only leave the DB here, for delivery). */
  devicesFor(user: string): Device[] {
    const rows = this.db
      .prepare(
        'SELECT user_idx, token_hash, app, platform, token_enc, categories, ts, apns_env FROM registrations WHERE user_idx = ? AND token_enc IS NOT NULL',
      )
      .all(this.uidx(user)) as Row[];
    const out: Device[] = [];
    for (const r of rows) {
      try {
        out.push({
          user,
          apnsEnv: r.apns_env ?? (this.sandboxApps.includes(r.app) ? 'sandbox' : 'production'),
          tokenHash: r.token_hash,
          ts: r.ts,
          app: r.app,
          platform: r.platform,
          token: this.crypto.decrypt(r.token_enc!, this.tokenAad(user, r.token_hash, r.app, r.platform)),
          categories: maskCats(r.categories),
        });
      } catch {
        // Wrong key or tampered row: unusable, drop it.
        this.dropUnreadable(r);
      }
    }
    return out;
  }

  private notifiedRows = -1;
  private notifiedBudget = { minute: 0, used: 0 };

  /**
   * Restart-safe dedupe for events that triggered pushes. Returns false only if
   * the id was already recorded. Stores a keyed hash of the id and an hour
   * bucket, not the id or exact time. Bounded: a hard row cap and a per-minute
   * insert budget; past either, the id simply isn't persisted (the in-memory
   * dedupe still applies), so spam can't grow the disk or stall the thread.
   */
  markNotified(id: string, nowSec: number): boolean {
    const key = this.eventKey(id);
    if (this.db.prepare('SELECT 1 FROM notified_events WHERE id = ?').get(key)) return false;
    const minute = Math.floor(nowSec / 60);
    if (this.notifiedBudget.minute !== minute) this.notifiedBudget = { minute, used: 0 };
    if (this.notifiedRows < 0) this.notifiedRows = (this.db.prepare('SELECT COUNT(*) AS n FROM notified_events').get() as { n: number }).n;
    if (this.notifiedBudget.used >= this.limits.notifiedInsertsPerMinute || this.notifiedRows >= this.limits.notifiedMaxRows) return true;
    this.notifiedBudget.used++;
    this.notifiedRows += this.db
      .prepare('INSERT OR IGNORE INTO notified_events (id, at) VALUES (?, ?)')
      .run(key, Math.floor(nowSec / HOUR) * HOUR).changes;
    return true;
  }

  /** Expire unrefreshed registrations, purge moot watermarks, prune notified ids. */
  sweep(nowSec: number): { expired: number; notifiedPruned: number } {
    const ttl = this.limits.registrationTtlDays * 86400;
    // (token_enc IS NULL only exists in pre-0.1 databases; they're unusable.)
    const expired = this.db
      .prepare('DELETE FROM registrations WHERE updated_at < ? OR token_enc IS NULL')
      .run(nowSec - ttl).changes;
    // A watermark W only blocks requests with ts <= W, and once W is older
    // than the registration timestamp window every such request is refused
    // as too old anyway — so a watermark of a user without a live
    // registration is kept no longer than that window (purged hourly). Live
    // users keep their reserved row.
    this.reconcileWatermarks(); // expiry may have made users inactive
    this.db.prepare('DELETE FROM user_watermarks WHERE active = 0 AND ts < ?').run(nowSec - this.limits.registrationMaxAgeSec);
    this.reconcileWatermarks();
    this.compactInactive();
    // Hour buckets: keep a bucket until all of it is past the retention.
    const notifiedPruned = this.db
      .prepare('DELETE FROM notified_events WHERE at < ?')
      .run(nowSec - this.limits.notifiedRetentionSec - HOUR).changes;
    this.notifiedRows = -1; // recount lazily
    return { expired, notifiedPruned };
  }

  countActive(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM registrations WHERE token_enc IS NOT NULL').get() as { n: number }).n;
  }

  /** Registrations whose token has not been proven yet (evictable at capacity). */
  countProvisional(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM registrations WHERE token_enc IS NOT NULL AND validated_at IS NULL').get() as { n: number })
      .n;
  }

  // ---- operator tooling (admin CLI) -------------------------------------

  /** Every registration, identity decrypted; never tokens or token hashes. */
  adminList(user?: string): AdminRow[] {
    const rows = (
      user
        ? this.db.prepare('SELECT * FROM registrations WHERE user_idx = ? ORDER BY updated_at DESC').all(this.uidx(user))
        : this.db.prepare('SELECT * FROM registrations ORDER BY updated_at DESC').all()
    ) as Row[];
    const out: AdminRow[] = [];
    for (const r of rows) {
      let ident: Ident;
      try {
        ident = this.openIdent(r);
      } catch {
        continue; // unreadable rows are dropped by the watcher itself
      }
      out.push({
        user: ident.user,
        app: r.app,
        platform: r.platform,
        categories: maskCats(r.categories),
        relays: ident.relays.length,
        nwc: ident.nwc.length,
        validated: r.validated_at !== null,
        updatedAt: r.updated_at,
      });
    }
    return out;
  }

  /** Remove all of a user's registrations (cleanup, not a ban: a newer registration is accepted again). */
  purgeUser(user: string): number {
    const idx = this.uidx(user);
    return this.transact(() => {
      const rows = this.db.prepare('SELECT token_hash, ts FROM registrations WHERE user_idx = ?').all(idx) as { token_hash: string; ts: number }[];
      let n = 0;
      for (const r of rows) if (this.removeVersion(idx, r.token_hash, r.ts)) n++;
      return n;
    });
  }

  /** Remove provisional registrations not refreshed since `beforeSec`. */
  purgeProvisional(beforeSec: number): number {
    return this.transact(() => {
      const rows = this.db
        .prepare('SELECT user_idx, token_hash, ts FROM registrations WHERE validated_at IS NULL AND updated_at < ?')
        .all(beforeSec) as { user_idx: string; token_hash: string; ts: number }[];
      let n = 0;
      for (const r of rows) if (this.removeVersion(r.user_idx, r.token_hash, r.ts)) n++;
      return n;
    });
  }
}
