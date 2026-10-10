// SQLite storage for registrations. Stores the minimum needed to deliver:
// user pubkey, app id, platform, encrypted token (+ HMAC index), category
// bitmask, relays, NWC (client, wallet) pubkeys, APNs environment, timestamps.
//
// Replay protection: newest-wins per (user, device) using the registration's
// `ts`, plus one replay watermark per user. Only live registrations are stored;
// removing one (unregister, dead token, eviction) deletes it and raises the
// user's watermark, so an older or replayed request for a device we don't hold
// can't (re)create it. The watermark table is bounded; when full, the watcher
// fails closed via a global watermark. Watermarks older than the registration
// timestamp window are moot and purged.
//
// The token HMAC covers (platform, app, token): a token registered under one
// app id can never affect the same token under another.

import Database from 'better-sqlite3';
import type { Limits } from './config.js';
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

export type ApplyResult = 'registered' | 'updated' | 'unregistered' | 'stale' | 'limit';

const catMask = (c: Record<Category, boolean>): number =>
  CATEGORIES.reduce((m, k, i) => (c[k] ? m | (1 << i) : m), 0);
const maskCats = (m: number): Record<Category, boolean> =>
  Object.fromEntries(CATEGORIES.map((k, i) => [k, (m & (1 << i)) !== 0])) as Record<Category, boolean>;

interface Row {
  user: string;
  token_hash: string;
  app: string;
  platform: Platform;
  token_enc: Buffer | null;
  categories: number;
  relays: string;
  nwc: string;
  ts: number;
  updated_at: number;
  apns_env: ApnsEnv | null;
}


export class Store {
  private readonly db: Database.Database;
  private readonly crypto: TokenCrypto;

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
    this.crypto = new TokenCrypto(tokenKey);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS registrations (
        user TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        app TEXT NOT NULL,
        platform TEXT NOT NULL,
        token_enc BLOB,
        categories INTEGER NOT NULL DEFAULT 0,
        relays TEXT NOT NULL DEFAULT '[]',
        nwc TEXT NOT NULL DEFAULT '[]',
        ts INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (user, token_hash)
      );
      CREATE INDEX IF NOT EXISTS registrations_updated ON registrations(updated_at);
      CREATE TABLE IF NOT EXISTS notified_events (
        id TEXT PRIMARY KEY,
        at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS notified_events_at ON notified_events(at);
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS user_watermarks (user TEXT PRIMARY KEY, ts INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0);
    `);
    // NULL = not specified by the registration: resolved at delivery through
    // the operator's sandbox-app fallback (so pre-existing rows keep their
    // previous behaviour).
    const cols = this.db.prepare(`PRAGMA table_info(registrations)`).all() as { name: string }[];
    if (!cols.some((c) => c.name === 'apns_env')) this.db.exec(`ALTER TABLE registrations ADD COLUMN apns_env TEXT`);
    const wcols = this.db.prepare(`PRAGMA table_info(user_watermarks)`).all() as { name: string }[];
    if (!wcols.some((c) => c.name === 'active')) this.db.exec(`ALTER TABLE user_watermarks ADD COLUMN active INTEGER NOT NULL DEFAULT 0`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS user_watermarks_inactive ON user_watermarks(active, ts)`);
    // Every live user holds a reserved replay-watermark row (backfill older databases).
    this.db.exec(`INSERT OR IGNORE INTO user_watermarks (user, ts)
      SELECT DISTINCT user, COALESCE((SELECT v FROM meta WHERE k = 'reject_new_before'), 0) FROM registrations`);
    this.reconcileWatermarks();
  }

  close(): void {
    this.db.close();
  }

  ping(): boolean {
    return this.db.prepare('SELECT 1 AS ok').get() !== undefined;
  }

  private aad(user: string, tokenHash: string, app: string, platform: string): string {
    return `${user}|${tokenHash}|${app}|${platform}`;
  }

  tokenHash(platform: string, app: string, token: string): string {
    return this.crypto.tokenHash(platform, app, token);
  }

  /**
   * The user's replay watermark. Users with their own row are ordered by it
   * alone; only users without one (never settled anything here) fall under
   * the global fail-closed watermark, so saturation can't touch existing users.
   */
  private watermark(user: string): number {
    const u = this.db.prepare(`SELECT ts FROM user_watermarks WHERE user = ?`).get(user) as { ts: number } | undefined;
    if (u) return u.ts;
    return (this.db.prepare(`SELECT v FROM meta WHERE k = 'reject_new_before'`).get() as { v: number } | undefined)?.v ?? 0;
  }

  private hasLive(user: string): boolean {
    return !!this.db.prepare('SELECT 1 FROM registrations WHERE user = ? LIMIT 1').get(user);
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
    this.db.exec(`UPDATE user_watermarks SET active = EXISTS (SELECT 1 FROM registrations r WHERE r.user = user_watermarks.user)`);
    this.inactive = (this.db.prepare(`SELECT COUNT(*) AS n FROM user_watermarks WHERE active = 0`).get() as { n: number }).n;
  }

  /** Every user with a live registration holds an active row (reserved on admission). */
  private ensureRow(user: string): void {
    const row = this.db.prepare(`SELECT active FROM user_watermarks WHERE user = ?`).get(user) as { active: number } | undefined;
    if (!row) {
      this.db.prepare(`INSERT INTO user_watermarks (user, ts, active) VALUES (?, ?, 1)`).run(user, this.globalWatermark());
    } else if (!row.active) {
      this.db.prepare(`UPDATE user_watermarks SET active = 1 WHERE user = ?`).run(user);
      this.inactive--;
    }
  }

  /** Call after removing a device: if it was the user's last, their row becomes inactive (and may be compacted). */
  private afterRemoval(user: string): void {
    if (this.hasLive(user)) return;
    if (this.db.prepare(`UPDATE user_watermarks SET active = 0 WHERE user = ? AND active = 1`).run(user).changes) this.inactive++;
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
  private raiseWatermark(user: string, ts: number): void {
    if (this.db.prepare(`UPDATE user_watermarks SET ts = MAX(ts, ?) WHERE user = ?`).run(ts, user).changes) return;
    if (this.hasLive(user)) {
      this.db.prepare(`INSERT INTO user_watermarks (user, ts, active) VALUES (?, ?, 1)`).run(user, Math.max(ts, this.globalWatermark()));
    } else if (this.inactive < this.limits.maxWatermarkUsers) {
      // A first row starts no lower than the global watermark, which may hold
      // ordering settled for this user while they had no row.
      this.db.prepare(`INSERT INTO user_watermarks (user, ts, active) VALUES (?, ?, 0)`).run(user, Math.max(ts, this.globalWatermark()));
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
      .prepare(`SELECT user, ts FROM user_watermarks WHERE active = 0 ORDER BY ts ASC LIMIT ?`)
      .all(excess) as { user: string; ts: number }[];
    for (const r of rows) {
      this.raiseGlobal(r.ts);
      this.db.prepare(`DELETE FROM user_watermarks WHERE user = ?`).run(r.user);
      this.inactive--;
    }
  }

  private deleteRow(user: string, tokenHash: string): void {
    this.db.prepare('DELETE FROM registrations WHERE user = ? AND token_hash = ?').run(user, tokenHash);
  }

  /**
   * True if `apply` would reject `req` as stale. Cheap pre-check, run before
   * the user's rate allowance is charged, so replays never consume it.
   */
  isStale(req: RegistrationRequest): boolean {
    const row = this.db
      .prepare('SELECT ts FROM registrations WHERE user = ? AND token_hash = ?')
      .get(req.user, this.tokenHash(req.platform, req.app, req.token)) as { ts: number } | undefined;
    return row ? req.ts <= row.ts : req.ts <= this.watermark(req.user);
  }

  /**
   * Newest-wins per (user, device token): `ts` must strictly increase.
   * Only live registrations are stored. Removing one (unregister, dead token,
   * device eviction) deletes the row and raises the user's replay watermark,
   * so no older request for a device we don't hold can (re)create it.
   */
  apply(req: RegistrationRequest, nowSec: number): ApplyResult {
    const tokenHash = this.tokenHash(req.platform, req.app, req.token);
    const tx = this.db.transaction((): ApplyResult => {
      const existing = this.db
        .prepare('SELECT ts FROM registrations WHERE user = ? AND token_hash = ?')
        .get(req.user, tokenHash) as { ts: number } | undefined;
      if (existing ? req.ts <= existing.ts : req.ts <= this.watermark(req.user)) return 'stale';

      if (req.action === 'unregister') {
        this.raiseWatermark(req.user, req.ts); // while still live, the user's reserved row is used
        if (existing) {
          this.deleteRow(req.user, tokenHash);
          this.afterRemoval(req.user);
        }
        return 'unregistered';
      }

      if (!existing) {
        // Refusals settle req.ts too, so a replay of this request is stale
        // (rejected before it can charge the user's rate allowance).
        if (this.countActive() >= this.limits.maxRegistrations) {
          this.raiseWatermark(req.user, req.ts);
          return 'limit';
        }
        // Cap devices per user: evict the least recently refreshed — keeping
        // its full ts as the watermark. An incoming device not newer than the
        // one it would evict is refused instead (ordering is never lowered).
        const devices = this.db
          .prepare('SELECT token_hash, ts FROM registrations WHERE user = ? ORDER BY updated_at ASC')
          .all(req.user) as { token_hash: string; ts: number }[];
        const excess = devices.length - this.limits.maxDevicesPerUser + 1;
        const victims = excess > 0 ? devices.slice(0, excess) : [];
        if (victims.some((v) => v.ts >= req.ts)) {
          this.raiseWatermark(req.user, req.ts);
          return 'limit';
        }
        for (const v of victims) {
          this.raiseWatermark(req.user, v.ts);
          this.deleteRow(req.user, v.token_hash);
        }
      }

      const enc = this.crypto.encrypt(req.token, this.aad(req.user, tokenHash, req.app, req.platform));
      this.db
        .prepare(
          `INSERT INTO registrations (user, token_hash, app, platform, token_enc, categories, relays, nwc, ts, updated_at, apns_env)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(user, token_hash) DO UPDATE SET app = excluded.app, platform = excluded.platform,
             token_enc = excluded.token_enc, categories = excluded.categories, relays = excluded.relays,
             nwc = excluded.nwc, ts = excluded.ts, updated_at = excluded.updated_at, apns_env = excluded.apns_env`,
        )
        .run(
          req.user,
          tokenHash,
          req.app,
          req.platform,
          enc,
          catMask(req.categories),
          JSON.stringify(req.relays),
          JSON.stringify(req.nwc),
          req.ts,
          nowSec,
          req.apnsEnv ?? null,
        );
      if (!existing) this.ensureRow(req.user); // reserve this live user's replay state
      return existing ? 'updated' : 'registered';
    });
    try {
      return tx();
    } catch (e) {
      this.reconcileWatermarks(); // the transaction rolled back; resync the in-memory count
      throw e;
    }
  }

  /**
   * Invalid-token cleanup: remove exactly the registration version that was
   * sent (a newer one accepted meanwhile is left alone).
   */
  removeRegistration(user: string, tokenHash: string, ts: number): boolean {
    const tx = this.db.transaction((): boolean => {
      const live = this.db.prepare('SELECT 1 FROM registrations WHERE user = ? AND token_hash = ? AND ts = ?').get(user, tokenHash, ts);
      if (!live) return false;
      this.raiseWatermark(user, ts);
      this.deleteRow(user, tokenHash);
      this.afterRemoval(user);
      return true;
    });
    try {
      return tx();
    } catch (e) {
      this.reconcileWatermarks();
      throw e;
    }
  }

  /** Is this exact registration version still live with `category` on? (checked right before each send) */
  isCurrent(user: string, tokenHash: string, ts: number, category: Category): boolean {
    const row = this.db
      .prepare('SELECT categories FROM registrations WHERE user = ? AND token_hash = ? AND ts = ?')
      .get(user, tokenHash, ts) as { categories: number } | undefined;
    return !!row && maskCats(row.categories)[category];
  }

  /** Active registrations without tokens — for the subscription plan and event routing. */
  listActive(): RegistrationSummary[] {
    const rows = this.db
      .prepare('SELECT user, token_hash, app, platform, categories, relays, nwc FROM registrations WHERE token_enc IS NOT NULL')
      .all() as Row[];
    return rows.map((r) => ({
      user: r.user,
      tokenHash: r.token_hash,
      app: r.app,
      platform: r.platform,
      categories: maskCats(r.categories),
      relays: JSON.parse(r.relays) as string[],
      nwc: JSON.parse(r.nwc) as NwcConnection[],
    }));
  }

  /** Decrypted devices for a user (tokens only leave the DB here, for delivery). */
  devicesFor(user: string): Device[] {
    const rows = this.db
      .prepare(
        'SELECT user, token_hash, app, platform, token_enc, categories, ts, apns_env FROM registrations WHERE user = ? AND token_enc IS NOT NULL',
      )
      .all(user) as Row[];
    const out: Device[] = [];
    for (const r of rows) {
      try {
        out.push({
          user: r.user,
          apnsEnv: r.apns_env ?? (this.sandboxApps.includes(r.app) ? 'sandbox' : 'production'),
          tokenHash: r.token_hash,
          ts: r.ts,
          app: r.app,
          platform: r.platform,
          token: this.crypto.decrypt(r.token_enc!, this.aad(r.user, r.token_hash, r.app, r.platform)),
          categories: maskCats(r.categories),
        });
      } catch {
        // Wrong key or tampered row: unusable, drop it.
        this.removeRegistration(r.user, r.token_hash, r.ts);
      }
    }
    return out;
  }

  private notifiedRows = -1;
  private notifiedBudget = { minute: 0, used: 0 };

  /**
   * Restart-safe dedupe for events that triggered pushes. Returns false only if
   * the id was already recorded. Bounded: a hard row cap and a per-minute
   * insert budget; past either, the id simply isn't persisted (the in-memory
   * dedupe still applies), so spam can't grow the disk or stall the thread.
   */
  markNotified(id: string, nowSec: number): boolean {
    if (this.db.prepare('SELECT 1 FROM notified_events WHERE id = ?').get(id)) return false;
    const minute = Math.floor(nowSec / 60);
    if (this.notifiedBudget.minute !== minute) this.notifiedBudget = { minute, used: 0 };
    if (this.notifiedRows < 0) this.notifiedRows = (this.db.prepare('SELECT COUNT(*) AS n FROM notified_events').get() as { n: number }).n;
    if (this.notifiedBudget.used >= this.limits.notifiedInsertsPerMinute || this.notifiedRows >= this.limits.notifiedMaxRows) return true;
    this.notifiedBudget.used++;
    this.notifiedRows += this.db.prepare('INSERT OR IGNORE INTO notified_events (id, at) VALUES (?, ?)').run(id, nowSec).changes;
    return true;
  }

  /** Expire unrefreshed registrations, purge moot watermarks, prune notified ids. */
  sweep(nowSec: number): { expired: number; notifiedPruned: number } {
    const ttl = this.limits.registrationTtlDays * 86400;
    // (token_enc IS NULL only exists in pre-0.1 databases; they're unusable.)
    const expired = this.db
      .prepare('DELETE FROM registrations WHERE updated_at < ? OR token_enc IS NULL')
      .run(nowSec - ttl).changes;
    const replayHorizon = this.limits.registrationMaxAgeSec + this.limits.registrationMaxSkewSec + 3600;
    // Moot watermarks of users without a live registration are purged; live
    // users keep their reserved row.
    this.reconcileWatermarks(); // expiry may have made users inactive
    this.db.prepare('DELETE FROM user_watermarks WHERE active = 0 AND ts < ?').run(nowSec - replayHorizon);
    this.reconcileWatermarks();
    this.compactInactive();
    const notifiedPruned = this.db
      .prepare('DELETE FROM notified_events WHERE at < ?')
      .run(nowSec - this.limits.notifiedRetentionSec).changes;
    this.notifiedRows = -1; // recount lazily
    return { expired, notifiedPruned };
  }

  countActive(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM registrations WHERE token_enc IS NOT NULL').get() as { n: number }).n;
  }
}
