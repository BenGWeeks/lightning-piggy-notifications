// Wiring: relay pool -> dedupe/verify -> route -> coalesce -> push, plus the
// registration inbox and the watcher's kind-10050 inbox relay list.

import type http from 'node:http';
import { npubEncode } from 'nostr-tools/nip19';
import { finalizeEvent, getPublicKey, verifyEvent, type EventTemplate, type NostrEvent } from 'nostr-tools/pure';
import { Activity } from './activity.js';
import type { Config } from './config.js';
import { startHealthServer } from './health.js';
import { errCode, log, logs, pseudonym, warnThrottled } from './log.js';
import { Notifier } from './notifier.js';
import { buildPlan, LIVE_SINCE_SLACK_SEC, planOverflow } from './plan.js';
import { ApnsSender } from './push/apns.js';
import { FcmSender } from './push/fcm.js';
import type { PushSender } from './push/types.js';
import {
  MAX_WRAP_CONTENT,
  parseRegistration,
  RegistrationError,
  unwrapRegistration,
  type RegistrationRequest,
} from './registration.js';
import { reasonCode, RelayPool, relayLabel, setPublicRelays, type RelayEventMeta } from './relay.js';
import { RouteIndex, SeenCache } from './router.js';
import { Store, type Validation } from './store.js';

const HEX64 = /^[0-9a-f]{64}$/;
const WATCHED_KINDS = new Set([1, 4, 1059, 9735, 23196, 23197]);
const REBUILD_DEBOUNCE_MS = 2_000;
/** A historical (pre-EOSE) sighting older than this suppresses a later live copy. */
const HISTORICAL_SUPPRESS_MS = 120_000;
const MAX_TAGS = 2_000;
/** A registration wrap carries just ["p", watcher] (NIP-59 allows a few more, e.g. expiration). */
const INBOX_MAX_TAGS = 4;
const MAX_TAG_ITEMS = 16;
const MAX_TAG_ITEM_LEN = 1_024;

/** Structural check of an untrusted relay event, before anything reads it. */
export function isWellFormedEvent(ev: unknown): ev is NostrEvent {
  if (!ev || typeof ev !== 'object') return false;
  const e = ev as Record<string, unknown>;
  if (
    typeof e.id !== 'string' ||
    !HEX64.test(e.id) ||
    typeof e.pubkey !== 'string' ||
    !HEX64.test(e.pubkey) ||
    typeof e.sig !== 'string' ||
    typeof e.kind !== 'number' ||
    !Number.isInteger(e.kind) ||
    typeof e.created_at !== 'number' ||
    !Number.isInteger(e.created_at) ||
    typeof e.content !== 'string' ||
    !Array.isArray(e.tags) ||
    e.tags.length > MAX_TAGS
  ) {
    return false;
  }
  for (const t of e.tags as unknown[]) {
    if (!Array.isArray(t) || t.length > MAX_TAG_ITEMS) return false;
    for (const x of t) if (typeof x !== 'string' || x.length > MAX_TAG_ITEM_LEN) return false;
  }
  return true;
}
const SWEEP_INTERVAL_MS = 60 * 60_000;
/** Concurrent provider token checks, and new devices allowed to wait for one. */
const CHECK_CONCURRENCY = 4;
const CHECK_QUEUE_MAX = 64;

export interface WatcherDeps {
  senders?: { apns?: PushSender; fcm?: PushSender };
}

export class Watcher {
  readonly pubkey: string;
  private readonly store: Store;
  private readonly pool: RelayPool;
  readonly notifier: Notifier;
  readonly activity = new Activity();
  private readonly senders: { apns?: PushSender; fcm?: PushSender };
  private index = new RouteIndex([]);
  /** Ids processed live (or as registrations). */
  private readonly processed = new SeenCache();
  /** Ids seen only as stored history (pre-EOSE wraps) — never notified. */
  private readonly historical = new SeenCache();
  private readonly inbox: { ev: NostrEvent; bytes: number }[] = [];
  private inboxBytes = 0;
  private planOverflow = 0;
  private inboxDraining = false;
  /** New devices waiting for a provider token check (bounded), and checks in flight. */
  private readonly checkQueue: RegistrationRequest[] = [];
  private checksRunning = 0;
  private checkIdleWaiters: (() => void)[] = [];
  private stopping = false;
  private regRate = new Map<string, { start: number; count: number }>();
  private rebuildTimer: NodeJS.Timeout | null = null;
  private sweepTimer: NodeJS.Timeout | null = null;
  private activityTimer: NodeJS.Timeout | null = null;
  private health: http.Server | null = null;
  readonly stats = { events: 0, matched: 0, registrations: 0, registrationRejects: 0, inboxDropped: 0, rebuilds: 0 };

  constructor(
    private readonly cfg: Config,
    deps: WatcherDeps = {},
  ) {
    this.pubkey = getPublicKey(cfg.secretKey);
    setPublicRelays(cfg.relays);
    this.store = new Store(cfg.dbPath, cfg.tokenKey, cfg.limits, cfg.apnsSandboxApps);
    const senders = deps.senders ?? {
      apns: cfg.apns ? new ApnsSender(cfg.apns) : undefined,
      fcm: cfg.fcm ? new FcmSender(cfg.fcm) : undefined,
    };
    this.senders = senders;
    this.notifier = new Notifier({
      store: this.store,
      senders,
      activity: this.activity,
      coalesceWindowSec: cfg.limits.coalesceWindowSec,
      devicePushesPerHour: cfg.limits.devicePushesPerHour,
      concurrency: cfg.limits.pushConcurrency,
      queueMax: cfg.limits.pushQueueMax,
      onRegistrationsChanged: () => this.scheduleRebuild(),
    });
    this.pool = new RelayPool(
      {
        onEvent: (ev, meta) => this.onEvent(ev, meta),
        signAuth: (t: EventTemplate) => finalizeEvent(t, cfg.secretKey),
        allowInsecure: cfg.allowInsecureRelays,
      },
      cfg.relays,
    );
  }

  async start(): Promise<void> {
    this.store.sweep(now());
    this.rebuild();
    this.health = await startHealthServer(this.cfg.healthHost, this.cfg.healthPort, () => this.readyStatus());
    this.sweepTimer = setInterval(() => this.sweep(), SWEEP_INTERVAL_MS);
    this.sweepTimer.unref();
    if (this.cfg.activityLogSec > 0) {
      this.activityTimer = setInterval(() => this.activity.flush(), this.cfg.activityLogSec * 1000);
      this.activityTimer.unref();
    }
    log.info('watcher started', {
      npub: npubEncode(this.pubkey), // the watcher's own public identity
      relays: this.cfg.relays,
      apns: !!this.cfg.apns,
      fcm: !!this.cfg.fcm,
      registrations: this.store.countActive(),
    });
    void this.publishInboxRelays();
  }

  async stop(): Promise<void> {
    // Stop taking registrations, and let token checks in flight finish (their
    // results are discarded; unprocessed wraps are re-read from the relays'
    // inbox history at the next start) before the store closes.
    this.stopping = true;
    this.checkQueue.length = 0;
    if (this.checksRunning > 0) {
      await Promise.race([
        new Promise<void>((r) => this.checkIdleWaiters.push(r)),
        new Promise<void>((r) => setTimeout(r, 5_000).unref()),
      ]);
    }
    if (this.rebuildTimer) clearTimeout(this.rebuildTimer);
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    if (this.activityTimer) clearInterval(this.activityTimer);
    this.pool.close();
    await this.notifier.drain();
    this.activity.flush();
    await new Promise<void>((r) => (this.health ? this.health.close(() => r()) : r()));
    this.store.close();
  }

  readyStatus(): { ready: boolean; [k: string]: unknown } {
    let db: boolean;
    let registrations = -1;
    let provisional = -1;
    try {
      db = this.store.ping();
      registrations = this.store.countActive();
      provisional = this.store.countProvisional();
    } catch {
      db = false;
    }
    const defaultsConnected = this.pool.connectedCount(this.cfg.relays);
    return {
      // Not ready if any registered user can't be watched (plan truncated).
      ready: db && defaultsConnected > 0 && this.planOverflow === 0,
      plan_overflow: this.planOverflow,
      db,
      default_relays_connected: defaultsConnected,
      relays_connected: this.pool.connectedCount(),
      relays_total: this.pool.conns.size,
      registrations,
      registrations_provisional: provisional,
      apns_configured: !!this.cfg.apns,
      fcm_configured: !!this.cfg.fcm,
      stats: { ...this.stats, push: this.notifier.stats },
    };
  }

  /** Publish the watcher's kind-10050 inbox relay list, unless already current. */
  async publishInboxRelays(): Promise<void> {
    const relays = [...this.cfg.relays].sort();
    const tpl: EventTemplate = {
      kind: 10050,
      created_at: now(),
      tags: relays.map((r) => ['relay', r]),
      content: '',
    };
    let ev: NostrEvent | null = null;
    for (const url of this.cfg.relays) {
      const conn = this.pool.get(url);
      if (!conn || !(await conn.waitConnected(15_000))) {
        log.warn('kind 10050: relay not connected', { relay: relayLabel(url) });
        continue;
      }
      const existing = (await conn.query({ kinds: [10050], authors: [this.pubkey], limit: 1 }))
        .filter((e) => e.pubkey === this.pubkey && verifyEvent(e))
        .sort((a, b) => b.created_at - a.created_at)[0];
      const current = existing?.tags
        .filter((t) => t[0] === 'relay')
        .map((t) => t[1])
        .sort();
      if (current && JSON.stringify(current) === JSON.stringify(relays)) {
        log.info('kind 10050 unchanged; skipping publish', { relay: relayLabel(url) });
        continue;
      }
      ev ??= finalizeEvent(tpl, this.cfg.secretKey);
      const r = await conn.publish(ev);
      log.info('kind 10050 published', { relay: relayLabel(url), ok: r.ok, reason: r.ok ? undefined : reasonCode(r.msg) });
    }
  }

  scheduleRebuild(): void {
    if (this.rebuildTimer) return;
    this.rebuildTimer = setTimeout(() => {
      this.rebuildTimer = null;
      try {
        this.rebuild();
      } catch (e) {
        log.error('rebuild failed; will retry', { err: e as Error });
        this.scheduleRebuild();
      }
    }, REBUILD_DEBOUNCE_MS);
    this.rebuildTimer.unref();
  }

  rebuild(): void {
    const regs = this.store.listActive();
    this.stats.rebuilds++;
    this.index = new RouteIndex(regs, this.cfg.limits.maxOwnersPerNwcClient);
    const plan = buildPlan(regs, { watcherPubkey: this.pubkey, defaultRelays: this.cfg.relays, limits: this.cfg.limits });
    this.pool.apply(plan);
    let subs = 0;
    let maxPerRelay = 0;
    for (const s of plan.values()) {
      subs += s.length;
      maxPerRelay = Math.max(maxPerRelay, s.length);
    }
    log.info('subscriptions planned', { registrations: regs.length, users: this.index.size, relays: plan.size, subs, maxPerRelay });
    const overflow = [...planOverflow().values()].reduce((a, b) => a + b, 0);
    this.planOverflow = overflow;
    if (overflow) log.error('subscription plan exceeds maxSubsPerRelay; some users are not watched', { dropped: overflow });
  }

  private sweep(): void {
    try {
      const r = this.store.sweep(now());
      // Always re-plan: the admin CLI may have purged registrations meanwhile.
      this.scheduleRebuild();
      log.info('sweep', r);
    } catch (e) {
      log.error('sweep failed', { err: e as Error });
    }
    this.notifier.pruneBuckets();
    const t = Date.now();
    for (const [k, v] of this.regRate) if (t - v.start > 3_600_000) this.regRate.delete(k);
  }

  onEvent(raw: unknown, meta: RelayEventMeta): void {
    if (!isWellFormedEvent(raw)) return;
    // Keep only the NIP-01 fields: extra (unsigned) properties never survive.
    const ev: NostrEvent = {
      id: raw.id,
      pubkey: raw.pubkey,
      created_at: raw.created_at,
      kind: raw.kind,
      tags: raw.tags,
      content: raw.content,
      sig: raw.sig,
    };
    if (this.processed.has(ev.id) || !WATCHED_KINDS.has(ev.kind)) return;

    if (meta.mode === 'inbox') {
      if (ev.kind !== 1059 || ev.tags.length > INBOX_MAX_TAGS || !ev.tags.some((t) => t[0] === 'p' && t[1] === this.pubkey)) return;
      if (ev.content.length > MAX_WRAP_CONTENT) return; // before any crypto
      // Account the whole retained (canonical) event, in UTF-8 bytes.
      const size = Buffer.byteLength(JSON.stringify(ev), 'utf8');
      if (this.inbox.length >= this.cfg.limits.inboxQueueMax || this.inboxBytes + size > this.cfg.limits.inboxQueueMaxBytes) {
        this.stats.inboxDropped++;
        return;
      }
      if (!verifyEvent(ev)) return;
      this.processed.add(ev.id);
      this.inbox.push({ ev, bytes: size });
      this.inboxBytes += size;
      this.drainInbox();
      return;
    }

    const t = now();
    if (meta.mode === 'wrap') {
      if (ev.kind !== 1059) return;
      // NIP-59 randomises created_at, so stored wraps can't be told from new
      // ones: only events streamed after EOSE count as new. Historical copies
      // are remembered separately (after verification, so a forged copy can't
      // poison dedupe) and only suppress a live copy if seen well before it.
      if (meta.preEose) {
        if (!this.historical.has(ev.id) && verifyEvent(ev)) this.historical.add(ev.id);
        return;
      }
      const firstHistorical = this.historical.firstSeen(ev.id);
      if (firstHistorical !== undefined && Date.now() - firstHistorical > HISTORICAL_SUPPRESS_MS) return;
    } else {
      if (t - ev.created_at > this.cfg.limits.freshnessSec || ev.created_at - t > 300) return;
      if (meta.preEose && ev.created_at < meta.subscribedAt - LIVE_SINCE_SLACK_SEC - 5) return;
    }

    if (!verifyEvent(ev)) return;
    this.processed.add(ev.id);
    this.stats.events++;
    const matches = this.index.route(ev);
    if (matches.length === 0) return;
    // Restart-safe dedupe for events that actually notify.
    try {
      if (!this.store.markNotified(ev.id, t)) return;
    } catch (e) {
      log.error('notified-event bookkeeping failed', { err: e as Error });
    }
    for (const m of matches) {
      this.stats.matched++;
      this.activity.count('matched', m.category);
      if (logs('debug')) log.debug('event matched', { kind: ev.kind, category: m.category, user: pseudonym(m.user), relay: relayLabel(meta.relay) });
      this.notifier.notify(m.user, m.category);
    }
  }

  /** One registration per tick. Token checks run on their own bounded workers, so they never block this. */
  private drainInbox(): void {
    if (this.inboxDraining) return;
    this.inboxDraining = true;
    const step = () => {
      const item = this.stopping ? undefined : this.inbox.shift();
      if (!item) {
        this.inboxDraining = false;
        return;
      }
      this.inboxBytes -= item.bytes;
      this.handleRegistration(item.ev);
      setImmediate(step);
    };
    setImmediate(step);
  }

  /**
   * Token-check workers. Requests may be applied out of arrival order (a
   * refresh or unregister doesn't wait for another device's check); that is
   * safe because every apply re-checks newest-wins ordering itself.
   */
  private pumpChecks(): void {
    while (!this.stopping && this.checksRunning < CHECK_CONCURRENCY && this.checkQueue.length > 0) {
      const req = this.checkQueue.shift()!;
      this.checksRunning++;
      this.runCheck(req)
        .catch((e: unknown) => log.error('registration error', { err: errCode(e) }))
        .finally(() => {
          this.checksRunning--;
          if (this.checksRunning === 0) for (const w of this.checkIdleWaiters.splice(0)) w();
          this.pumpChecks();
        });
    }
  }

  private async runCheck(req: RegistrationRequest): Promise<void> {
    // The state may have changed while queued: re-decide before spending a request.
    let validation: Validation | undefined;
    if (this.store.isNewDevice(req) && this.store.wouldAdmit(req, now())) {
      validation = this.store.takeTokenCheck(now(), req.user) ? await this.checkToken(req) : 'unchecked';
    }
    if (this.stopping) return;
    this.finishRegistration(req, validation);
  }

  /**
   * Admission check of a new device's token with its push provider (nothing is
   * shown to the user). Without a sender for the platform, or if the provider
   * can't answer, the device is admitted provisionally.
   */
  private async checkToken(req: RegistrationRequest): Promise<Validation> {
    const sender = req.platform === 'apns' ? this.senders.apns : this.senders.fcm;
    if (!sender?.validate) return 'unavailable';
    try {
      return await sender.validate({
        token: req.token,
        app: req.app,
        platform: req.platform,
        apnsEnv: req.apnsEnv ?? (this.cfg.apnsSandboxApps.includes(req.app) ? 'sandbox' : 'production'),
      });
    } catch (e) {
      warnThrottled(`token check ${errCode(e)}`, 'token check failed', { err: errCode(e) });
      return 'unavailable';
    }
  }

  handleRegistration(wrap: NostrEvent): void {
    let user = '';
    try {
      const { rumor, sealPubkey } = unwrapRegistration(wrap, this.cfg.secretKey);
      user = sealPubkey;
      const req = parseRegistration(rumor, {
        apps: this.cfg.apps,
        limits: this.cfg.limits,
        allowInsecureRelays: this.cfg.allowInsecureRelays,
        nowSec: now(),
      });
      // Replays/stale requests are rejected before they can use up the user's
      // allowance (so re-broadcast old wraps can't block a fresh unregister).
      if (this.store.isStale(req)) throw new RegistrationError('stale');
      if (!this.regRateOk(user)) throw new RegistrationError('rate limited');
      // A new device's token is checked with its provider before it can take
      // a slot — unless it would be refused anyway (then no request is made).
      if (this.store.isNewDevice(req) && this.store.wouldAdmit(req, now())) {
        if (this.checkQueue.length >= CHECK_QUEUE_MAX) {
          this.finishRegistration(req, 'unchecked'); // refused (settled); the app retries on its next refresh
        } else {
          this.checkQueue.push(req);
          this.pumpChecks();
        }
        return;
      }
      this.finishRegistration(req, undefined);
    } catch (e) {
      this.registrationRejected(e, user, wrap);
    }
  }

  private finishRegistration(req: RegistrationRequest, validation: Validation | undefined): void {
    try {
      const result = this.store.apply(req, now(), validation);
      this.stats.registrations++;
      this.activity.registration(result === 'invalid-token' ? 'invalid_token' : result);
      // Per-user detail is debug-only (an info line per registration would be
      // a per-user timeline, linkable to the stored timestamps).
      if (logs('debug')) {
        log.debug('registration', {
          action: req.action,
          result,
          validation,
          user: pseudonym(req.user),
          app: req.app,
          platform: req.platform,
          categories: Object.entries(req.categories)
            .filter(([, v]) => v)
            .map(([k]) => k),
          relays: req.relays.length,
          nwc: req.nwc.length,
        });
      }
      if (result === 'registered' || result === 'updated' || result === 'unregistered') this.scheduleRebuild();
    } catch (e) {
      this.registrationRejected(e, req.user);
    }
  }

  private registrationRejected(e: unknown, user: string, wrap?: NostrEvent): void {
    this.stats.registrationRejects++;
    this.activity.registration('rejected');
    const reason = e instanceof RegistrationError ? e.reason : 'internal error';
    log.debug('registration rejected', { reason, user: pseudonym(user), wrap: pseudonym(wrap?.id) });
    if (!(e instanceof RegistrationError)) log.error('registration error', { err: errCode(e) });
  }

  private regRateOk(user: string): boolean {
    const t = Date.now();
    const r = this.regRate.get(user);
    if (!r || t - r.start > 3_600_000) {
      if (this.regRate.size > 100_000) this.regRate.clear();
      this.regRate.set(user, { start: t, count: 1 });
      return true;
    }
    return ++r.count <= this.cfg.limits.registrationsPerUserPerHour;
  }
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}
