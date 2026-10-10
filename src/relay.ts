// One relay connection: reconnect with jittered exponential backoff, keep a
// desired subscription set and diff it on change, liveness pings, inbound
// size/rate bounds, and NIP-42 AUTH (signed by the watcher — only useful for
// its own inbox; it never authenticates as a user).

import { createHash } from 'node:crypto';
import WebSocket from 'ws';
import type { Filter } from 'nostr-tools/filter';
import type { EventTemplate, NostrEvent } from 'nostr-tools/pure';
import { errCode, log } from './log.js';
import type { SubMode, SubTemplate } from './plan.js';
import { safeLookup } from './relayUrl.js';

const MAX_MESSAGE_BYTES = 512 * 1024;
const PING_INTERVAL_MS = 30_000;
const CONNECT_TIMEOUT_MS = 15_000;
const BACKOFF_MIN_MS = 1_000;
const BACKOFF_MAX_MS = 5 * 60_000;
/** Inbound events per relay per minute before the excess is dropped. */
/** Inbound frames (any type) per relay per minute before the excess is dropped. */
const MAX_FRAMES_PER_MINUTE = 6_000;
const CLOSED_RETRY_MIN_MS = 60_000;
const CLOSED_RETRY_MAX_MS = 30 * 60_000;
const AUTH_MIN_INTERVAL_MS = 30_000;
const AUTH_MAX_PER_CONNECTION = 10;
const MAX_PENDING_OK = 100;

const publicRelays = new Set<string>();
/** Relays whose URLs may appear in logs (the watcher's own, configured relays). */
export function setPublicRelays(urls: readonly string[]): void {
  publicRelays.clear();
  for (const u of urls) publicRelays.add(u);
}

/**
 * Log-safe relay label. Configured relays log their host; user-supplied relays
 * (whose hostnames or paths could carry identifiers) get an opaque hash.
 */
export function relayLabel(url: string): string {
  if (publicRelays.has(url)) {
    try {
      return new URL(url).host;
    } catch {
      return 'invalid';
    }
  }
  return `user-relay:${createHash('sha256').update(url).digest('hex').slice(0, 10)}`;
}


/** Log-safe CLOSED/NOTICE reason: the machine-readable prefix only (NIP-01 `code:`). */
export function reasonCode(reason: unknown): string {
  const m = /^([a-z][a-z-]{0,31}):/.exec(String(reason ?? ''));
  return m ? m[1]! : 'other';
}

export interface RelayEventMeta {
  relay: string;
  subId: string;
  mode: SubMode;
  /** True when the event arrived before this subscription's EOSE. */
  preEose: boolean;
  /** Unix seconds when the REQ was sent (its `since`, if any, is relative to this). */
  subscribedAt: number;
}

export interface RelayOptions {
  onEvent: (ev: NostrEvent, meta: RelayEventMeta) => void;
  signAuth?: (t: EventTemplate) => NostrEvent;
  allowInsecure: boolean;
}

interface ActiveSub {
  tpl: SubTemplate;
  eose: boolean;
  sentAt: number;
}

export class RelayConn {
  private ws: WebSocket | null = null;
  private desired = new Map<string, SubTemplate>();
  private active = new Map<string, ActiveSub>();
  private attempts = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private pingTimer: NodeJS.Timeout | null = null;
  private alive = false;
  private closed = false;
  private rate = { windowStart: 0, count: 0, warned: false };
  private auth = { lastAt: 0, count: 0, challenge: '' };
  private closedRetries = new Map<string, number>();
  /** Pending re-REQ timers per subscription (a CLOSED backoff in progress). */
  private retryTimers = new Map<string, NodeJS.Timeout>();
  private pendingOk = new Map<string, (r: { ok: boolean; msg: string }) => void>();
  private oneShots = new Map<string, { events: NostrEvent[]; done: (evs: NostrEvent[]) => void }>();
  connected = false;
  authed = false;

  constructor(
    readonly url: string,
    private readonly opts: RelayOptions,
  ) {}

  setSubs(subs: readonly SubTemplate[]): void {
    this.desired = new Map(subs.map((s) => [s.id, s]));
    if (!this.connected) {
      if (!this.ws && !this.reconnectTimer && !this.closed) this.connect();
      return;
    }
    for (const id of [...this.active.keys()]) {
      if (!this.desired.has(id)) {
        this.send(['CLOSE', id]);
        this.active.delete(id);
      }
    }
    for (const id of [...this.closedRetries.keys()]) if (!this.desired.has(id)) this.closedRetries.delete(id);
    for (const [id, t] of [...this.retryTimers]) {
      if (!this.desired.has(id)) {
        clearTimeout(t);
        this.retryTimers.delete(id);
      }
    }
    // Subscriptions in a CLOSED backoff wait for their timer; rebuilds don't bypass it.
    for (const tpl of this.desired.values()) if (!this.active.has(tpl.id) && !this.retryTimers.has(tpl.id)) this.req(tpl);
  }

  private req(tpl: SubTemplate): void {
    const now = Math.floor(Date.now() / 1000);
    const filters: Filter[] = tpl.filters.map((f) =>
      tpl.sinceAgoSec !== undefined ? { ...f, since: now - tpl.sinceAgoSec } : { ...f },
    );
    this.active.set(tpl.id, { tpl, eose: false, sentAt: now });
    this.send(['REQ', tpl.id, ...filters]);
  }

  private scheduleReq(id: string, delayMs: number): void {
    const prev = this.retryTimers.get(id);
    if (prev) clearTimeout(prev);
    const t = setTimeout(() => {
      this.retryTimers.delete(id);
      const tpl = this.desired.get(id);
      if (this.connected && tpl && !this.active.has(id)) this.req(tpl);
    }, delayMs);
    t.unref();
    this.retryTimers.set(id, t);
  }

  private send(msg: unknown[]): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
  }

  private connect(): void {
    if (this.closed) return;
    const ws = new WebSocket(this.url, {
      maxPayload: MAX_MESSAGE_BYTES,
      handshakeTimeout: CONNECT_TIMEOUT_MS,
      perMessageDeflate: false,
      followRedirects: false,
      ...(this.opts.allowInsecure ? {} : { lookup: safeLookup as never }),
    });
    this.ws = ws;
    ws.on('open', () => {
      this.connected = true;
      this.alive = true;
      this.attempts = 0;
      this.auth = { lastAt: 0, count: 0, challenge: '' };
      log.info('relay connected', { relay: relayLabel(this.url) });
      for (const tpl of this.desired.values()) this.req(tpl);
      this.pingTimer = setInterval(() => {
        if (!this.alive) {
          ws.terminate();
          return;
        }
        this.alive = false;
        ws.ping();
      }, PING_INTERVAL_MS);
      this.pingTimer.unref();
    });
    ws.on('pong', () => (this.alive = true));
    ws.on('message', (data) => {
      this.alive = true;
      if (!this.rateOk()) return;
      try {
        this.onMessage(data.toString());
      } catch (e) {
        // Exception boundary: a malformed frame must never take the service down.
        log.warn('relay message handling failed', { relay: relayLabel(this.url), err: errCode(e) });
      }
    });
    ws.on('error', (e) => log.debug('relay socket error', { relay: relayLabel(this.url), err: errCode(e) }));
    ws.on('close', () => this.onClose());
  }

  private onClose(): void {
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = null;
    const wasConnected = this.connected;
    this.ws = null;
    this.connected = false;
    this.authed = false;
    this.active.clear();
    this.closedRetries.clear();
    for (const t of this.retryTimers.values()) clearTimeout(t);
    this.retryTimers.clear();
    for (const done of this.pendingOk.values()) done({ ok: false, msg: 'connection closed' });
    this.pendingOk.clear();
    for (const [id, q] of this.oneShots) {
      q.done(q.events);
      this.oneShots.delete(id);
    }
    if (this.closed) return;
    if (wasConnected) log.warn('relay disconnected', { relay: relayLabel(this.url) });
    const base = Math.min(BACKOFF_MAX_MS, BACKOFF_MIN_MS * 2 ** Math.min(this.attempts, 12));
    const delay = Math.round(base / 2 + Math.random() * (base / 2));
    this.attempts++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
    this.reconnectTimer.unref();
  }

  private rateOk(): boolean {
    const t = Date.now();
    if (t - this.rate.windowStart > 60_000) this.rate = { windowStart: t, count: 0, warned: false };
    if (++this.rate.count <= MAX_FRAMES_PER_MINUTE) return true;
    if (!this.rate.warned) {
      this.rate.warned = true;
      log.warn('relay frame rate exceeded; dropping', { relay: relayLabel(this.url) });
    }
    return false;
  }

  private onMessage(raw: string): void {
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (!Array.isArray(msg) || typeof msg[0] !== 'string') return;
    switch (msg[0]) {
      case 'EVENT': {
        const [, subId, ev] = msg as [string, string, NostrEvent];
        if (typeof subId !== 'string' || !ev || typeof ev !== 'object') return;
        const shot = this.oneShots.get(subId);
        if (shot) {
          if (shot.events.length < 50) shot.events.push(ev);
          return;
        }
        const sub = this.active.get(subId);
        if (!sub) return;
        this.opts.onEvent(ev, {
          relay: this.url,
          subId,
          mode: sub.tpl.mode,
          preEose: !sub.eose,
          subscribedAt: sub.sentAt,
        });
        return;
      }
      case 'EOSE': {
        const id = msg[1];
        if (typeof id !== 'string') return;
        const shot = this.oneShots.get(id);
        if (shot) {
          this.oneShots.delete(id);
          this.send(['CLOSE', id]);
          shot.done(shot.events);
          return;
        }
        const sub = this.active.get(id);
        if (sub) {
          sub.eose = true;
          this.closedRetries.delete(id);
        }
        return;
      }
      case 'CLOSED': {
        const [, id, reason] = msg as [string, string, string];
        const sub = this.active.get(id);
        if (!sub) return;
        this.active.delete(id);
        const code = reasonCode(reason);
        log.info('relay closed subscription', { relay: relayLabel(this.url), mode: sub.tpl.mode, reason: code });
        const n = (this.closedRetries.get(id) ?? 0) + 1;
        this.closedRetries.set(id, n);
        if (code === 'auth-required') {
          // If AUTH already succeeded (the OK can race ahead of this CLOSED),
          // retry shortly; otherwise the AUTH handler re-opens it.
          if (this.authed && n <= 3) this.scheduleReq(id, 2_000);
          return;
        }
        // Rate limits, restarts, "too many subscriptions"…: back off per subscription.
        this.scheduleReq(id, Math.min(CLOSED_RETRY_MAX_MS, CLOSED_RETRY_MIN_MS * 2 ** Math.min(n - 1, 5)));
        return;
      }
      case 'OK': {
        const [, id, ok, m] = msg as [string, string, boolean, string];
        const done = this.pendingOk.get(id);
        if (done) {
          this.pendingOk.delete(id);
          done({ ok: ok === true, msg: String(m ?? '').slice(0, 200) });
        }
        return;
      }
      case 'AUTH': {
        const challenge = msg[1];
        if (typeof challenge !== 'string' || challenge.length > 256 || !this.opts.signAuth) return;
        // Bound AUTH work: ignore repeats, rate-limit, cap per connection.
        const t = Date.now();
        if (challenge === this.auth.challenge && this.authed) return;
        if (t - this.auth.lastAt < AUTH_MIN_INTERVAL_MS || this.auth.count >= AUTH_MAX_PER_CONNECTION) return;
        this.auth = { lastAt: t, count: this.auth.count + 1, challenge };
        const ev = this.opts.signAuth({
          kind: 22242,
          created_at: Math.floor(t / 1000),
          tags: [
            ['relay', this.url],
            ['challenge', challenge],
          ],
          content: '',
        });
        void this.publish(ev, 'AUTH').then((r) => {
          if (!r.ok) return;
          this.authed = true;
          // Re-open anything the relay closed while unauthenticated (AUTH
          // recovery overrides a pending backoff for those subscriptions).
          for (const tpl of this.desired.values()) {
            if (this.active.has(tpl.id)) continue;
            const t = this.retryTimers.get(tpl.id);
            if (t) {
              clearTimeout(t);
              this.retryTimers.delete(tpl.id);
            }
            this.req(tpl);
          }
        });
        return;
      }
      default:
        return;
    }
  }

  publish(ev: NostrEvent, verb: 'EVENT' | 'AUTH' = 'EVENT', timeoutMs = 10_000): Promise<{ ok: boolean; msg: string }> {
    if (!this.connected) return Promise.resolve({ ok: false, msg: 'not connected' });
    if (this.pendingOk.size >= MAX_PENDING_OK) return Promise.resolve({ ok: false, msg: 'too many pending' });
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pendingOk.delete(ev.id);
        resolve({ ok: false, msg: 'timeout' });
      }, timeoutMs);
      timer.unref();
      this.pendingOk.set(ev.id, (r) => {
        clearTimeout(timer);
        resolve(r);
      });
      this.send([verb, ev]);
    });
  }

  /** One-shot query until EOSE (bounded to 50 events). */
  query(filter: Filter, timeoutMs = 8_000): Promise<NostrEvent[]> {
    if (!this.connected) return Promise.resolve([]);
    const id = `q${Math.random().toString(36).slice(2, 10)}`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const q = this.oneShots.get(id);
        this.oneShots.delete(id);
        this.send(['CLOSE', id]);
        resolve(q?.events ?? []);
      }, timeoutMs);
      timer.unref();
      this.oneShots.set(id, {
        events: [],
        done: (evs) => {
          clearTimeout(timer);
          resolve(evs);
        },
      });
      this.send(['REQ', id, filter]);
    });
  }

  /** Wait until connected (or timeout). */
  async waitConnected(timeoutMs: number): Promise<boolean> {
    const end = Date.now() + timeoutMs;
    while (!this.connected && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
    return this.connected;
  }

  close(): void {
    this.closed = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    for (const t of this.retryTimers.values()) clearTimeout(t);
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.ws?.close();
    this.ws?.terminate();
  }
}

/** The set of relay connections, driven by a Plan. */
export class RelayPool {
  readonly conns = new Map<string, RelayConn>();

  /** `authRelays`: the only relays we answer NIP-42 AUTH on (the watcher's own inbox relays). */
  constructor(
    private readonly opts: RelayOptions,
    private readonly authRelays: readonly string[] = [],
  ) {}

  apply(plan: Map<string, SubTemplate[]>): void {
    for (const [url, conn] of this.conns) {
      if (!plan.has(url)) {
        conn.close();
        this.conns.delete(url);
      }
    }
    for (const [url, subs] of plan) {
      let conn = this.conns.get(url);
      if (!conn) {
        const opts = this.authRelays.includes(url) ? this.opts : { ...this.opts, signAuth: undefined };
        conn = new RelayConn(url, opts);
        this.conns.set(url, conn);
      }
      conn.setSubs(subs);
    }
  }

  get(url: string): RelayConn | undefined {
    return this.conns.get(url);
  }

  connectedCount(urls?: readonly string[]): number {
    let n = 0;
    for (const [url, c] of this.conns) if (c.connected && (!urls || urls.includes(url))) n++;
    return n;
  }

  close(): void {
    for (const c of this.conns.values()) c.close();
    this.conns.clear();
  }
}
