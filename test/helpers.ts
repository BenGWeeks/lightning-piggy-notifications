import { WebSocketServer, type WebSocket } from 'ws';
import { matchFilters, type Filter } from 'nostr-tools/filter';
import { createRumor, createSeal, createWrap } from 'nostr-tools/nip59';
import type { NostrEvent } from 'nostr-tools/pure';
import { DEFAULT_LIMITS, type Config } from '../src/config.js';
import { REGISTRATION_KIND } from '../src/registration.js';

export const FCM_TOKEN = 'fKq1:APA91bHPRgkF' + 'x'.repeat(120);
export const APNS_TOKEN = 'a'.repeat(64);

export function regContent(over: Record<string, unknown> = {}, ts = Math.floor(Date.now() / 1000)) {
  return {
    v: 1,
    action: 'register',
    app: 'com.lightningpiggy.app',
    platform: 'fcm',
    token: FCM_TOKEN,
    categories: { dm: true, zap: true, mention: true, payment: true },
    relays: ['wss://relay.example.com'],
    nwc: [],
    ts,
    ...over,
  };
}

export function makeRegistrationWrap(
  userSk: Uint8Array,
  watcherPk: string,
  content: Record<string, unknown>,
  opts: { kind?: number; tamperSeal?: (s: NostrEvent) => NostrEvent } = {},
): NostrEvent {
  const rumor = createRumor(
    { kind: opts.kind ?? REGISTRATION_KIND, content: JSON.stringify(content), created_at: content.ts as number, tags: [] },
    userSk,
  );
  let seal = createSeal(rumor, userSk, watcherPk);
  if (opts.tamperSeal) seal = opts.tamperSeal(seal);
  return createWrap(seal, watcherPk);
}

export function testConfig(over: Partial<Config> = {}): Config {
  return {
    secretKey: new Uint8Array(32).fill(7),
    tokenKey: Buffer.alloc(32, 9),
    dbPath: ':memory:',
    relays: [],
    apps: ['com.lightningpiggy.app', 'com.lightningpiggy.app.preview', 'com.lightningpiggy.app.dev'],
    apnsSandboxApps: ['com.lightningpiggy.app.dev'],
    healthHost: '127.0.0.1',
    healthPort: 0,
    logLevel: 'error',
    activityLogSec: 0,
    allowInsecureRelays: true,
    limits: { ...DEFAULT_LIMITS },
    ...over,
  };
}

/** Minimal NIP-01 relay for end-to-end tests. */
export class MiniRelay {
  readonly events: NostrEvent[] = [];
  private readonly subs = new Map<WebSocket, Map<string, Filter[]>>();
  private wss!: WebSocketServer;
  url = '';

  async start(): Promise<void> {
    this.wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await new Promise<void>((r) => this.wss.once('listening', () => r()));
    const addr = this.wss.address();
    if (!addr || typeof addr === 'string') throw new Error('unexpected address');
    this.url = `ws://127.0.0.1:${addr.port}`;
    this.wss.on('connection', (ws) => {
      this.subs.set(ws, new Map());
      ws.on('close', () => this.subs.delete(ws));
      ws.on('message', (raw) => this.onMessage(ws, raw.toString()));
    });
  }

  private onMessage(ws: WebSocket, raw: string): void {
    const msg = JSON.parse(raw) as unknown[];
    if (msg[0] === 'EVENT') {
      const ev = msg[1] as NostrEvent;
      this.publish(ev);
      ws.send(JSON.stringify(['OK', ev.id, true, '']));
    } else if (msg[0] === 'REQ') {
      const id = msg[1] as string;
      const filters = msg.slice(2) as Filter[];
      this.subs.get(ws)?.set(id, filters);
      const limit = Math.min(...filters.map((f) => f.limit ?? 500));
      const stored = this.events
        .filter((e) => matchFilters(filters, e))
        .sort((a, b) => b.created_at - a.created_at)
        .slice(0, limit);
      for (const e of stored) ws.send(JSON.stringify(['EVENT', id, e]));
      ws.send(JSON.stringify(['EOSE', id]));
    } else if (msg[0] === 'CLOSE') {
      this.subs.get(ws)?.delete(msg[1] as string);
    }
  }

  publish(ev: NostrEvent): void {
    this.events.push(ev);
    for (const [ws, subs] of this.subs) {
      for (const [id, filters] of subs) if (matchFilters(filters, ev)) ws.send(JSON.stringify(['EVENT', id, ev]));
    }
  }

  subscriptionCount(): number {
    let n = 0;
    for (const s of this.subs.values()) n += s.size;
    return n;
  }

  async stop(): Promise<void> {
    for (const ws of this.subs.keys()) ws.terminate();
    await new Promise<void>((r) => this.wss.close(() => r()));
  }
}

export async function waitFor(cond: () => boolean, timeoutMs = 10_000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > end) throw new Error('waitFor timed out');
    await new Promise((r) => setTimeout(r, 25));
  }
}
