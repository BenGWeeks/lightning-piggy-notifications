import { readFileSync } from 'node:fs';
import { decode as nip19Decode } from 'nostr-tools/nip19';
import { hexToBytes } from 'nostr-tools/utils';

export interface Limits {
  /** Max relays a registration may list (inbox + NWC relays combined). */
  maxRelaysPerRegistration: number;
  maxNwcPubkeysPerRegistration: number;
  maxDevicesPerUser: number;
  maxRegistrations: number;
  /** Users with a replay watermark (bounded; when full the watcher fails closed). */
  maxWatermarkUsers: number;
  /** Max users that may claim one NWC client pubkey (routing fan-out bound). */
  maxOwnersPerNwcClient: number;
  /** How long ids of events that triggered pushes are remembered (restart-safe dedupe). */
  notifiedRetentionSec: number;
  notifiedMaxRows: number;
  notifiedInsertsPerMinute: number;
  /** Max REQ subscriptions per relay connection (plans beyond this are truncated, loudly). */
  maxSubsPerRelay: number;
  /** Bytes of gift wraps queued for unwrapping. */
  inboxQueueMaxBytes: number;
  /** Concurrent push requests, and queued deliveries before new ones are dropped. */
  pushConcurrency: number;
  pushQueueMax: number;
  /** Max filters per REQ (several chunks are packed into one subscription). */
  filtersPerReq: number;
  /** Max serialized REQ size (relays commonly cap frames at 128 KiB). */
  reqMaxBytes: number;
  /** Max distinct user-supplied relays the pool connects to (defaults excluded). */
  maxUserRelays: number;
  /** Max #p values per REQ filter. */
  pTagChunk: number;
  /** Registration timestamp window. */
  registrationMaxAgeSec: number;
  registrationMaxSkewSec: number;
  /** Registrations not refreshed within this many days are deleted. */
  registrationTtlDays: number;
  /** Max registration events accepted per user per hour. */
  registrationsPerUserPerHour: number;
  /** Max gift wraps queued for unwrapping (excess dropped). */
  inboxQueueMax: number;
  /** One push per (user, category) per window; extra events are counted. */
  coalesceWindowSec: number;
  /** Per-device token bucket: pushes per hour. */
  devicePushesPerHour: number;
  /** Non-gift-wrap events older than this are never notified. */
  freshnessSec: number;
}

export interface Config {
  secretKey: Uint8Array;
  tokenKey: Buffer;
  dbPath: string;
  relays: string[];
  apps: string[];
  apnsSandboxApps: string[];
  apns?: { keyPem: string; keyId: string; teamId: string };
  fcm?: { clientEmail: string; privateKeyPem: string; projectId: string };
  healthHost: string;
  healthPort: number;
  logLevel: string;
  /** Tests only: allow ws:// and private/loopback relay hosts. */
  allowInsecureRelays: boolean;
  limits: Limits;
}

export const DEFAULT_LIMITS: Limits = {
  maxRelaysPerRegistration: 8,
  maxNwcPubkeysPerRegistration: 3,
  maxDevicesPerUser: 10,
  // Sized so the default relays can always carry every registration within
  // maxSubsPerRelay REQs of at most reqMaxBytes each (a test asserts the worst
  // case: every registration with all categories and 3 NWC connections).
  maxRegistrations: 1_000,
  maxWatermarkUsers: 100_000,
  maxOwnersPerNwcClient: 3,
  notifiedRetentionSec: 3 * 86400,
  notifiedMaxRows: 100_000,
  notifiedInsertsPerMinute: 600,
  maxSubsPerRelay: 15,
  inboxQueueMaxBytes: 16 * 1024 * 1024,
  pushConcurrency: 32,
  pushQueueMax: 10_000,
  filtersPerReq: 10,
  reqMaxBytes: 60_000,
  maxUserRelays: 40,
  pTagChunk: 400,
  registrationMaxAgeSec: 6 * 3600,
  registrationMaxSkewSec: 120,
  registrationTtlDays: 60,
  registrationsPerUserPerHour: 30,
  inboxQueueMax: 1000,
  coalesceWindowSec: 30,
  devicePushesPerHour: 60,
  freshnessSec: 600,
};

function readSecret(path: string, what: string): string {
  try {
    return readFileSync(path, 'utf8').trim();
  } catch (e) {
    throw new Error(`cannot read ${what} file (${path}): ${(e as NodeJS.ErrnoException).code ?? 'error'}`, { cause: e });
  }
}

/** Accepts a 64-char hex key or an nsec. */
export function parseSecretKey(raw: string): Uint8Array {
  const s = raw.trim();
  if (s.startsWith('nsec1')) {
    const d = nip19Decode(s);
    if (d.type !== 'nsec') throw new Error('invalid nsec');
    return d.data;
  }
  if (!/^[0-9a-fA-F]{64}$/.test(s)) throw new Error('private key must be 64 hex chars or nsec');
  return hexToBytes(s.toLowerCase());
}

/** 32 bytes as 64 hex chars or base64. */
export function parseTokenKey(raw: string): Buffer {
  const s = raw.trim();
  const buf = /^[0-9a-fA-F]{64}$/.test(s) ? Buffer.from(s, 'hex') : Buffer.from(s, 'base64');
  if (buf.length !== 32) throw new Error('token encryption key must be 32 bytes (64 hex chars or base64)');
  return buf;
}

const list = (v: string | undefined, dflt: string[]): string[] =>
  v === undefined || v.trim() === ''
    ? dflt
    : v
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

function intEnv(env: NodeJS.ProcessEnv, name: string, dflt: number): number {
  const v = env[name];
  if (v === undefined || v === '') return dflt;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${name} must be a non-negative integer`);
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const keyFile = env.WATCHER_PRIVATE_KEY_FILE;
  if (!keyFile) throw new Error('WATCHER_PRIVATE_KEY_FILE is required');
  const tokenKeyFile = env.WATCHER_TOKEN_KEY_FILE;
  if (!tokenKeyFile) throw new Error('WATCHER_TOKEN_KEY_FILE is required');

  let apns: Config['apns'];
  if (env.APNS_KEY_FILE) {
    const keyId = env.APNS_KEY_ID;
    const teamId = env.APNS_TEAM_ID;
    if (!keyId || !teamId) throw new Error('APNS_KEY_ID and APNS_TEAM_ID are required with APNS_KEY_FILE');
    apns = { keyPem: readSecret(env.APNS_KEY_FILE, 'APNs key'), keyId, teamId };
  }

  let fcm: Config['fcm'];
  if (env.FCM_SERVICE_ACCOUNT_FILE) {
    const sa = JSON.parse(readSecret(env.FCM_SERVICE_ACCOUNT_FILE, 'FCM service account')) as Record<string, unknown>;
    const clientEmail = sa.client_email;
    const privateKeyPem = sa.private_key;
    const projectId = env.FCM_PROJECT_ID || sa.project_id;
    if (typeof clientEmail !== 'string' || typeof privateKeyPem !== 'string' || typeof projectId !== 'string') {
      throw new Error('FCM service account JSON is missing client_email / private_key / project_id');
    }
    fcm = { clientEmail, privateKeyPem, projectId };
  }

  const [healthHost, healthPortStr] = (env.WATCHER_HEALTH_BIND || '127.0.0.1:8080').split(':');
  const limits: Limits = { ...DEFAULT_LIMITS };
  limits.registrationTtlDays = intEnv(env, 'WATCHER_REGISTRATION_TTL_DAYS', limits.registrationTtlDays);
  limits.coalesceWindowSec = intEnv(env, 'WATCHER_COALESCE_SECONDS', limits.coalesceWindowSec);
  limits.devicePushesPerHour = intEnv(env, 'WATCHER_DEVICE_PUSHES_PER_HOUR', limits.devicePushesPerHour);
  limits.maxRegistrations = intEnv(env, 'WATCHER_MAX_REGISTRATIONS', limits.maxRegistrations);
  limits.maxUserRelays = intEnv(env, 'WATCHER_MAX_USER_RELAYS', limits.maxUserRelays);

  return {
    secretKey: parseSecretKey(readSecret(keyFile, 'watcher private key')),
    tokenKey: parseTokenKey(readSecret(tokenKeyFile, 'token encryption key')),
    dbPath: env.WATCHER_DB_PATH || '/data/watcher.db',
    relays: list(env.WATCHER_RELAYS, ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']),
    apps: list(env.WATCHER_APPS, [
      'com.lightningpiggy.app',
      'com.lightningpiggy.app.preview',
      'com.lightningpiggy.app.dev',
    ]),
    // Fallback only, for registrations without `apns_env`.
    apnsSandboxApps: list(env.WATCHER_APNS_SANDBOX_APPS, []),
    apns,
    fcm,
    healthHost: healthHost || '127.0.0.1',
    healthPort: Number(healthPortStr || 8080),
    logLevel: env.LOG_LEVEL || 'info',
    allowInsecureRelays: env.WATCHER_ALLOW_INSECURE_RELAYS === '1',
    limits,
  };
}
