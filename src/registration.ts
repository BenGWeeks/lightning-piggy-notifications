// Registration protocol: the app gift-wraps (NIP-59) a kind-8480 rumor to the
// watcher's pubkey. The seal (kind 13) is signed by the user, so a valid seal
// signature + rumor.pubkey === seal.pubkey authenticates the request without
// any HTTP endpoint. See PROTOCOL.md.

import { createHash } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import { getEventHash, verifyEvent, type NostrEvent } from 'nostr-tools/pure';
import { decrypt as nip44Decrypt, getConversationKey } from 'nostr-tools/nip44';
import type { Limits } from './config.js';
import { normalizeRelayUrl } from './relayUrl.js';

export const REGISTRATION_KIND = 8480;
export const GIFT_WRAP_KIND = 1059;
export const SEAL_KIND = 13;

/** A maximal registration (8 KiB content) wraps to well under this; checked before any crypto. */
export const MAX_WRAP_CONTENT = 32_000;
const MAX_CONTENT_JSON = 8_192;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const APNS_TOKEN = /^[0-9a-fA-F]{64,200}$/;
const FCM_TOKEN = /^[A-Za-z0-9_:\-.]{32,512}$/;

export type Platform = 'apns' | 'fcm';
export type Category = 'dm' | 'zap' | 'mention' | 'payment';
export const CATEGORIES: readonly Category[] = ['dm', 'zap', 'mention', 'payment'];

export interface NwcConnection {
  /** The app's NWC client pubkey (the `p` tag on the wallet's notifications). */
  client: string;
  /** The wallet service pubkey (the author of the notifications). */
  wallet: string;
}

/** Domain-separated message the NWC client key signs to prove the user controls it. */
export function nwcProofMessage(user: string, wallet: string): Uint8Array {
  return createHash('sha256').update(`lightning-piggy-watcher/nwc/v1:${user}:${wallet}`).digest();
}

export interface RegistrationRequest {
  user: string;
  action: 'register' | 'unregister';
  app: string;
  platform: Platform;
  token: string;
  categories: Record<Category, boolean>;
  relays: string[];
  nwc: NwcConnection[];
  /** APNs environment of the token (from the app's aps-environment entitlement); undefined = not stated. */
  apnsEnv?: 'production' | 'sandbox';
  ts: number;
  /** Rumor id — used as the replay key. */
  rumorId: string;
}

export class RegistrationError extends Error {
  constructor(public readonly reason: string) {
    super(reason);
  }
}

function fail(reason: string): never {
  throw new RegistrationError(reason);
}

function isEventShape(x: unknown): x is NostrEvent {
  if (!x || typeof x !== 'object') return false;
  const e = x as Record<string, unknown>;
  return (
    typeof e.id === 'string' &&
    typeof e.pubkey === 'string' &&
    typeof e.created_at === 'number' &&
    typeof e.kind === 'number' &&
    Array.isArray(e.tags) &&
    typeof e.content === 'string' &&
    typeof e.sig === 'string'
  );
}

/** Unwrap a gift wrap addressed to the watcher and return the authenticated rumor. */
export function unwrapRegistration(
  wrap: NostrEvent,
  watcherSecretKey: Uint8Array,
): { rumor: NostrEvent & { sig?: string }; sealPubkey: string } {
  if (wrap.kind !== GIFT_WRAP_KIND) fail('not a gift wrap');
  if (wrap.content.length > MAX_WRAP_CONTENT) fail('wrap too large');
  if (!HEX64.test(wrap.pubkey)) fail('bad wrap pubkey');

  let seal: unknown;
  try {
    seal = JSON.parse(nip44Decrypt(wrap.content, getConversationKey(watcherSecretKey, wrap.pubkey)));
  } catch {
    fail('wrap decrypt failed');
  }
  if (!isEventShape(seal) || seal.kind !== SEAL_KIND) fail('bad seal');
  if (!HEX64.test(seal.pubkey) || !HEX128.test(seal.sig)) fail('bad seal fields');
  if (seal.tags.length !== 0) fail('seal must have no tags');
  if (seal.content.length > MAX_WRAP_CONTENT) fail('seal too large');
  if (!verifyEvent(seal)) fail('seal signature invalid');

  let rumor: unknown;
  try {
    rumor = JSON.parse(nip44Decrypt(seal.content, getConversationKey(watcherSecretKey, seal.pubkey)));
  } catch {
    fail('seal decrypt failed');
  }
  const r = rumor as Record<string, unknown> | null;
  if (
    !r ||
    typeof r !== 'object' ||
    typeof r.id !== 'string' ||
    typeof r.pubkey !== 'string' ||
    typeof r.created_at !== 'number' ||
    typeof r.kind !== 'number' ||
    !Array.isArray(r.tags) ||
    typeof r.content !== 'string'
  ) {
    fail('bad rumor');
  }
  const rumorEv = r as unknown as NostrEvent;
  // NIP-17/59: the rumor's author must be the seal's signer, or anyone could
  // seal someone else's rumor.
  if (rumorEv.pubkey !== seal.pubkey) fail('rumor pubkey does not match seal signer');
  if (getEventHash(rumorEv) !== rumorEv.id) fail('rumor id mismatch');
  return { rumor: rumorEv, sealPubkey: seal.pubkey };
}

/** Validate the rumor content. `nowSec` is injected for tests. */
export function parseRegistration(
  rumor: NostrEvent,
  opts: { apps: readonly string[]; limits: Limits; allowInsecureRelays: boolean; nowSec: number },
): RegistrationRequest {
  if (rumor.kind !== REGISTRATION_KIND) fail(`unexpected rumor kind ${rumor.kind}`);
  if (rumor.content.length > MAX_CONTENT_JSON) fail('content too large');
  let c: Record<string, unknown>;
  try {
    c = JSON.parse(rumor.content) as Record<string, unknown>;
  } catch {
    fail('content is not JSON');
  }
  if (!c || typeof c !== 'object' || Array.isArray(c)) fail('content is not an object');
  if (c.v !== 1) fail('unsupported version');
  const action = c.action;
  if (action !== 'register' && action !== 'unregister') fail('bad action');
  if (typeof c.app !== 'string' || !opts.apps.includes(c.app)) fail('unknown app');
  const platform = c.platform;
  if (platform !== 'apns' && platform !== 'fcm') fail('bad platform');
  const rawToken = c.token;
  if (typeof rawToken !== 'string' || !(platform === 'apns' ? APNS_TOKEN : FCM_TOKEN).test(rawToken)) fail('bad token');
  // APNs tokens are hex: canonicalise so case variants are one device. FCM tokens are case-sensitive.
  const token = platform === 'apns' ? rawToken.toLowerCase() : rawToken;

  const apnsEnv = c.apns_env;
  if (apnsEnv !== undefined && apnsEnv !== 'production' && apnsEnv !== 'sandbox') fail('bad apns_env');

  const ts = c.ts;
  if (typeof ts !== 'number' || !Number.isInteger(ts)) fail('bad ts');
  if (ts !== rumor.created_at) fail('ts must equal rumor created_at');
  if (ts < opts.nowSec - opts.limits.registrationMaxAgeSec) fail('registration too old');
  if (ts > opts.nowSec + opts.limits.registrationMaxSkewSec) fail('registration from the future');

  const categories: Record<Category, boolean> = { dm: false, zap: false, mention: false, payment: false };
  const relays: string[] = [];
  const nwc: NwcConnection[] = [];

  if (action === 'register') {
    const cats = c.categories;
    if (!cats || typeof cats !== 'object' || Array.isArray(cats)) fail('bad categories');
    for (const k of CATEGORIES) {
      const v = (cats as Record<string, unknown>)[k];
      if (v !== undefined && typeof v !== 'boolean') fail(`bad category ${k}`);
      categories[k] = v === true;
    }

    const rawRelays = c.relays ?? [];
    if (!Array.isArray(rawRelays)) fail('bad relays');
    if (rawRelays.length > opts.limits.maxRelaysPerRegistration * 2) fail('too many relays');
    for (const raw of rawRelays) {
      const n = normalizeRelayUrl(raw, opts.allowInsecureRelays);
      if (n && !relays.includes(n)) relays.push(n);
    }
    if (relays.length > opts.limits.maxRelaysPerRegistration) relays.length = opts.limits.maxRelaysPerRegistration;

    const rawNwc = c.nwc ?? [];
    if (!Array.isArray(rawNwc) || rawNwc.length > opts.limits.maxNwcPubkeysPerRegistration) fail('bad nwc');
    for (const entry of rawNwc) {
      const e = entry as Record<string, unknown> | null;
      if (!e || typeof e !== 'object') fail('bad nwc entry');
      const { client, wallet, proof } = e;
      if (typeof client !== 'string' || !HEX64.test(client)) fail('bad nwc client pubkey');
      if (typeof wallet !== 'string' || !HEX64.test(wallet)) fail('bad nwc wallet pubkey');
      if (typeof proof !== 'string' || !HEX128.test(proof)) fail('bad nwc proof');
      if (client === rumor.pubkey) fail('nwc client pubkey must not be the user pubkey');
      // Only the holder of the NWC connection secret can claim its notifications.
      let ok: boolean;
      try {
        ok = schnorr.verify(Buffer.from(proof, 'hex'), nwcProofMessage(rumor.pubkey, wallet), Buffer.from(client, 'hex'));
      } catch {
        ok = false;
      }
      if (!ok) fail('nwc proof invalid');
      if (!nwc.some((n) => n.client === client && n.wallet === wallet)) nwc.push({ client, wallet });
    }
  }

  return {
    user: rumor.pubkey,
    action,
    app: c.app,
    platform,
    token,
    categories,
    relays,
    nwc,
    ...(apnsEnv !== undefined ? { apnsEnv } : {}),
    ts,
    rumorId: rumor.id,
  };
}
