// Pure subscription planning: registrations -> per-relay REQ filters.
//
// * Default relays carry the watcher's own inbox (registrations) and every
//   registered user's filters; user-listed relays carry only their users.
// * User relays are capped globally (most-referenced first) so registrations
//   can't make the watcher fan out to an unbounded number of hosts.
// * Privacy: relays should learn only that a pubkey is watched, not what the
//   user toggled. Every watched user gets the same filters — one superset
//   regular-kinds filter (4, 1, 9735) and one gift-wrap filter per #p chunk —
//   and the router drops what a user didn't enable. NWC client keys (which
//   would otherwise be linkable to the user by filter grouping on every
//   default relay) are only sent to relays that user listed, i.e. their
//   wallet's relay.
// * #p values are chunked (<= limits.pTagChunk per filter).
// * Chunks of the same mode are packed into multi-filter REQs (<=
//   limits.filtersPerReq filters each), bounding subscriptions per relay.
// * Subscription ids are a hash of the filters (minus `since`), so re-planning
//   only reopens subscriptions whose content changed.

import { createHash } from 'node:crypto';
import type { Filter } from 'nostr-tools/filter';
import type { Limits } from './config.js';
import type { RegistrationSummary } from './store.js';

export type SubMode =
  /** The watcher's own inbox: registrations, processed even before EOSE. */
  | 'inbox'
  /** Users' gift wraps: created_at is randomised, so only post-EOSE events notify. */
  | 'wrap'
  /** Regular events bounded by `since`; fresh pre-EOSE events (reconnect catch-up) notify. */
  | 'live';

export interface SubTemplate {
  id: string;
  mode: SubMode;
  /** Filters without `since`; `sinceAgoSec` is applied to each when the REQ is sent. */
  filters: Filter[];
  sinceAgoSec?: number;
}

interface FilterSpec {
  mode: SubMode;
  filter: Filter;
  sinceAgoSec?: number;
}

export type Plan = Map<string, SubTemplate[]>;

/** Catch-up slack for regular kinds after a (re)subscribe. */
export const LIVE_SINCE_SLACK_SEC = 120;
/** NIP-59 randomises created_at up to 2 days back; plus the registration window. */
export const INBOX_SINCE_SEC = 2 * 86400 + 7 * 3600;
export const INBOX_LIMIT = 500;
/** Gift-wrap subs never notify pre-EOSE events, so ask for as few as possible. */
export const WRAP_LIMIT = 1;

const KIND_DM4 = 4;
const KIND_WRAP = 1059;
const KIND_MENTION = 1;
const KIND_ZAP = 9735;
const NWC_KINDS = [23196, 23197];

export function chunk<T>(arr: readonly T[], size: number): T[][] {
  if (size <= 0) throw new Error('chunk size must be positive');
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function subId(mode: SubMode, filters: Filter[]): string {
  return `${mode[0]}${createHash('sha256').update(JSON.stringify(filters)).digest('hex').slice(0, 20)}`;
}

/** REQ envelope + per-filter `since` allowance when budgeting bytes. */
const REQ_OVERHEAD_BYTES = 64;
const SINCE_BYTES = 24;

/**
 * Pack filter specs of the same mode into REQs of at most `perReq` filters and
 * `maxBytes` serialized bytes (relays reject oversized frames).
 */
export function pack(specs: readonly FilterSpec[], perReq: number, maxBytes = Infinity): SubTemplate[] {
  const byMode = new Map<string, FilterSpec[]>();
  for (const sp of specs) {
    const key = `${sp.mode}|${sp.sinceAgoSec ?? ''}`;
    const g = byMode.get(key) ?? [];
    g.push(sp);
    byMode.set(key, g);
  }
  const out: SubTemplate[] = [];
  const emit = (part: FilterSpec[]) => {
    const filters = part.map((p) => p.filter);
    const first = part[0]!;
    const tpl: SubTemplate = { id: subId(first.mode, filters), mode: first.mode, filters };
    if (first.sinceAgoSec !== undefined) tpl.sinceAgoSec = first.sinceAgoSec;
    out.push(tpl);
  };
  for (const group of byMode.values()) {
    let part: FilterSpec[] = [];
    let bytes = REQ_OVERHEAD_BYTES;
    for (const sp of group) {
      const b = JSON.stringify(sp.filter).length + 1 + (sp.sinceAgoSec !== undefined ? SINCE_BYTES : 0);
      if (part.length && (part.length >= perReq || bytes + b > maxBytes)) {
        emit(part);
        part = [];
        bytes = REQ_OVERHEAD_BYTES;
      }
      part.push(sp);
      bytes += b;
    }
    if (part.length) emit(part);
  }
  return out;
}

/** Choose user relays to connect to: most-referenced first, capped. */
export function selectUserRelays(regs: readonly RegistrationSummary[], defaults: readonly string[], cap: number): Set<string> {
  const counts = new Map<string, number>();
  for (const r of regs) {
    for (const url of r.relays) {
      if (defaults.includes(url)) continue;
      counts.set(url, (counts.get(url) ?? 0) + 1);
    }
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  return new Set(sorted.slice(0, cap).map(([u]) => u));
}

interface Wants {
  /** Watched user pubkeys: every one gets the same (superset) filters. */
  users: Set<string>;
  nwc: Set<string>;
}

/** Regular kinds every watched user is subscribed to, whatever they enabled. */
export const REGULAR_KINDS = [KIND_MENTION, KIND_DM4, KIND_ZAP];

const emptyWants = (): Wants => ({ users: new Set(), nwc: new Set() });

function addWants(w: Wants, r: RegistrationSummary, withNwc: boolean): void {
  if (!Object.values(r.categories).some(Boolean)) return;
  w.users.add(r.user);
  if (withNwc && r.categories.payment) for (const n of r.nwc) w.nwc.add(n.client);
}

function specsFor(w: Wants, pTagChunk: number): FilterSpec[] {
  const out: FilterSpec[] = [];
  const users = [...w.users].sort();
  for (const part of chunk(users, pTagChunk)) {
    out.push({ mode: 'live', filter: { kinds: REGULAR_KINDS, '#p': part }, sinceAgoSec: LIVE_SINCE_SLACK_SEC });
  }
  for (const part of chunk(users, pTagChunk)) {
    out.push({ mode: 'wrap', filter: { kinds: [KIND_WRAP], '#p': part, limit: WRAP_LIMIT } });
  }
  for (const part of chunk([...w.nwc].sort(), pTagChunk)) {
    out.push({ mode: 'live', filter: { kinds: NWC_KINDS, '#p': part }, sinceAgoSec: LIVE_SINCE_SLACK_SEC });
  }
  return out;
}

export function buildPlan(
  regs: readonly RegistrationSummary[],
  opts: { watcherPubkey: string; defaultRelays: readonly string[]; limits: Limits },
): Plan {
  const userRelays = selectUserRelays(regs, opts.defaultRelays, opts.limits.maxUserRelays);
  const perRelay = new Map<string, Wants>();
  const wantsFor = (url: string): Wants => {
    let w = perRelay.get(url);
    if (!w) perRelay.set(url, (w = emptyWants()));
    return w;
  };
  for (const url of opts.defaultRelays) wantsFor(url);

  for (const r of regs) {
    // NWC filters only where the user listed the relay (their wallet's relay).
    for (const url of opts.defaultRelays) addWants(wantsFor(url), r, r.relays.includes(url));
    for (const url of r.relays) if (userRelays.has(url)) addWants(wantsFor(url), r, true);
  }

  const plan: Plan = new Map();
  const overflow = new Map<string, number>();
  for (const [url, w] of perRelay) {
    const specs = specsFor(w, opts.limits.pTagChunk);
    if (opts.defaultRelays.includes(url)) {
      specs.unshift({
        mode: 'inbox',
        filter: { kinds: [KIND_WRAP], '#p': [opts.watcherPubkey], limit: INBOX_LIMIT },
        sinceAgoSec: INBOX_SINCE_SEC,
      });
    }
    let subs = pack(specs, opts.limits.filtersPerReq, opts.limits.reqMaxBytes);
    if (subs.length > opts.limits.maxSubsPerRelay) {
      // Admission (maxRegistrations) is sized so this can't happen with the
      // defaults; if limits are raised, keep the inbox and fail loudly.
      overflow.set(url, subs.length - opts.limits.maxSubsPerRelay);
      subs = subs.slice(0, opts.limits.maxSubsPerRelay);
    }
    if (subs.length) plan.set(url, subs);
  }
  lastOverflow = overflow;
  return plan;
}

let lastOverflow = new Map<string, number>();
/** Subscriptions dropped per relay by the last buildPlan (empty when everything fit). */
export function planOverflow(): ReadonlyMap<string, number> {
  return lastOverflow;
}
