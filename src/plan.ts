// Pure subscription planning: registrations -> per-relay REQ filters.
//
// * Default relays carry the watcher's own inbox (registrations) and every
//   registered user's filters; user-listed relays carry only their users.
// * User relays are capped globally (most-referenced first) so registrations
//   can't make the watcher fan out to an unbounded number of hosts.
// * #p values are chunked (<= limits.pTagChunk per filter) and users are
//   grouped by the exact kind set they need, so a user with mentions off
//   doesn't pull kind-1 traffic.
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
  /** pubkey -> regular kinds wanted (4 / 1 / 9735). */
  regular: Map<string, Set<number>>;
  wraps: Set<string>;
  nwc: Set<string>;
}

const emptyWants = (): Wants => ({ regular: new Map(), wraps: new Set(), nwc: new Set() });

function addWants(w: Wants, r: RegistrationSummary): void {
  const kinds = w.regular.get(r.user) ?? new Set<number>();
  if (r.categories.dm) {
    kinds.add(KIND_DM4);
    w.wraps.add(r.user);
  }
  if (r.categories.zap) kinds.add(KIND_ZAP);
  if (r.categories.mention) kinds.add(KIND_MENTION);
  if (kinds.size) w.regular.set(r.user, kinds);
  if (r.categories.payment) for (const n of r.nwc) w.nwc.add(n.client);
}

function specsFor(w: Wants, pTagChunk: number): FilterSpec[] {
  const out: FilterSpec[] = [];
  // Group users by identical kind sets.
  const groups = new Map<string, string[]>();
  for (const [pk, kinds] of w.regular) {
    const key = [...kinds].sort((a, b) => a - b).join(',');
    const g = groups.get(key) ?? [];
    g.push(pk);
    groups.set(key, g);
  }
  for (const [key, pks] of [...groups.entries()].sort()) {
    const kinds = key.split(',').map(Number);
    for (const part of chunk(pks.sort(), pTagChunk)) {
      out.push({ mode: 'live', filter: { kinds, '#p': part }, sinceAgoSec: LIVE_SINCE_SLACK_SEC });
    }
  }
  for (const part of chunk([...w.wraps].sort(), pTagChunk)) {
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
    for (const url of opts.defaultRelays) addWants(wantsFor(url), r);
    for (const url of r.relays) if (userRelays.has(url)) addWants(wantsFor(url), r);
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
