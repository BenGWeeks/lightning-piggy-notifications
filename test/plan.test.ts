import { describe, expect, it } from 'vitest';
import { DEFAULT_LIMITS } from '../src/config.js';
import { buildPlan, chunk, INBOX_SINCE_SEC, planOverflow, selectUserRelays, WRAP_LIMIT, type SubTemplate } from '../src/plan.js';

/** Flatten packed REQs into (mode, filter) pairs. */
const flat = (subs: SubTemplate[]) => subs.flatMap((s) => s.filters.map((filter) => ({ mode: s.mode, filter, sinceAgoSec: s.sinceAgoSec })));
import type { RegistrationSummary } from '../src/store.js';

const pk = (i: number) => i.toString(16).padStart(64, '0');
const reg = (i: number, over: Partial<RegistrationSummary> = {}): RegistrationSummary => ({
  user: pk(i),
  tokenHash: `t${i}`,
  app: 'com.lightningpiggy.app',
  platform: 'fcm',
  categories: { dm: true, zap: true, mention: true, payment: false },
  relays: [],
  nwc: [],
  ...over,
});
const WATCHER = 'f'.repeat(64);
const DEFAULTS = ['wss://a.example', 'wss://b.example'];

describe('chunk', () => {
  it('splits into bounded chunks', () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 3)).toEqual([]);
  });
});

describe('buildPlan', () => {
  it('puts the inbox only on default relays, with a since window', () => {
    const plan = buildPlan([reg(1, { relays: ['wss://user.example'] })], { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: DEFAULT_LIMITS });
    for (const url of DEFAULTS) {
      const inbox = plan.get(url)!.find((s) => s.mode === 'inbox')!;
      expect(inbox.filters).toHaveLength(1);
      expect(inbox.filters[0]).toMatchObject({ kinds: [1059], '#p': [WATCHER] });
      expect(inbox.sinceAgoSec).toBe(INBOX_SINCE_SEC);
    }
    expect(plan.get('wss://user.example')!.some((s) => s.mode === 'inbox')).toBe(false);
  });

  it('gift-wrap subs never use since; regular subs do', () => {
    const plan = buildPlan([reg(1)], { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: DEFAULT_LIMITS });
    const subs = flat(plan.get(DEFAULTS[0]!)!);
    const wrap = subs.find((s) => s.mode === 'wrap')!;
    expect(wrap.filter).toEqual({ kinds: [1059], '#p': [pk(1)], limit: WRAP_LIMIT });
    expect(wrap.sinceAgoSec).toBeUndefined();
    const live = subs.find((s) => s.mode === 'live')!;
    expect(live.filter.kinds).toEqual([1, 4, 9735]);
    expect(live.sinceAgoSec).toBeGreaterThan(0);
  });

  it('chunks #p values and groups users by kind set', () => {
    const regs = Array.from({ length: 1100 }, (_, i) => reg(i + 1));
    regs.push(reg(5000, { categories: { dm: false, zap: true, mention: false, payment: false } }));
    const plan = buildPlan(regs, { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: DEFAULT_LIMITS });
    const live = flat(plan.get(DEFAULTS[0]!)!).filter((s) => s.mode === 'live');
    for (const s of live) expect(s.filter['#p']!.length).toBeLessThanOrEqual(DEFAULT_LIMITS.pTagChunk);
    expect(live.filter((s) => s.filter.kinds!.join() === '1,4,9735')).toHaveLength(3);
    expect(live.find((s) => s.filter.kinds!.join() === '9735')!.filter['#p']).toEqual([pk(5000)]);
    expect(flat(plan.get(DEFAULTS[0]!)!).filter((s) => s.mode === 'wrap')).toHaveLength(3);
    // Chunks are packed into few REQs, each within the filter-count and byte budgets.
    const subs = plan.get(DEFAULTS[0]!)!;
    expect(subs.length).toBeLessThan(flat(subs).length);
    for (const s of subs) {
      expect(s.filters.length).toBeLessThanOrEqual(DEFAULT_LIMITS.filtersPerReq);
      expect(JSON.stringify(['REQ', s.id, ...s.filters]).length).toBeLessThanOrEqual(DEFAULT_LIMITS.reqMaxBytes);
    }
  });

  it('watches NWC client pubkeys only for users with payments on', () => {
    const nwc = 'c'.repeat(64);
    const plan = buildPlan(
      [
        reg(1, { categories: { dm: false, zap: false, mention: false, payment: true }, nwc: [{ client: nwc, wallet: 'e'.repeat(64) }] }),
        reg(2, { nwc: [{ client: 'd'.repeat(64), wallet: 'e'.repeat(64) }] }),
      ],
      { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: DEFAULT_LIMITS },
    );
    const nwcSub = flat(plan.get(DEFAULTS[0]!)!).find((s) => s.filter.kinds!.includes(23196))!;
    expect(nwcSub.filter).toEqual({ kinds: [23196, 23197], '#p': [nwc] });
  });

  it('subscription ids are stable for unchanged filters', () => {
    const a = buildPlan([reg(1), reg(2)], { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: DEFAULT_LIMITS });
    const b = buildPlan([reg(2), reg(1)], { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: DEFAULT_LIMITS });
    expect(a.get(DEFAULTS[0]!)!.map((s) => s.id)).toEqual(b.get(DEFAULTS[0]!)!.map((s) => s.id));
  });

  it('packs at most filtersPerReq filters per REQ', () => {
    const regs = Array.from({ length: 30 }, (_, i) => reg(i + 1));
    const plan = buildPlan(regs, { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: { ...DEFAULT_LIMITS, pTagChunk: 2, filtersPerReq: 4 } });
    const subs = plan.get(DEFAULTS[0]!)!;
    for (const s of subs) expect(s.filters.length).toBeLessThanOrEqual(4);
    expect(flat(subs).filter((s) => s.mode === 'wrap')).toHaveLength(15);
    expect(subs.filter((s) => s.mode === 'wrap')).toHaveLength(4);
  });

  it('default capacity carries maxRegistrations worst-case registrations within maxSubsPerRelay', () => {
    const nwc = (i: number) =>
      Array.from({ length: DEFAULT_LIMITS.maxNwcPubkeysPerRegistration }, (_, j) => ({ client: (i * 8 + j + 1).toString(16).padStart(64, 'c'), wallet: 'e'.repeat(64) }));
    const regs = Array.from({ length: DEFAULT_LIMITS.maxRegistrations }, (_, i) =>
      reg(i + 1, { categories: { dm: true, zap: true, mention: true, payment: true }, nwc: nwc(i) }),
    );
    const plan = buildPlan(regs, { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: DEFAULT_LIMITS });
    const subs = plan.get(DEFAULTS[0]!)!;
    expect(subs.length).toBeLessThanOrEqual(DEFAULT_LIMITS.maxSubsPerRelay);
    expect(planOverflow().size).toBe(0);
    // Every REQ, as sent (with since), fits the frame budget.
    for (const s of subs) {
      const filters = s.filters.map((f) => (s.sinceAgoSec !== undefined ? { ...f, since: 1_800_000_000 } : f));
      expect(JSON.stringify(['REQ', s.id, ...filters]).length).toBeLessThanOrEqual(DEFAULT_LIMITS.reqMaxBytes);
    }
  });

  it('truncates (keeping the inbox) and reports overflow past maxSubsPerRelay', () => {
    const regs = Array.from({ length: 50 }, (_, i) => reg(i + 1));
    const plan = buildPlan(regs, { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: { ...DEFAULT_LIMITS, pTagChunk: 1, filtersPerReq: 1, maxSubsPerRelay: 5 } });
    expect(plan.get(DEFAULTS[0]!)!).toHaveLength(5);
    expect(plan.get(DEFAULTS[0]!)![0]!.mode).toBe('inbox');
    expect(planOverflow().get(DEFAULTS[0]!)).toBeGreaterThan(0);
  });

  it('caps user relays globally, most-referenced first', () => {
    const regs = [
      reg(1, { relays: ['wss://popular.example', 'wss://rare.example'] }),
      reg(2, { relays: ['wss://popular.example'] }),
      reg(3, { relays: ['wss://popular.example', DEFAULTS[0]!] }),
    ];
    expect([...selectUserRelays(regs, DEFAULTS, 1)]).toEqual(['wss://popular.example']);
    const plan = buildPlan(regs, { watcherPubkey: WATCHER, defaultRelays: DEFAULTS, limits: { ...DEFAULT_LIMITS, maxUserRelays: 1 } });
    expect([...plan.keys()].sort()).toEqual([...DEFAULTS, 'wss://popular.example'].sort());
  });
});
