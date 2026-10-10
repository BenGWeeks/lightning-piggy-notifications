// Event -> (user, category) routing. Uses only public event metadata (kind,
// author, p-tags); content is never read or decrypted.

import type { NostrEvent } from 'nostr-tools/pure';
import type { Category } from './registration.js';
import type { RegistrationSummary } from './store.js';

export interface Match {
  user: string;
  category: Category;
}

/** Bound on p-tags examined per event (mass-mention spam). */
const MAX_P_TAGS = 100;

export class RouteIndex {
  /** user -> categories enabled on at least one device. */
  private readonly userCats = new Map<string, Set<Category>>();
  /** NWC client pubkey -> (user, wallet) pairs with payments enabled; capped per client key. */
  private readonly nwcOwners = new Map<string, { user: string; wallet: string }[]>();

  constructor(regs: readonly RegistrationSummary[], maxOwnersPerNwcClient = 3) {
    for (const r of regs) {
      const cats = this.userCats.get(r.user) ?? new Set<Category>();
      for (const [k, on] of Object.entries(r.categories)) if (on) cats.add(k as Category);
      this.userCats.set(r.user, cats);
      if (r.categories.payment) {
        for (const n of r.nwc) {
          const owners = this.nwcOwners.get(n.client) ?? [];
          if (owners.some((o) => o.user === r.user && o.wallet === n.wallet)) continue;
          if (owners.length >= maxOwnersPerNwcClient) continue;
          owners.push({ user: r.user, wallet: n.wallet });
          this.nwcOwners.set(n.client, owners);
        }
      }
    }
  }

  get size(): number {
    return this.userCats.size;
  }

  route(ev: NostrEvent): Match[] {
    const pTags: string[] = [];
    for (const t of ev.tags) {
      if (t[0] === 'p' && typeof t[1] === 'string' && !pTags.includes(t[1])) {
        pTags.push(t[1]);
        if (pTags.length >= MAX_P_TAGS) break;
      }
    }
    const out: Match[] = [];
    const added = new Set<string>();
    const add = (user: string, category: Category) => {
      const key = `${user}|${category}`;
      if (!added.has(key) && this.userCats.get(user)?.has(category)) {
        added.add(key);
        out.push({ user, category });
      }
    };

    switch (ev.kind) {
      case 4:
      case 1:
        for (const p of pTags) if (p !== ev.pubkey) add(p, ev.kind === 4 ? 'dm' : 'mention');
        break;
      case 1059:
        // Author is a throwaway key; self-copies of our own sent DMs can't be told apart.
        for (const p of pTags) add(p, 'dm');
        break;
      case 9735: {
        const sender = ev.tags.find((t) => t[0] === 'P')?.[1];
        for (const p of pTags) if (p !== sender) add(p, 'zap');
        break;
      }
      case 23196:
      case 23197:
        // Only the registered wallet service may trigger a payment push.
        for (const p of pTags) {
          for (const o of this.nwcOwners.get(p) ?? []) if (o.wallet === ev.pubkey) add(o.user, 'payment');
        }
        break;
    }
    return out;
  }
}

/** Bounded insertion-ordered id -> first-seen-time map for event dedupe across relays. */
export class SeenCache {
  private readonly map = new Map<string, number>();
  constructor(private readonly max = 200_000) {}
  has(id: string): boolean {
    return this.map.has(id);
  }
  /** When the id was first recorded (ms), or undefined. */
  firstSeen(id: string): number | undefined {
    return this.map.get(id);
  }
  add(id: string, at = Date.now()): void {
    if (this.map.has(id)) return;
    this.map.set(id, at);
    if (this.map.size > this.max) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
  }
  get size(): number {
    return this.map.size;
  }
}
