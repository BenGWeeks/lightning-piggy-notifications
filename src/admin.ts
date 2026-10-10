// Operator CLI for the registrations database. Prints no secrets: never device
// tokens, token hashes or keys. Uses the same env/secret files as the watcher,
// so run it inside the container:
//
//   docker exec lightning-piggy-watcher node dist/admin.js stats
//   docker exec lightning-piggy-watcher node dist/admin.js list [<npub|hex>]
//   docker exec lightning-piggy-watcher node dist/admin.js purge-user <npub|hex>
//   docker exec lightning-piggy-watcher node dist/admin.js purge-provisional [--older-than-days N]
//
// Purging is cleanup, not a ban: a newer registration from the same key is
// accepted again. The running watcher stops pushing to purged registrations
// at once and drops their relay subscriptions at its next hourly sweep.

import { decode as nip19Decode, npubEncode } from 'nostr-tools/nip19';
import { loadConfig } from './config.js';
import { setLogLevel } from './log.js';
import { CATEGORIES } from './registration.js';
import { Store } from './store.js';

const out = (s: string) => process.stdout.write(s + '\n');

function usage(): never {
  process.stderr.write('usage: admin.js stats | list [<npub|hex>] | purge-user <npub|hex> | purge-provisional [--older-than-days N]\n');
  process.exit(2);
}

export function parsePubkey(raw: string | undefined): string {
  const s = (raw ?? '').trim();
  if (s.startsWith('npub1')) {
    const d = nip19Decode(s);
    if (d.type === 'npub') return d.data;
  }
  if (/^[0-9a-fA-F]{64}$/.test(s)) return s.toLowerCase();
  throw new Error('expected an npub or a 64-char hex pubkey');
}

function main(argv: string[]): void {
  const [cmd, arg, val] = argv;
  // Exact arity per command: a typo must never widen a purge.
  const arity: Record<string, number[]> = { stats: [1], list: [1, 2], 'purge-user': [2], 'purge-provisional': [1, 3] };
  if (!cmd || !arity[cmd] || !arity[cmd].includes(argv.length)) usage();
  setLogLevel('warn');
  const cfg = loadConfig();
  const store = new Store(cfg.dbPath, cfg.tokenKey, cfg.limits, cfg.apnsSandboxApps);
  try {
    const now = Math.floor(Date.now() / 1000);
    if (cmd === 'stats') {
      const rows = store.adminList();
      const by = (f: (r: (typeof rows)[number]) => string) => {
        const m: Record<string, number> = {};
        for (const r of rows) m[f(r)] = (m[f(r)] ?? 0) + 1;
        return m;
      };
      out(
        JSON.stringify(
          {
            registrations: store.countActive(),
            provisional: store.countProvisional(),
            users: new Set(rows.map((r) => r.user)).size,
            capacity: cfg.limits.maxRegistrations,
            by_app: by((r) => r.app),
            by_platform: by((r) => r.platform),
          },
          null,
          2,
        ),
      );
    } else if (cmd === 'list') {
      for (const r of store.adminList(arg ? parsePubkey(arg) : undefined)) {
        const cats = CATEGORIES.filter((c) => r.categories[c]).join(',') || '-';
        const updated = new Date(r.updatedAt * 1000).toISOString().slice(0, 16);
        out(
          [npubEncode(r.user), r.app, r.platform, cats, r.validated ? 'validated' : 'provisional', `updated=${updated}`, `relays=${r.relays}`, `nwc=${r.nwc}`].join(
            '  ',
          ),
        );
      }
    } else if (cmd === 'purge-user') {
      out(`removed ${store.purgeUser(parsePubkey(arg))} registration(s)`);
    } else {
      let days = 0;
      if (arg !== undefined) {
        if (arg !== '--older-than-days' || !/^\d+$/.test(val ?? '')) usage();
        days = Number(val);
      }
      out(`removed ${store.purgeProvisional(now - days * 86400)} provisional registration(s)`);
    }
  } finally {
    store.close();
  }
}

if (process.argv[1]?.endsWith('admin.js')) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`error: ${e instanceof Error ? e.message : 'failed'}\n`);
    process.exit(1);
  }
}
