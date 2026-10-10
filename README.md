# Lightning Piggy Watcher

A small, open-source TypeScript/Node service that sends **privacy-preserving push
notifications** for Nostr events. [Lightning Piggy](https://github.com/BenGWeeks/lightning-piggy-mobile)
uses it for:

| Category | Nostr events | Push text |
|---|---|---|
| Messages | NIP-04 DMs (kind 4) and NIP-17 DMs (kind 1059 gift wraps) | "New message" |
| Zaps | Zap receipts (kind 9735) | "Zap received" |
| Mentions | Notes that `p`-tag you (kind 1) | "New mention" |
| Payments | NWC wallet notifications (kinds 23196/23197) for your wallet connections | "Payment received" |

Marmot (MLS) group chats are covered by [Transponder](https://github.com/marmot-protocol/transponder)
([MIP-05](https://github.com/marmot-protocol/marmot)). Group members trigger those
pushes themselves. The watcher covers events that have no sender-side push
mechanism: it watches the relays and notices them itself.

## Privacy

**What the push contains.** Only a generic line such as "New message". There is
no sender, no text, no amount and no conversation. The app fetches and decrypts
the details itself once it opens.

**What Apple and Google learn.** For each push: the app id, the device token,
the time, the category (`dm`, `zap`, `mention` or `payment`, in the payload and
in the collapse id / thread id / Android tag and channel) and the coalesced count
(in the alert text, e.g. "3 new messages"). When a device first registers, the
watcher also checks its token once without showing anything: FCM `validate_only`
(nothing is delivered), or an APNs background push (`content-available`, no
alert). They never see message content, amounts, the Nostr kind, or who the
event came from.

**What the watcher operator learns.** The user's Nostr pubkey, linked to an app
id, a platform and a device token. Also the relays they listed, the public keys
of their NWC connections, and therefore **which wallet service** they use (the
wallet's pubkey and, usually, its relay). And **when** matching events arrive,
per category. The operator never sees any content. DMs, zap requests and NWC
payloads stay encrypted, and the watcher doesn't try to decrypt them: it routes
on public metadata only (kind, author, `p` tags). Registrations arrive over
Nostr relays, so the operator does not see users' IP addresses. All of this is
encrypted at rest (see [Storage](#storage-and-retention)), and at the default
log level the logs hold only aggregate counts (see [Logging](#logging)).

**Users opt in** per category, and unregistering deletes the registration.
Registrations that aren't refreshed expire after 30 days (the app refreshes
weekly).

### Threat model

| Party | Can | Can't |
|---|---|---|
| Watcher operator / anyone who compromises the running host (database + key) | Link a pubkey to a device token and app; see the timing of incoming events per category (by turning on debug logging or instrumenting the process); link NWC client keys and the wallet service to the user's identity; send generic pushes to registered devices | Read DMs, zap notes or wallet traffic; learn IP addresses; register or unregister someone else (the seal signature proves authorship) |
| Someone who gets the database file only (a backup, a disk image) | See how many registrations and (pseudonymous) users there are, each row's app id, platform, APNs environment, category toggles and timestamps; how many devices each pseudonymous user has; how many events notified, per hour | Learn any pubkey, relay, NWC key or device token: those are AES-256-GCM encrypted or replaced by keyed HMACs, with the key held in a separate secret file |
| Someone who gets the logs (at `info`) | See the watcher's own npub, relay connection health, and per-interval totals per category (events matched, pushes delivered/failed, registrations) | See any user, device or event identifier |
| Relay operators | See that the watcher's IP subscribes to a set of pubkeys, which marks them as likely Lightning Piggy users with notifications on ("the watcher is watching your key"). On relays a user listed, see the NWC client keys of that user's registered connections; when few users list that relay, the client key is linkable to them | See who registered (gift wraps use throwaway keys) or what was registered; see which categories a user turned on (every watched user gets the same filters, and NWC filters don't depend on the payment toggle) |
| Apple / Google | See delivery, timing, category and coalesced count of generic alerts, and one silent token check per newly registered device | See content, senders or Nostr kinds |
| Other Nostr users | Trigger a push by mentioning or zapping you. This is rate-limited: at most one push per category per 30 s window, and a per-device token bucket (bursts up to 60, refilling at 60 per hour). | Register your devices, change your settings, learn your token, claim your NWC connection (that needs a proof signed by the connection secret), or fake a payment push (it must come from your registered wallet) |
| Replay attacker (re-broadcasts old gift wraps) | Nothing | Roll back or resurrect a registration (newest-wins per device, per-user replay watermarks, 6-hour timestamp window), or use up your registration allowance (stale requests are rejected before rate-limiting) |

Known limits:

- A NIP-17 self-copy of a DM you sent triggers "New message" on your other devices.
- Marmot welcomes look like DMs.
- DMs on auth-gated inbox relays can't be seen. As of October 2026 that includes relay.damus.io, which requires NIP-42 AUTH to read kind 1059. The watcher authenticates as itself, which is enough for its own registration inbox but not for users' gift wraps there. Users' DMs are still seen on the watcher's other configured relays (`WATCHER_RELAYS`; nos.lol and primal by default) and on public inbox relays users list, within the user-relay cap (`WATCHER_MAX_USER_RELAYS`, default 40, most-referenced first).
- Anyone can publish a kind 9735, so a forged receipt can produce a "Zap
  received" push. Receipts are not checked against the LNURL server key.

[PROTOCOL.md](PROTOCOL.md) explains each of these.

## Architecture

```
          app (gift-wrapped kind 8480, seal signed by the user)
                │
                ▼
   ┌──────── relays ────────┐        ┌──────────────── watcher ─────────────────┐
   │ damus / nos.lol / …    │◀──REQ──│ RelayPool (backoff, ping, size/rate caps)│
   │ + users' inbox relays  │──EVT──▶│  ├ inbox: unwrap → validate → SQLite     │
   └────────────────────────┘        │  └ watch: dedupe → verify → route        │
                                     │        → coalesce (30 s) → rate-limit    │
                                     │        → APNs (HTTP/2) / FCM (HTTP v1)   │
                                     └──────────────────────────────────────────┘
```

- **Registration over Nostr** ([PROTOCOL.md](PROTOCOL.md)). The service is
  outbound-only. It exposes only `/health` and `/ready` on localhost.
- **Subscriptions.** The watcher subscribes on its default relays plus the
  relays users list. User relays are capped (default 40, most-referenced first).
  Every watched user gets the same filters, chunked to at most 400 `#p` values:
  one for kinds 1, 4 and 9735 and one for gift wraps, whatever categories they
  turned on. The router then drops events for categories a user didn't enable,
  so relays can't infer per-user category settings. (A registration with
  every category off isn't watched at all, so relays can see a user stop being
  watched, as with unregistering.) NWC filters (kinds
  23196/23197 by client key) are sent only to the relays that user listed
  (their wallet's relay), not to every default relay. They are sent whenever
  the registration lists NWC connections, whether or not payment pushes are on,
  so they don't reveal that toggle either.
  Regular kinds use `since = now − 120 s`. Gift-wrap filters don't use `since`
  at all, because NIP-59 back-dates `created_at` by up to 48 h: they use
  `limit: 1`, and only events that arrive after EOSE count as new. Event ids are
  deduplicated across relays.
- **Verification.** Events are structurally validated, then signature-checked
  before they can trigger a push or enter a dedupe cache. Events more than
  10 minutes old are ignored, except gift wraps. The user's own events are
  ignored. Keyed hashes of the ids of events that triggered a push are kept in
  SQLite for 2 days (with an hour bucket, not the exact time), so a restart
  doesn't re-notify. This store is capped at 100k rows and 600 inserts per
  minute. Beyond that, only the in-memory dedupe applies.
- **Bounds.** User-relay subscriptions are packed into multi-filter REQs, at most
  10 filters each. All inbound relay frames are rate-limited. NIP-42 AUTH is
  only answered on the watcher's own relays. The inbox queue is bounded by count
  and bytes. The registrations and replay-watermark tables are capped.
  Pushes, including deferred retries, share one work budget with fixed
  concurrency (32). Each send first re-checks that the exact registration
  version is still live with the category on. Throttling and 5xx responses are
  retried at most twice:
  - The watcher never retries earlier than `Retry-After`.
  - FCM quota errors wait at least 60 s.
  - A push that can't go out within 10 minutes is dropped.
- **Delivery.** APNs uses token auth (`.p8`). The topic is each registration's
  app id, and the environment comes from its `apns_env`, so one instance serves
  every app id and both environments. FCM uses HTTP v1 with
  service-account OAuth. Dead tokens (`410`/`BadDeviceToken`, `UNREGISTERED`,
  …) remove exactly the registration version that was sent.
- **Delivery guarantees: best effort.** Gift wraps that arrive while a relay
  connection is down are not reconciled afterwards, because NIP-59 timestamps
  are random. Regular kinds are caught up for the last 2 minutes on reconnect.
- **Storage.** SQLite (`better-sqlite3`). See [Storage and retention](#storage-and-retention).
- **SSRF guard.** User relays must be public `wss://` hostnames, and the socket's
  DNS lookup refuses private, loopback and link-local results.

## Storage and retention

Nothing identifying is stored in the clear. One 32-byte master key (the token
key file) derives separate HKDF subkeys for each use:

- **Device tokens**: AES-256-GCM, with associated data binding each ciphertext
  to its row; looked up by an HMAC of (platform, app, token).
- **Identity**: the user's pubkey, their relays and their NWC (client, wallet)
  keys are one AES-256-GCM blob per row, bound to the row. Rows and replay
  watermarks are looked up by a keyed HMAC of the pubkey, never the pubkey
  itself. The watcher decrypts identities into memory at startup and on
  changes to build relay filters and the routing index (NWC client lookups
  happen there, in memory).
- **Notified events**: keyed hashes of the ids, with an hour bucket.

Plaintext columns: app id, platform, APNs environment, category bitmask, and
timestamps (registration `ts`, last refresh, validation). Deletes use
`secure_delete`. A database from an older version (plaintext pubkeys, relays
and NWC keys) is migrated in place on first start, in one transaction. A
`VACUUM` and a WAL truncate follow, and they are retried at every start until
they complete. Back the database up first, and delete the backup once the
upgrade is verified, because the backup still holds the plaintext.

The database stores a keyed check value. If the token key file doesn't match
the database (a mistake in the configuration), the watcher refuses to start and
changes nothing, rather than dropping every registration as unreadable.

**If only the database file leaks**, it reveals counts, app ids, platforms,
category toggles, timestamps and how rows group by (pseudonymous) user. **With
the key as well**, it reveals everything the operator knows.

Retention:

| Data | Kept for |
|---|---|
| Registration | Until unregistered, its token is reported dead, it is evicted, or 30 days without a refresh (`WATCHER_REGISTRATION_TTL_DAYS`) |
| Replay watermark of a user with no live registration | The registration timestamp window (6 h), the minimum for replay safety. Purged hourly. |
| Notified-event hashes | 2 days |

## Capacity and admission

The registration table has a hard cap (`WATCHER_MAX_REGISTRATIONS`, default
1,000), sized for what the default relays can carry. Nostr keys are free, so
the cap is protected by several layers:

1. **Token check before admission.** A new device's token is checked with its
   push provider before it takes a slot, without showing the user anything:
   FCM `validate_only` (nothing is delivered) or an APNs background push
   (`apns-push-type: background`, `content-available`, `apns-expiration: 0`).
   A token the provider rejects is refused, so made-up tokens never take a
   slot. If the check can't be made (the provider is down or throttling, or
   that platform isn't configured), the device is admitted **provisionally**.
   The first push the provider accepts validates it. Refreshes of an existing
   device aren't re-checked, and no check is made for a request that would be
   refused anyway. Checks run on a few background workers, so a slow provider
   never holds up other registrations (refreshes, unregisters). They are
   budgeted at 4 × `WATCHER_NEW_REGISTRATIONS_PER_HOUR` per hour, so made-up
   tokens from fresh keys can't cause unbounded provider requests. Keys that
   already hold a live registration don't draw on that budget, so such a flood
   can't stop existing users adding a device. Past the budget, or with too
   many checks waiting, new devices are refused until the app's next refresh.
2. **Per-user and per-device shares.** One key holds at most
   `WATCHER_MAX_DEVICES_PER_USER` devices (default 10, 1% of the cap). An 11th
   replaces that key's least recently refreshed device. One device token can
   be registered by at most `WATCHER_MAX_USERS_PER_TOKEN` keys (default 5, for
   several accounts on one phone). Past that, the least recently refreshed of
   them is replaced, so one real device can't be multiplied across fresh keys.
3. **New-registration budget.** At most `WATCHER_NEW_REGISTRATIONS_PER_HOUR`
   new devices are admitted per hour across all keys (default 60). Refreshes
   don't count. Nobody can fill the cap faster than that, which gives the
   operator time to see it (`limit` in the activity log, `/ready`) and react.
   Existing registrations are never affected, but during such a burst a
   genuinely new device may be refused until the app's next refresh.
4. **Eviction at capacity.** When the table is full, a newcomer with a
   validated token evicts the least recently refreshed **provisional**
   registration. Validated registrations are never evicted to make room. If
   there is nothing provisional, the newcomer is refused.

Refused requests are settled into the user's replay watermark, so replaying
them can't trigger another token check. The app gets no acknowledgement (see
[PROTOCOL.md](PROTOCOL.md)), so it simply retries on its next refresh.

**Operator CLI** (prints no tokens, token hashes or keys):

```bash
docker exec lightning-piggy-watcher node dist/admin.js stats
docker exec lightning-piggy-watcher node dist/admin.js list [<npub|hex>]
docker exec lightning-piggy-watcher node dist/admin.js purge-user <npub|hex>
docker exec lightning-piggy-watcher node dist/admin.js purge-provisional [--older-than-days N]
```

Purging is cleanup, not a ban: a newer registration from the same key is
accepted again. The running watcher stops pushing to purged registrations
immediately, and drops their relay subscriptions at its next hourly sweep.

## Logging

JSON lines on stdout. At `LOG_LEVEL=info` (the default) the logs contain no
user, device or event identifiers, not even truncated ones. They hold:

- the watcher's own npub and relay health (user-supplied relays appear as
  opaque hashes);
- warnings and errors, with error codes but never raw network error messages.
  Provider-side warnings that can recur on every delivery (rejections,
  transport errors) are throttled to one line per kind per 5 minutes, with a
  count of how many were suppressed;
- an `activity` line every `WATCHER_ACTIVITY_LOG_SECONDS` (default 300; quiet
  intervals log nothing) with totals per category: events matched, pushes
  delivered, failed, retried, dropped, rate-limited and invalid tokens, plus
  registration outcomes.

`LOG_LEVEL=debug` adds a line per matched event, delivery and registration, for
troubleshooting only. There, users and devices appear as pseudonyms: a keyed
hash with a random per-process key. They correlate lines within one run but
can't be linked to the database or to another run. Tokens and content are
never logged at any level. Rotate the logs: `docker-compose.example.yml` caps
them at 3 × 10 MB.

## Configuration

| Env | Default | |
|---|---|---|
| `WATCHER_PRIVATE_KEY_FILE` | **required** | Nostr key (hex or nsec). It defines the watcher npub that apps build in. |
| `WATCHER_TOKEN_KEY_FILE` | **required** | 32-byte token-encryption key (hex or base64). |
| `WATCHER_DB_PATH` | `/data/watcher.db` | |
| `WATCHER_RELAYS` | `wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net` | The watcher's inbox and default watch relays. Published as kind 10050. |
| `WATCHER_APPS` | `com.lightningpiggy.app,…preview,…dev` | Accepted app ids (APNs topics). |
| `WATCHER_APNS_SANDBOX_APPS` | *(empty)* | Fallback only, for registrations without `apns_env`: app ids whose iOS tokens are treated as sandbox tokens. |
| `APNS_KEY_FILE`, `APNS_KEY_ID`, `APNS_TEAM_ID` | – | Enables APNs. |
| `FCM_SERVICE_ACCOUNT_FILE` (`FCM_PROJECT_ID`) | – | Enables FCM. The project id defaults to the one in the JSON. |
| `WATCHER_HEALTH_BIND` | `127.0.0.1:8080` | The image sets `0.0.0.0:8080`. Publish it on `127.0.0.1` only. |
| `WATCHER_REGISTRATION_TTL_DAYS` | `30` | Registrations not refreshed for this long expire. The app refreshes weekly. |
| `WATCHER_COALESCE_SECONDS` | `30` | |
| `WATCHER_DEVICE_PUSHES_PER_HOUR` | `60` | |
| `WATCHER_MAX_REGISTRATIONS` | `1000` | The admission cap. It is sized so the default relays can always carry every registration (worst case: all categories plus 3 NWC connections) within 15 REQs of at most 60 KB each. Raise it only together with the planner limits. If the plan ever overflows, `/ready` reports `plan_overflow`. |
| `WATCHER_MAX_DEVICES_PER_USER` | `10` | Per-key share of the cap. See [Capacity and admission](#capacity-and-admission). |
| `WATCHER_MAX_USERS_PER_TOKEN` | `5` | Keys that may register the same device token. |
| `WATCHER_NEW_REGISTRATIONS_PER_HOUR` | `60` | New devices admitted per hour, across all keys. `0` means unlimited. Token checks are budgeted at 4× this. |
| `WATCHER_MAX_USER_RELAYS` | `40` | |
| `WATCHER_ACTIVITY_LOG_SECONDS` | `300` | Interval of the aggregate `activity` log line. `0` turns it off. |
| `LOG_LEVEL` | `info` | `info` logs no user, device or event identifiers. See [Logging](#logging). |

## Self-hosting

```bash
npm ci && npm run build
mkdir -p secrets data && chmod 700 secrets data
node dist/keygen.js nostr secrets/watcher_private_key   # prints the npub only
node dist/keygen.js token secrets/watcher_token_key
docker compose -f docker-compose.example.yml up -d --build
curl -s 127.0.0.1:18087/ready
```

**Back up both secret files.** If the Nostr key changes, the npub changes, and
every app with the old npub built in stops reaching the watcher. If the token key
changes, all stored registrations become unreadable and are dropped.

Run the container read-only, with `cap_drop: ALL`, `no-new-privileges`, a
non-root user that owns the secret files, and a `tmpfs` `/tmp`.
`docker-compose.example.yml` has all of these.

## Development

Requires Node `^22.14.0` or `>= 24`, because `better-sqlite3` needs Node-API 10.

```bash
npm ci
npm run typecheck && npm run lint && npm test
```

The tests (vitest) cover:

- registration parsing, authentication and replay handling;
- filter planning and chunking;
- routing, deduplication and coalescing;
- APNs and FCM request building and error mapping, with HTTP mocked;
- invalid-token cleanup;
- privacy: aggregate-only `info` logs, admission (token checks, new-registration
  budget, provisional eviction), encryption at rest and the v1 migration,
  hashed notified ids, retention, uniform relay filters;
- an end-to-end run against an in-memory relay.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).
Never put tokens, keys or nsecs in an issue.

## License

[MIT](LICENSE)
