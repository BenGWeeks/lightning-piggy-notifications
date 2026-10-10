# Lightning Piggy notifications (watcher)

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

**What Apple and Google learn.** That a Lightning Piggy notification in one of
four generic categories was delivered to a device, and when. They never see
message content, amounts, or who the event came from.

**What the watcher operator learns.** The user's Nostr pubkey, linked to an app
id, a platform and an (encrypted) device token. Also the relays they listed, the
public keys of their NWC wallet connections, and **when** matching events arrive.
The operator never sees any content. DMs, zap requests and NWC payloads stay
encrypted, and the watcher doesn't try to decrypt them: it routes on public
metadata only (kind, author, `p` tags). Registrations arrive over Nostr relays,
so the operator does not see users' IP addresses.

**Users opt in** per category, and unregistering deletes the registration.

### Threat model

| Party | Can | Can't |
|---|---|---|
| Watcher operator / anyone who compromises the host | Link a pubkey to a device token and app; see the timing of incoming events per category; link NWC client keys to the user's identity (public relays don't reveal that link); send generic pushes to registered devices | Read DMs, zap notes or wallet traffic; learn IP addresses; register or unregister someone else (the seal signature proves authorship) |
| Someone who steals the database file only | See pubkeys, app ids, relays and NWC client keys | Recover device tokens (AES-256-GCM, with the key held in a separate secret file) |
| Relay operators | See that the watcher's IP subscribes to a set of pubkeys, which marks them as likely Lightning Piggy users with notifications on | See who registered (gift wraps use throwaway keys) or what was registered |
| Apple / Google | See delivery and timing of generic category alerts | See content or senders |
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
  Filters are grouped by kind set and chunked to at most 400 `#p` values.
  Regular kinds use `since = now − 120 s`. Gift-wrap filters don't use `since`
  at all, because NIP-59 back-dates `created_at` by up to 48 h: they use
  `limit: 1`, and only events that arrive after EOSE count as new. Event ids are
  deduplicated across relays.
- **Verification.** Events are structurally validated, then signature-checked
  before they can trigger a push or enter a dedupe cache. Events more than
  10 minutes old are ignored, except gift wraps. The user's own events are
  ignored. Ids of events that triggered a push are kept in SQLite for 3 days, so
  a restart doesn't re-notify. This store is capped at 100k rows and 600 inserts
  per minute. Beyond that, only the in-memory dedupe applies.
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
- **Storage.** SQLite (`better-sqlite3`). Tokens are encrypted with
  AES-256-GCM, with associated data binding each ciphertext to its row, and
  indexed by HMAC. Registrations not refreshed for 60 days expire.
- **SSRF guard.** User relays must be public `wss://` hostnames, and the socket's
  DNS lookup refuses private, loopback and link-local results.

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
| `WATCHER_REGISTRATION_TTL_DAYS` | `60` | |
| `WATCHER_COALESCE_SECONDS` | `30` | |
| `WATCHER_DEVICE_PUSHES_PER_HOUR` | `60` | |
| `WATCHER_MAX_REGISTRATIONS` | `1000` | The admission cap. It is sized so the default relays can always carry every registration (worst case: all categories plus 3 NWC connections) within 15 REQs of at most 60 KB each. Raise it only together with the planner limits. If the plan ever overflows, `/ready` reports `plan_overflow`. |
| `WATCHER_MAX_USER_RELAYS` | `40` | |
| `LOG_LEVEL` | `info` | JSON logs. Ids are truncated, and user-supplied relays are logged as opaque hashes. Tokens, content and raw network error messages are never logged. |

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
- an end-to-end run against an in-memory relay.

## License

[MIT](LICENSE)
