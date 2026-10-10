# Registration protocol (v1)

Apps register a device with the watcher over Nostr. There is no HTTP API. The
app sends a [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md)
gift wrap to the watcher's pubkey. The wrap carries a **kind 8480** rumor
whose JSON content describes the device and what to notify about.

## Why kind 8480

- The rumor only ever exists inside a gift wrap, so relays never see or store
  it. Kind-range storage rules (replaceable, addressable, ephemeral) don't apply
  to it. Of the three, an *addressable* kind would also suggest a public `d`-tagged
  record, which this is not.
- A **regular** kind fits best. Each registration is a one-off, timestamped
  instruction, and the watcher applies "newest wins" itself.
- 8480 is not in the NIPs kind table or the nostrbook registry (checked
  2026-10-10). It is deliberately far from the MIP-05 kinds (446–451) so it can't
  be confused with a Marmot push trigger.

## Layers

| Layer | Kind | Signed by | Encrypted to | Notes |
|---|---|---|---|---|
| Gift wrap | 1059 | throwaway key | watcher (NIP-44) | `["p", <watcher pubkey>]` tag. `created_at` may be randomised. |
| Seal | 13 | **the user** | watcher (NIP-44) | `tags` must be empty. Its signature is what authenticates the user. |
| Rumor | **8480** | unsigned | – | `pubkey` must equal the seal's pubkey. `id` must be the NIP-01 hash. `created_at` = `ts`. |

The watcher checks the seal signature and requires `rumor.pubkey == seal.pubkey`.
Together these prove that the user's key authored the request. Anyone can wrap a
seal, but only the key holder can sign one, so nobody can register or unregister
someone else.

## Rumor content

```jsonc
{
  "v": 1,
  "action": "register",                  // or "unregister"
  "app": "com.lightningpiggy.app",       // must be in the watcher's WATCHER_APPS
  "platform": "apns",                    // "apns" (iOS) or "fcm" (Android)
  "apns_env": "production",              // iOS only: "production" or "sandbox" (see below)
  "token": "<native device push token>", // APNs: 64–200 hex chars; FCM: 32–512 chars [A-Za-z0-9_:-.]
  "categories": { "dm": true, "zap": true, "mention": false, "payment": true },
  "relays": ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.getalby.com/v1"],
  "nwc": [{
    "client": "<hex pubkey of the app's NWC client key>",
    "wallet": "<hex pubkey of the NWC wallet service>",
    "proof": "<BIP-340 signature by the NWC client key, see below>"
  }],
  "ts": 1791590400                        // unix seconds, == rumor.created_at
}
```

| Field | Rules |
|---|---|
| `v` | Must be `1`. |
| `action` | `register` creates or replaces the registration for (user, app, token). `unregister` deletes it. Only `app`, `platform`, `token` and `ts` are read for `unregister`. |
| `app` | The app id. It is also the APNs topic, so it must be the iOS bundle id / Android package. The watcher only accepts ids it is configured for. |
| `apns_env` | Optional, iOS only: `production` (the default) or `sandbox`. This is the APNs environment the token was issued for. It follows the build's signing (`aps-environment` entitlement), not its bundle id. The iOS Simulator and development-signed (Xcode / `expo run:ios`) builds get `sandbox`. App Store, TestFlight and ad hoc builds get `production`, and that includes EAS `distribution: internal` builds of the dev client. Read it with `expo-application`'s `getIosPushNotificationServiceEnvironmentAsync()`, where `'development'` means `sandbox`. If the field is omitted, the operator's `WATCHER_APNS_SANDBOX_APPS` fallback applies (empty by default). |
| `categories` | Missing keys mean `false`. `dm` covers NIP-04 (kind 4) and NIP-17 (kind 1059). `zap` covers kind 9735. `mention` covers kind 1 with a `p` tag. `payment` covers NWC notifications (kinds 23196/23197). |
| `relays` | `wss://` only. Hostnames only: no IP literals, `localhost`, `.local` or similar. No credentials or query string. URLs are normalised and de-duplicated, and anything invalid is dropped. At most 8 are kept (sending more than 16 is rejected). Include the user's DM inbox relays (kind 10050), their read relays (kind 10002), **and the NWC wallet relay** if `payment` is on. The watcher always watches its own default relays for DMs, zaps and mentions as well, but sends NWC filters **only** to relays listed here (so the client keys aren't exposed to every default relay): without the wallet relay, payment pushes won't fire. NWC filters are sent whenever `nwc` is non-empty, whatever `categories.payment` says (so relays can't see that toggle); to stop watching a connection at all, omit it from `nwc`. |
| `nwc` | 0–3 entries, one per NWC connection. `client` is the pubkey of the connection's `secret` (the `p` tag on the wallet's notifications). `wallet` is the wallet service pubkey (the `nostr+walletconnect://<wallet>` part, and the author of the notifications). `proof` (128 hex chars) is a BIP-340 Schnorr signature **by the client secret** over `sha256("lightning-piggy-watcher/nwc/v1:" + <user pubkey hex> + ":" + <wallet pubkey hex>)`. The proof means only someone holding the connection secret can claim its notifications. It is bound to the user, so it can't be reused by anyone else. A payment push only fires when a kind 23196/23197 event `p`-tags `client` **and** is authored by `wallet`. |
| `ts` | Must equal the rumor's `created_at`. It must be no more than 6 hours in the past and no more than 2 minutes in the future. It must also **strictly increase** for each (user, token). |

### Replay protection and ordering

- Gift wraps are public, so anyone can re-broadcast an old one. For a device
  the watcher holds, it keeps the last accepted `ts` for each
  (user, app, device token). Anything with `ts <=` that value is ignored as
  `stale`.
- When a device is removed (by `unregister`, a dead token, or eviction of the
  oldest device), its row is deleted and the **user's replay watermark** is
  raised to that `ts`. A request for a device the watcher doesn't hold is
  `stale` if its `ts` is at or below the user's watermark. A replayed or
  out-of-order older `register` therefore can't bring a removed device back.
  This works even when the `unregister` arrives first, because an `unregister`
  for an unknown device still raises the watermark.
- **Keep `ts` monotonic per user**, across that user's devices. A new device
  whose `ts` is not after the user's latest unregister is ignored until its
  next refresh.
- The watermark table is bounded. Users with a live registration always get
  their own entry. If the table fills up with entries for other keys, the
  watcher fails closed with a global watermark. That watermark only applies to
  users with **no** state on this watcher (brand-new users), whose first
  registration can be delayed for as long as the flood lasts. Existing users
  are never affected.
- Requests refused for capacity or for an invalid token are settled into the
  user's watermark too, so their replays are stale (and can't trigger another
  token check).
- A watermark of a user with no live registration is kept only as long as the
  6-hour timestamp window: after that, every request it could block is refused
  as too old anyway.
- Stale and replayed requests are rejected before they count against the user's
  hourly allowance.
- Tokens are scoped to (platform, app, token). A rejection for one app id
  (for example `DeviceTokenNotForTopic`) only removes that one registration, and
  only the exact version that was sent.
- Because of the 6-hour window, a registration sent while the watcher was down for
  longer than that is dropped. Refreshing periodically (see below) covers this.

### Limits

Per user: 30 registration events per hour and 10 devices. When an 11th device
registers, the least recently refreshed one is dropped. If the new device's
`ts` isn't newer than the one it would replace, the new device is refused instead. Registrations that are
not refreshed for **30 days** expire.

Per watcher: by default 1,000 registrations. That is the most its default relays
can provably carry within 15 subscriptions of at most 60 KB each. Admission into
that cap (details in the README, "Capacity and admission"):

- A **new device's token is checked** with APNs/FCM before it is admitted,
  without showing anything (FCM `validate_only`; an APNs background push with
  `content-available` and no alert). A token the provider rejects is refused.
  If the check can't be made, the device is admitted provisionally, until its
  first accepted push.
- At most 60 **new devices** are admitted per hour across all keys by default
  (refreshes don't count), and one device token can be registered by at most
  5 keys (several accounts on one phone). Past that, the least recently
  refreshed of them is replaced.
- When full, a newcomer with a validated token replaces the least recently
  refreshed provisional registration; validated registrations are never
  replaced. Otherwise the newcomer is refused, and the app retries on its next
  refresh.

### No acknowledgement

The watcher is outbound-only and does not reply. A reply would itself be a gift
wrap to the user, which would trigger a "New message" push. The app should treat
registration as fire-and-forget and re-send it when:

- notifications are first enabled, or a category toggle changes;
- the native push token changes (`addPushTokenListener`);
- the set of NWC connections changes;
- the app starts and the last registration is more than **7 days** old.

On logout, or when notifications are disabled, send `unregister`. Send the
registration to the relays in the watcher's kind-10050 list (fall back to its
defaults: `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.primal.net`).

## Push payload

All pushes use generic text only. The title is `Lightning Piggy`.

| category | body (count = 1) | body (coalesced) | suggested tap target |
|---|---|---|---|
| `dm` | New message | N new messages | Messages |
| `zap` | Zap received | N zaps received | Home / Notifications |
| `mention` | New mention | N new mentions | Notifications |
| `payment` | Payment received | N payments received | Home (wallet) |

Data (FCM `data`, APNs top-level keys): `{ "source": "lp-watcher", "category": "<category>" }`.
The category is all the app needs to route a tap; the Nostr kind isn't sent.
APNs uses `thread-id` and `apns-collapse-id` = `lp-<category>`. FCM uses `collapse_key` and
`android.notification.tag` = `lp-<category>`, and posts to the Android channel `messages` (dm, mention) or `payments` (zap, payment). A newer push for the same category
therefore replaces the older one on the device.

Apple and Google see the category (in the data, the collapse id / thread id and
the Android tag and channel) and the coalesced count (in the alert text), as
well as the app id, the device token and the time.

The only other push is the **token check** when a device first registers. On
FCM it is `validate_only` and never reaches the device. On iOS it is a silent
background push, `{ "aps": { "content-available": 1 }, "source": "lp-watcher", "type": "validate" }`,
which the app should ignore.

`payment` is triggered by any NWC notification from the registered wallet,
including `payment_sent`, because the watcher can't decrypt them. A payment the
user makes in the app happens while the app is in the foreground, where it
should suppress the alert.

## Client implementation (TypeScript, nostr-tools)

```ts
import { finalizeEvent, generateSecretKey, getEventHash, type NostrEvent } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

export const WATCHER_PUBKEY = '<hex of the watcher npub>';
export const REGISTRATION_KIND = 8480;

/** Signer abstraction the app already has (nsec / Amber NIP-55 / NIP-46). */
interface Signer {
  getPublicKey(): Promise<string>;
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
  signEvent(t: { kind: number; created_at: number; tags: string[][]; content: string }): Promise<NostrEvent>;
}

interface Registration {
  action: 'register' | 'unregister';
  app: string;
  platform: 'apns' | 'fcm';
  token: string;
  categories: { dm: boolean; zap: boolean; mention: boolean; payment: boolean };
  relays: string[]; // inbox + read relays + NWC relay(s); <= 8
  nwc: { client: string; wallet: string; proof: string }[]; // <= 3
  apns_env?: 'production' | 'sandbox'; // iOS: from getIosPushNotificationServiceEnvironmentAsync()
}

/** Prove we hold an NWC connection's secret (from nostr+walletconnect://<wallet>?secret=<hex>). */
export function nwcEntry(userPubkey: string, walletPubkey: string, nwcSecretHex: string) {
  const secret = hexToBytes(nwcSecretHex);
  const msg = sha256(utf8ToBytes(`lightning-piggy-watcher/nwc/v1:${userPubkey}:${walletPubkey}`));
  return {
    client: bytesToHex(schnorr.getPublicKey(secret)),
    wallet: walletPubkey,
    proof: bytesToHex(schnorr.sign(msg, secret)),
  };
}

const now = () => Math.floor(Date.now() / 1000);
const randomPast = (t: number) => t - Math.floor(Math.random() * 2 * 86400); // NIP-59 timestamp tweak

export async function buildRegistrationWrap(signer: Signer, reg: Registration, lastTs: number): Promise<NostrEvent> {
  const pubkey = await signer.getPublicKey();
  const ts = Math.max(now(), lastTs + 1); // must strictly increase per (user, token)
  const rumor = {
    kind: REGISTRATION_KIND,
    pubkey,
    created_at: ts,
    tags: [] as string[][],
    content: JSON.stringify({ v: 1, ...reg, ts }),
  };
  const rumorWithId = { ...rumor, id: getEventHash(rumor) };

  // Seal: the user's key encrypts the rumor to the watcher and signs it.
  // With Amber / NIP-46 these are the only two signer operations.
  const seal = await signer.signEvent({
    kind: 13,
    created_at: randomPast(ts),
    tags: [],
    content: await signer.nip44Encrypt(WATCHER_PUBKEY, JSON.stringify(rumorWithId)),
  });

  // Wrap: a throwaway key, so relays can't see who registered.
  const eph = generateSecretKey();
  return finalizeEvent(
    {
      kind: 1059,
      created_at: randomPast(now()),
      tags: [['p', WATCHER_PUBKEY]],
      content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(eph, WATCHER_PUBKEY)),
    },
    eph,
  );
}
// Publish the wrap to the watcher's kind-10050 relays, then persist `ts` as lastTs.
```

## Things the app should handle

- **Self-copies of sent NIP-17 DMs.** These are gift wraps `p`-tagged to the
  sender. The watcher can't tell them apart from incoming DMs, so the user's
  *other* devices get "New message" for messages they sent themselves.
- **Marmot welcomes** (kind 444 inside kind 1059) look exactly like NIP-17 DMs,
  so the watcher sends "New message" for them. If Transponder (MIP-05) also
  notifies for the same invite, the user sees two notifications. Marmot group
  messages (kind 445) are not `p`-tagged, so the watcher never sees them, and
  Transponder handles those alone. Collapse or ignore duplicate `lp-watcher` dm
  pushes when the app opens.
- **Foreground.** Suppress the system alert for `source: lp-watcher` pushes
  while the app is open, because live data already shows the event.
- **Token check.** Ignore the silent `type: validate` background push (iOS)
  sent when a device first registers.
- **Auth-gated inbox relays** (NIP-42 relays that only serve kind 1059 to the
  recipient) won't deliver the user's gift wraps to the watcher, because it can't
  authenticate as the user. List public inbox relays if DM pushes matter.
