# Security policy

## Supported versions

Only the latest commit on `main` is supported. Deployments pin a commit (see
the README's self-hosting notes), so upgrade to the latest `main` before you
report, if you can.

| Version | Supported |
|---|---|
| `main` (latest) | Yes |
| Anything older | No: please upgrade |

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository. That opens a private
security advisory that only the maintainers can see.

Please include:

- what an attacker can do, and what they need (network position, a Nostr key, a
  registered device, access to the host or database, …);
- steps to reproduce, ideally against a local instance (`npm test` and the
  in-memory relay in `test/helpers.ts` make this easy);
- the commit you tested.

**Never include secrets in a report**: no device push tokens, Nostr private keys
(nsec / hex), NWC connection strings (`nostr+walletconnect://…?secret=`), APNs
`.p8` keys, FCM service-account JSON, the watcher's token key, or unredacted
logs or databases from a production instance. Use made-up or test values, and
redact anything you're unsure about.

This is a small volunteer project. We'll acknowledge reports as soon as we can,
keep you updated in the advisory, and credit you in it unless you'd rather not
be named.

## Scope

The watcher is a server that holds sensitive material, so reports about any of
the following are in scope:

- **Push credentials**: the APNs `.p8` key and the FCM service account it uses to
  send notifications.
- **The watcher's own keys**: its Nostr private key (its identity, which apps
  build in) and the 32-byte token key, which encrypts data at rest.
- **What it stores about users**: device push tokens; user pubkeys, relay lists
  and NWC client and wallet pubkeys (encrypted at rest, with keyed-HMAC lookups);
  replay watermarks; and hashes of notified event ids.
- **What it logs**: logs at `info` must not contain user, device or event
  identifiers.

Examples of issues we want to hear about: registering or unregistering someone
else's device; forging a payment push; learning a device token or a user's
identity from the database file, the logs or the push payload; denying service
to registered users (for example by exhausting the registration capacity);
SSRF through user-supplied relay URLs; and anything that makes the
[privacy claims in the README](README.md#privacy) untrue.

Out of scope here (report upstream instead):

- the Lightning Piggy app: [lightning-piggy-mobile](https://github.com/BenGWeeks/lightning-piggy-mobile);
- Marmot push (MIP-05):
  [Transponder](https://github.com/marmot-protocol/transponder);
- Nostr relays, APNs and FCM themselves;
- the limits documented in the README's threat model, such as forged zap
  receipts or relays seeing which pubkeys the watcher watches, unless you find
  a way to make them worse than described.
