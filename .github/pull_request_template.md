## What and why

<!-- What does this change, and why? Link the issue: Closes #N -->

## Privacy and security

<!-- Does this change what is stored, logged, sent to relays, or sent to Apple/Google? If so, update the README threat model / PROTOCOL.md. -->

- [ ] No device tokens, keys, nsecs, NWC secrets or production data in this PR (code, tests, fixtures or description)
- [ ] `info`-level logs still contain no user, device or event identifiers (per-user detail is `debug` only, via `pseudonym()`)
- [ ] Nothing identifying is stored in the clear (new identifying fields go into the encrypted identity blob)
- [ ] Registration format changes (if any) are documented in PROTOCOL.md and backwards-compatible within `v: 1`

## Test plan

- [ ] `npm run typecheck && npm run lint && npm test`
- [ ] New or changed behaviour is covered by tests
