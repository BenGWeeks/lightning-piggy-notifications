# Contributing

Issues and pull requests are welcome.

- Use Node 22. Run `npm ci`, then `npm run typecheck && npm run lint && npm test`. CI runs the same checks, plus gitleaks and a Docker build.
- Keep dependencies minimal. Each new runtime dependency is attack surface for a service that holds push credentials.
- Never log device tokens, event content, raw network error messages, or full pubkeys or ids. At `info` and above, log nothing that identifies a user or device (not even a prefix): count outcomes with `Activity` (`src/activity.ts`) instead. Per-user detail belongs at `debug`, with identifiers passed through `pseudonym()` from `src/log.ts`.
- Nothing identifying is stored in the clear: new identifying columns go into the encrypted identity blob, with lookups through a keyed HMAC index (`src/store.ts`).
- Any change to the registration format must update [PROTOCOL.md](PROTOCOL.md) and stay backwards-compatible within `v: 1`.
- Report security issues privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.
- Never paste device tokens, keys, nsecs, NWC connection strings or unredacted logs from a production instance into issues or PRs.
- By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
