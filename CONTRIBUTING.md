# Contributing

Issues and pull requests are welcome.

- Use Node 22. Run `npm ci`, then `npm run typecheck && npm run lint && npm test`. CI runs the same checks, plus gitleaks and a Docker build.
- Keep dependencies minimal. Each new runtime dependency is attack surface for a service that holds push credentials.
- Never log device tokens, event content, or full pubkeys or ids. Use `short()` from `src/log.ts`.
- Any change to the registration format must update [PROTOCOL.md](PROTOCOL.md) and stay backwards-compatible within `v: 1`.
- Report security issues privately through GitHub's "Report a vulnerability" (Security tab), not in a public issue.
