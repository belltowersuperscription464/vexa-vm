# Contributing to Vexa-VM

Thanks for helping build a dependable open-source KVM control plane.

## Before opening a change

1. Search existing issues and discussions.
2. Open an issue before large schema, API, hypervisor, security, or UI changes.
3. Keep pull requests focused and explain the operator-visible behavior.
4. Never include real customer data, public infrastructure addresses, credentials, private keys,
   production database extracts, or proprietary migration artifacts.

## Development setup

Use Linux, Rust 1.75 or newer, Node.js 22, and the locked dependencies:

```bash
npm ci
npm run build
npm test
cargo test --locked --all-targets
cargo test --locked --manifest-path guest-tools/Cargo.toml --workspace
```

Source runs use the mock hypervisor by default. Set a unique development `VEXA_MASTER_KEY`, database,
and storage directory. Do not point a development process at a production libvirt URI.

## Engineering expectations

- Preserve API compatibility or document the versioned migration.
- Put schema changes in a new numbered migration; never edit a released migration.
- Validate identifiers and paths before invoking host tools. Do not add shell-evaluated API input.
- Keep firewall and protection features disabled by default.
- Avoid logging passwords, bearer tokens, cookies, private keys, or decrypted guest data.
- Add tests for authorization boundaries, failure cleanup, and idempotency.
- Update operator documentation and `docs/openapi.json` with user-visible API changes.

## Pull requests

All checks must pass. Maintainers may request threat-model notes for changes involving authentication,
networking, image downloads, updates, guest communication, or privileged host operations.

Contributions are accepted under the repository's AGPL-3.0-or-later license.
