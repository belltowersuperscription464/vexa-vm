# Changelog

All notable changes to Vexa-VM are documented here. The project follows Semantic Versioning after
the first stable release.

## 0.1.0 - 2026-08-10

### Added

- Rust/Axum single-node KVM control plane with mock and libvirt hypervisor backends.
- Responsive Tailwind administration panel and versioned REST/OpenAPI interface.
- VM lifecycle, provisioning, snapshots, resize, maintenance, pause/suspend, reinstall and deletion.
- IPv4/IPv6 inventory, routed networking, rate limits, enforced traffic quotas and opt-in firewall,
  DDoS, BCP38, disk-protection and network-protection controls.
- Scoped customer status links and one-time ten-minute same-origin noVNC sessions.
- AES-256-GCM guest secrets, Argon2id accounts, role-based administrators and scoped API keys.
- Linux and Windows Vexa Guest Tools over an authenticated VM-bound virtio-serial channel.
- Host/guest metrics history, durable jobs, activity audit and IP abuse evidence records.
- Verified remote image downloads, signed in-panel update workflow and rollback checks.
- Immutable release archives, one-line installer, Debian packaging and signed APT publication tooling.
