# Changelog

All notable changes to Vexa-VM are documented here. The project follows Semantic Versioning after
the first stable release.

## 0.1.1 - 2026-08-11

### Added

- Default-on managed IP ownership enforcement that binds each VM TAP interface to the public IPv4
  and IPv6 addresses assigned by Vexa-VM, independently from the optional BCP38 policy.
- Shared-bridge and routed per-VM bridge enforcement for inbound and outbound managed-subnet
  traffic, including IPv4 ARP sender-address protection.
- An administrator setting and API field to explicitly disable or re-enable the ownership guard.

### Changed

- IP-pool and address changes now reconcile the ownership rules atomically, with rollback where a
  newly created pool cannot be enforced.
- VM network startup remains fail-closed when required ownership rules cannot be installed.

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
