# Vexa Guest Tools

Vexa Guest Tools is the optional, open-source in-guest service used when an administrator selects
**Install Vexa Guest Tools** while creating or reinstalling a VM. It provides deterministic guest
operations without depending on QEMU Guest Agent availability. It supports Linux and Windows from
one Rust codebase and shares its wire protocol with the Vexa host.

The initial command set is deliberately small:

- authenticated ping and health/capability discovery;
- change a local account password without putting the password in logs or a shell command line;
- change hostname and DNS servers;
- replace only the Vexa-managed block of a user's OpenSSH authorized keys;
- acknowledge, then perform guest shutdown or reboot.

The service does not run arbitrary commands, transfer arbitrary files, execute scripts supplied by
the host, or expose a TCP listener. Linux uses
`/dev/virtio-ports/com.vexa.guest_tools.0`; Windows uses the corresponding
`\\.\Global\com.vexa.guest_tools.0` virtio-serial device.

## Workspace

```text
guest-tools/
  crates/protocol  v2 AEAD messages, outer HMAC, replay cache and bounded framing
  crates/agent     Linux/Windows service and tightly scoped OS operations
  packaging/linux systemd unit and image/provisioning installer
  packaging/windows elevated PowerShell service installer
  docs             host integration, protocol and security requirements
```

Build the Linux binary on Linux:

```bash
cargo build --manifest-path guest-tools/Cargo.toml \
  --locked --package vexa-guest-tools --release
```

Build the Windows binary from a trusted Windows builder, or with a configured Rust cross toolchain:

```powershell
cargo build --manifest-path guest-tools/Cargo.toml `
  --locked --package vexa-guest-tools --release
```

Release artifacts must be reproducibly built and included in the SHA-256-bound, Ed25519-signed Vexa
release payload. Vexa provisioning must verify that release signature and artifact digest before
placing an artifact in a guest image. Windows images must separately provide a trusted, signed
virtio-serial driver; Vexa Guest Tools does not bundle one and the current workflow makes no
Authenticode publisher claim for the `.exe` or PowerShell installer.

## Installation contract

The Vexa host creates a random secret of at least 32 bytes for each VM. The secret is stored encrypted
by the host and provisioned as base64 into a root/SYSTEM-only file. Never reuse a secret between VMs.
The Linux and Windows installers accept a secret *file* so the secret is not exposed in process
arguments. The service configuration can independently disable password, hostname, DNS, SSH-key or
power operations and optionally restrict operations to named local users.

See [Host integration](docs/HOST-INTEGRATION.md), [Protocol](docs/PROTOCOL.md), and
[Security](docs/SECURITY.md) before wiring the create/reinstall checkbox.
