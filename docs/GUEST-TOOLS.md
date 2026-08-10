# Vexa Guest Tools

Vexa Guest Tools is a small Rust service for Linux and Windows guests. It does not depend on the
QEMU guest agent. The host communicates through a dedicated virtio-serial channel. Protocol v2
encrypts every command and response payload with AES-256-GCM and authenticates its envelope with an
outer HMAC, using direction-separated material derived from a unique per-VM 256-bit secret.

The implementation lives in the independent `guest-tools/` Rust workspace. Protocol details and the
full threat model are in [`guest-tools/docs/PROTOCOL.md`](../guest-tools/docs/PROTOCOL.md) and
[`guest-tools/docs/SECURITY.md`](../guest-tools/docs/SECURITY.md).

## What it can do

The protocol exposes a closed command enum rather than a shell:

- health and version reporting;
- set the configured account password;
- set the hostname;
- replace DNS servers;
- replace the Vexa-managed OpenSSH authorized-key block;
- request a graceful reboot; and
- request a graceful shutdown.

There is no command for arbitrary program execution, file upload, package installation, registry
editing, or host access. The guest configuration can independently disable password, hostname, DNS,
SSH-key, or power commands and can restrict commands to named guest accounts.

## Opt-in installation

**Install Vexa Guest Tools** is off by default in the VM creation flow. Automatic installation is
available only when all of these conditions are met:

1. the selected image is an automatic cloud-init, Cloudbase-Init, or Vexa unattended-Windows image
   supported by its catalog metadata;
2. the matching Linux or Windows artifact is present in a digest-verified, Ed25519-signed Vexa
   release payload; and
3. the VM is being created or reinstalled, so its trusted bootstrap media can be regenerated.

Windows cloud images declare `guest_tools_provisioner=cloudbase-init-nocloud`; automatic installer
ISOs declare `guest_tools_provisioner=windows-unattend`. Both require
`virtio_serial_driver=installed_signed` and a pinned provider-supplied VirtIO driver ISO. For the
installer path, Vexa builds one protected answer ISO containing Autounattend.xml, the signed storage,
network and serial drivers, QEMU Guest Agent, and the release-bound Windows Vexa executable. Drivers
and tools are installed before first-boot networking is applied. Vexa also acknowledges Microsoft's
bounded UEFI "Press any key" DVD prompt through libvirt, including when a prepared stopped guest is
started later; the credential-bearing answer media is the durable pending-install marker. Windows
Setup and authenticated Guest Tools bootstrap each have a bounded 30-minute completion window. The release pipeline authenticates
Guest Tools through the outer signed release artifact; it does not claim an Authenticode publisher
signature for the `.exe` or PowerShell installer.

## RouterOS integration

RouterOS CHR does not run the Vexa Rust service. Vexa uses CHR's vendor-provided QEMU Guest Agent,
which MikroTik ships for KVM, and labels this clearly as **built-in RouterOS integration**. Automatic
CHR provisioning applies hostname, DNS, routed public addresses, and default routes after the
appliance boots. MikroTik deliberately omits the `password` policy from QGA scripts, so Vexa enables
RouterOS REST only on the per-VM link-local transit and only for the hypervisor address, creates the
requested non-factory administrator, disables the blank factory `admin`, and disables HTTP again.
Live password changes use the same short-lived host-only link. Commands are passed to `virsh` over
private stdin so encoded values do not appear in process arguments. Automatic credentials require a
Vexa-routed public IPv4 `/32`, and the reserved factory username `admin` cannot be selected;
`vexa-admin` is the default. RouterOS SSH-key replacement is not exposed because CHR does not provide
an atomic managed-key-block operation equivalent to the Linux and Windows service.

Checking the box does not claim that an arbitrary already-running or manual-installer guest was
modified. For such a VM the panel records **install on next compatible reinstall** and reports the
tool as pending. If a requested artifact is missing, provisioning fails with a specific error instead
of silently continuing without the tool.

## Channel and keys

Each opted-in domain receives one libvirt channel:

```xml
<channel type="unix">
  <source mode="bind" path="/var/lib/vexa-vm/guest-tools/VM_ID.sock"/>
  <target type="virtio" name="com.vexa.guest_tools.0"/>
</channel>
```

Vexa-VM generates a different 32-byte random secret for every VM. The database stores only an
AES-256-GCM envelope bound to that VM's identity. Provisioning writes the base64 secret into a
root/Administrator-readable file inside the guest. Neither the secret nor password command payloads
may be placed in application logs, audit details, job error strings, or API responses.

The XML uses QEMU's bind/server-side Unix channel. The packaged setgid `kvm` socket directory and
`vexa` supplementary group are necessary, but libvirt does not provide a portable guarantee for the
socket mode or mandatory-access-control policy across distributions. Before production use, verify
that the actual QEMU/libvirt account can create the socket and that `vexa` can connect under the
host's AppArmor or SELinux policy. Do not solve a denial with a world-writable directory or broad
`chmod`; add the narrow distribution-specific group/MAC rule. Readiness records whether the socket
is absent, denied, refused, or timed out without exposing its path.

Requests use bounded length-prefixed JSON with a v2 envelope, timestamp, random nonce, request ID,
AES-256-GCM encrypted command and outer HMAC-SHA256 signature. Direction/version-specific key
derivation and authenticated metadata prevent request/response substitution. The guest authenticates
the envelope, enforces clock skew and a bounded replay cache, then decrypts and validates the closed
command enum. Encrypted responses are bound to the request ID, nonce, command type and time. Protocol
v1 is not accepted.

## Linux service

The Linux package installs `/usr/local/sbin/vexa-guest-tools`, a mode-0600 secret, a strict JSON
configuration, and a hardened systemd service. It connects to
`/dev/virtio-ports/com.vexa.guest_tools.0`. Password operations use native account tooling via stdin;
DNS changes use the supported resolver backend; SSH keys are written atomically with restrictive
permissions by the target account. Existing key files are opened without following the final
symlink, unreadable or non-UTF-8 content aborts the update, and the file plus containing directory
are synchronized before success is reported. The installer explicitly restarts the service on an
upgrade and fails if it does not remain active through its post-start health window. A failed
replacement restores the prior binary, secret, configuration, unit, enablement state, and running
state.

Address assignments are authoritative. After an administrator or API client adds or releases a VM
address, the host sends the complete current address, gateway, and DNS inventory over the
authenticated channel. Ubuntu-family guests publish `/etc/netplan/90-vexa-guest-tools.yaml`, verify
it with `netplan generate`, and restore the previous managed file if apply fails. Windows reconciles
the selected active adapter with native NetTCPIP and DNS cmdlets. RouterOS performs the equivalent
replacement through its built-in QEMU Guest Agent. Existing unmanaged configuration outside the
Vexa-owned Linux file is not edited, but settings for the same interface can be superseded by the
managed netplan definition.

See [`guest-tools/packaging/linux/install.sh`](../guest-tools/packaging/linux/install.sh) for the
standalone installer.

## Windows service

The Windows package installs the Rust executable as the `VexaGuestTools` Windows Service beneath
`%ProgramFiles%\Vexa\GuestTools`. Its configuration and secret live beneath `%ProgramData%\Vexa` with
an Administrator/SYSTEM ACL. It uses the virtio-serial named device exposed by the image provider's
installed signed VirtIO driver and native Windows account, DNS, hostname, OpenSSH, reboot, and
shutdown APIs or fixed system utilities. Redirected PowerShell payloads are UTF-8 encoded independently of the system code page,
and sensitive ACLs use well-known SYSTEM and Administrators SIDs so localized Windows editions are
supported. Upgrades stop and wait for the existing service before publishing staged files, retain a
rollback copy until the replacement remains Running, restore any OpenSSH configuration edit if a
later install step fails, and configure bounded automatic recovery.

Authenticated health responses include only commands enabled by guest policy and backed by the
required local utility/configuration. Windows reports operating-system uptime, not service uptime.
After bootstrap, the host refreshes authenticated health for opted-in running VMs every minute with
bounded concurrency; VMs without Guest Tools are never probed.

## Provisioning-seed retirement

Generated cloud-init, Cloudbase-Init and unattended-Windows ISO media can contain provisioning
credentials; Windows answer media necessarily carries the initial password, and an opted-in image
also carries its unique Guest Tools channel secret. Vexa serializes seed publication and bootstrap per VM. Only after the
agent authenticates with the exact installed secret and reports the expected signed-artifact version
does the host eject that exact ISO source from both the live and persistent libvirt definitions,
verify it is absent, and unlink it from the managed seed directory. A detach failure leaves the file
in place and the bootstrap retryable; it never ejects a CD-ROM merely by target name. The unlink is
not a promise of forensic secure erasure on copy-on-write or solid-state storage.

A Windows/Cloudbase image created with Guest Tools off has no authenticated completion signal. Its
seed therefore remains attached so Vexa cannot race first-boot provisioning. Treat that ISO as a
credential-bearing root-only asset, rotate the initial password after first boot, and have an
operator verify Cloudbase completion before manually ejecting/removing it. Enabling Guest Tools is
the automated retirement path; Vexa does not guess completion from a timer.

The signed release workflow requires the application and Guest Tools workspace versions to match.
When the configured artifact paths use `/opt/vexa-vm/current/guest-tools`, the advertised expected
version follows the running application's compile-time version across atomic panel updates and
rollbacks. Set `VEXA_GUEST_TOOLS_VERSION` only when both artifacts are administrator-managed outside
the signed release layout.

See
[`guest-tools/packaging/windows/Install-VexaGuestTools.ps1`](../guest-tools/packaging/windows/Install-VexaGuestTools.ps1).

## Operational status

The panel distinguishes:

- **disabled** — no channel or secret is requested;
- **pending install** — opted in but awaiting a compatible create/reinstall;
- **offline** — provisioned, but the authenticated health check cannot connect;
- **online** — the authenticated health check succeeded; and
- **error** — the last install or command failed.

Hostname, password, DNS, and SSH-key mutations report whether they were applied live or stored for
the next reinstall. Storing a desired value is not presented as a successful live guest change.

## Recovery and rotation

Rotating the host AES master key requires decrypting and re-encrypting each per-VM guest-tools
envelope during an offline maintenance procedure. A destructive reinstall stages a fresh
generation-bound guest secret in a separate encrypted envelope. The old active secret remains intact
until provisioning has installed the replacement and its expected version returns an authenticated
health response; the matching seed is retired and only then is the pending secret promoted
transactionally. A failed pre-install job
discards its pending generation, while an installed-but-offline replacement remains pending rather
than falling back to the prior disk's secret. Losing the host master key does not give access to a
guest, but it prevents the panel from authenticating to already-installed tools; use the manual
in-guest installer with a newly generated secret to recover that VM.
