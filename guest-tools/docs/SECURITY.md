# Guest Tools security model

Vexa Guest Tools runs as root on Linux and LocalSystem on Windows because its supported operations
change machine-wide state. Treat it as a narrow privileged endpoint.

Required controls:

- Generate a unique 256-bit or stronger secret for every VM. Store host copies encrypted and guest
  copies with root/SYSTEM-only ACLs. Never put a secret in XML, process arguments, logs or an API.
- Keep the libvirt Unix socket below a root-owned mode-0700 directory. Do not expose it through the
  public Vexa web service, a VM-share directory, TCP proxy or VNC.
- Ship Guest Tools only inside an artifact covered by the signed Vexa release manifest and verify its
  pinned digest before provisioning. Guest Tools must never download or self-update from a URL
  supplied by a tenant.
- Maintain accurate guest clocks. Authentication intentionally fails outside the bounded clock-skew
  window. Clock synchronization is not a reason to expand it beyond 600 seconds.
- Log command names and outcomes on both sides, but redact passwords, secrets, signed frames and full
  public keys. The central Vexa audit event is authoritative for actor attribution.
- Restrict `policy.allowed_users` when a product exposes management for only one account. Keep unused
  command categories disabled in the guest configuration. An omitted policy is deny-by-default;
  Vexa provisioning writes each intentionally enabled category explicitly.
- On Linux, the SSH-key writer opens existing content without following the final symlink, rejects
  read errors and non-regular files, and publishes a synchronized mode-0600 temporary file as the
  target user with an atomic rename. This prevents the root service from following a
  user-controlled key target with elevated write privileges or erasing unreadable existing keys.
- On Windows, keep managed SSH keys below the SYSTEM/Administrators-only Guest Tools data directory,
  never below a user-writable profile. The installer prepends that protected per-user path to active
  OpenSSH `AuthorizedKeysFile` directives, validates the result with `sshd -t`, and restores its
  backup on failure. The image provider must preinstall a trusted, signed virtio-serial driver and
  declare that prerequisite in image metadata; Vexa does not bundle a driver. The current release
  workflow authenticates Guest Tools through the outer signed Vexa artifact and does not claim
  Authenticode signatures on the `.exe` or installer. ACL grants use well-known SIDs rather than
  localized account names; service upgrades are stopped and awaited before staged files are
  published, and Service Control Manager recovery is configured explicitly.

The v2 AES-256-GCM plus outer-HMAC channel authenticates Vexa to the guest and keeps command/response
payloads confidential on the local channel; it does not make a compromised guest trustworthy.
Guest-reported health and action results remain untrusted input. A compromised host can control every
guest regardless of this protocol, while a compromised guest must not gain access to another VM's
socket or secret.

The protocol intentionally omits arbitrary shell execution, file upload/download, registry
editing, service management, package installation and secret rotation. Those capabilities materially
expand the attack surface and require separate designs rather than generic command wrappers.
