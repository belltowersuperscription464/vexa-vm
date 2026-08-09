# Host integration

The panel checkbox is a provisioning policy, not a live toggle. For a new VM or destructive
reinstall, the Vexa control plane should perform these steps inside the existing durable job:

1. Resolve the Guest Tools artifact matching guest OS and architecture from the digest-verified Vexa
   payload whose release manifest passed Ed25519 verification. Refuse provisioning when that
   configured artifact is absent or invalid.
2. Generate a unique 32-byte secret from the operating-system CSPRNG. Encrypt it using the same
   master-key envelope discipline as VM passwords, but keep a separate record and reveal no endpoint.
3. Add a named libvirt channel to the VM definition. The socket directory and socket must never be
   accessible to tenant users or the web process outside its scoped helper.
4. Provision the artifact, configuration, base64 secret and installer. Linux cloud-init can use a
   `write_files` plus `runcmd` module. A Windows image must already contain a provider-supplied,
   trusted, signed virtio-serial driver and explicitly declare
   `guest_tools_provisioner=cloudbase-init-nocloud` plus
   `virtio_serial_driver=installed_signed`. Vexa Guest Tools does not bundle or silently install a
   virtio-serial driver.
5. Start the VM, wait for an authenticated v2 health response with the exact expected version, eject
   the exact generated seed source from both live and persistent domain definitions, verify that it
   is absent, unlink it, and only then promote a staged channel secret and record readiness. Seed
   generation and retirement must share the per-VM lock so an old bootstrap cannot unlink a newer
   reinstall seed. Agent installation or seed retirement failure must not silently report success.

Recommended libvirt device (replace the VM ID and socket path with validated values):

```xml
<channel type='unix'>
  <source mode='bind' path='/var/lib/vexa-vm/guest-tools/VM_ID.sock'/>
  <target type='virtio' name='com.vexa.guest_tools.0'/>
</channel>
```

The host-side client connects to the libvirt-owned Unix socket and uses the
`vexa-guest-protocol` crate for bounded framing, AES-256-GCM encryption, outer-HMAC verification,
replay protection and response-type validation. Serialize access per VM: only one request may be in
flight on a channel. Use a short connection/operation timeout and record the request ID, VM ID, actor
type/ID, source IP, action and outcome in Vexa's central audit log. Never record a password, protocol
secret, full SSH key, ciphertext or signed message.

QEMU creates the socket for `<source mode='bind'>`; its final ownership/mode and AppArmor or SELinux
permission are distribution and libvirt-policy dependent. Verify both QEMU creation access and the
`vexa` client's connect access on the installed host. A setgid `kvm` directory alone is not a
portable guarantee. Use narrow group and MAC-policy changes, never a world-writable socket directory
or broad recursive `chmod`. Surface missing, permission-denied, refused, and timed-out channels as
unavailable readiness with actionable operator text.

## Checkbox behavior

- Default: off, unless the administrator changes the node default.
- Creation/reinstall: embed and enable the agent before first boot.
- Existing VM: show **Install on next reinstall** unless an authenticated OS-specific bootstrap path
  is already available. The hypervisor cannot securely install software into an arbitrary running
  guest by itself.
- Removal: revoke/delete the encrypted host secret, detach the channel after shutdown, and provide an
  in-guest uninstall operation. Detaching the channel alone does not remove guest files.
- Destructive reinstall: stage a fresh secret in the new seed and do not promote it to the active
  host credential until the replacement service returns an authenticated health response. If
  provisioning fails, discard the staged secret and retain the prior credential for the prior disk.

Cloudbase-Init media without Guest Tools has no authenticated host completion signal and must not be
ejected on a timer. It can contain the initial Windows password; keep it protected and attached until
an operator verifies first-boot completion, rotates the password, and explicitly retires the media.

Do not fall back from Guest Tools to QEMU Guest Agent for password or key changes without clearly
reporting which mechanism executed the operation. Normal libvirt power controls remain the fallback
when the guest service is unavailable.

On Windows, install Microsoft OpenSSH Server before Guest Tools when SSH-key management is requested.
The installer validates and wires a protected per-user `AuthorizedKeysFile`; the agent rejects key
changes instead of reporting false success when that OpenSSH integration is absent. The Vexa release
signature authenticates the distributed Guest Tools payload, but the current workflow does not make
an Authenticode publisher claim for the `.exe` or PowerShell installer.
