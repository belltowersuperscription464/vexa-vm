# Architecture

## Trust boundaries

Vexa-VM separates four kinds of callers even though the first release ships as one binary:

1. The admin panel authenticates with a server-side session and CSRF token.
2. Automation authenticates with hash-only, scoped API keys.
3. A customer portal authenticates with a VM-bound status token and can perform only its recorded
   scopes. It cannot change allocated CPU, RAM, disk, port speed, traffic quota or IP ownership.
4. A VNC link is a separate one-time credential. It has a fixed ten-minute lifetime and grants only
   a WebSocket relay to the VM's loopback VNC target.

`Hypervisor` is the privileged boundary. Route handlers never compose shell commands. The libvirt
backend validates names, MAC addresses, storage roots and image paths before invoking fixed binaries
with argument arrays. The mock backend implements the same contract for development and API testing.

```text
Browser / API client
        |
        v
Axum routes -- auth + CSRF + validation + request ID
        |
        +--> SQLite repositories (WAL, FK, transactions, audit)
        |
        +--> service operations / durable jobs
                  |
                  +--> Hypervisor trait --> libvirt tools or mock
                  +--> host sampler -----> /proc, /sys, `ip -j`
                  +--> signed updater ---> staging + approval spool
                                              |
                                              v
                                      root update executor
                                      (fixed typed operations)
```

## Persistence

`migrations/0001_init.sql` is authoritative. SQLite runs with WAL, foreign keys, a busy timeout and
transactional reservations. The major records are:

- admins, sessions and API keys;
- VMs plus a separately encrypted secret envelope;
- networks, ranges, individual dual-stack addresses, assignments and DNS;
- images/ISOs and their checksum/provisioning metadata;
- host and VM metric samples, traffic periods, jobs and snapshots;
- customer/VNC tokens and append-only audit events;
- validated node settings and schema migration history.

All times are UTC Unix seconds. Byte fields are bytes; live network rates are bytes per second, not
bits per second. The UI converts units at the edge. Traffic usage is combined RX + TX. A zero/null
traffic quota means unlimited. When sampled usage exceeds a positive quota, the control plane sets
the primary libvirt interface link down for both the live guest and persistent definition. The
Vexa-owned enforcement state is durable, is reapplied at startup and after power/reinstall actions,
and is cleared only after a limit increase/removal or an administrator traffic reset successfully
restores the link.

Audit entries are immutable activity records. The activity service normalizes actor/request context,
redacts credential-shaped details and represents datacenter IP-abuse reports as queryable
`resource_type=ip_abuse` events. Abuse observations never trigger automatic enforcement.

Signed release discovery and staging run without privilege. Activation/rollback are approval-bound
data requests for a separate constrained root helper; the web process never invokes an arbitrary
command or package. The helper consumes UUID requests exactly once, independently repeats signature,
digest, path and package validation, backs up SQLite, activates immutable versioned releases through
an atomic symlink, and publishes root-owned structured status. QEMU/libvirt remain
distribution-managed packages and can use only exact signed versions from fixed APT allowlists. See
`docs/UPDATES.md`.

## Provisioning

The image record declares `cloud_image` or `installer_iso`, architecture, format, firmware, guest-agent
support, cloud-init support, automatic/manual mode and expected SHA-256. The libvirt backend creates a
new VM disk beneath the configured storage root; it never lets a request choose an arbitrary host path.
Cloud images use a copy-on-write qcow2 overlay. Manual images attach a read-only ISO and boot from it.
Remote sources are acquired only from HTTPS port 443 after public-address DNS validation. Each redirect
is revalidated and DNS is pinned for the connection. The response is bounded and hashed into a unique
partial file, then atomically renamed only when the administrator-supplied SHA-256 matches.

VM creation is represented as a job. Within one Vexa process, a dedicated reservation mutex spans the
host-capacity check, IP/DNS association, provisional `creating` VM row and create-job publication.
That row is the durable CPU/RAM reservation counted by the next request; while it remains `creating`,
its requested disk is also deducted from filesystem free space because the worker may not have created
the disk yet. Concurrent creates therefore cannot both pass against the same capacity snapshot. A
publication failure removes the provisional row and its transactional address associations before
releasing the mutex. The request releases the mutex immediately after publishing the job and neither
performs nor waits for libvirt or disk work. The desired state remains visible if later host work
fails, and the job records the safe operator error. Destructive reinstall requires explicit
confirmation and should be preceded by a snapshot or backup in production. Once libvirt accepts a
reinstall, its staged encrypted password (or manual-install password removal) is committed to the VM
row before inventory, firewall, start, traffic, or Guest Tools post-steps run. A later post-step
failure therefore leaves the operation failed for operator visibility without reverting the panel to
the destroyed guest's credential.

Deletion serializes domain removal and provisioning-seed cleanup with the per-VM Guest Tools/seed
lock. The domain operation is idempotent (`NotFound` means it was already removed), but the VM row is
kept as durable ownership until `<vm-id>.iso` has been removed and the managed directory synced.
Transient hypervisor, filesystem, or database failures receive bounded job retries; a terminal
cleanup failure remains attached to the retained VM row instead of silently orphaning seed material.
The delete job also retains immutable target ID/name fields: if the process stops after the VM-row
commit clears its foreign key but before the job is marked successful, startup grants a finalizer
attempt that re-verifies the named domain and seed are absent before completing the operation.

## Networking

The schema models IPv4 and IPv6, public/private ranges, a protected main-node address, reservations,
gateways and associations. The libvirt adapter supports a configured shared bridge and Vexa-managed
routed per-VM TAP/bridge links. The network-security reconciler owns a dedicated nftables table,
applies updates atomically, reserves every host-bound IP and fails closed if required rules cannot load.
The default host policy binds each TAP to its assigned addresses inside Vexa-managed pool CIDRs in
both directions, including ARP sender validation; optional BCP38 extends source validation beyond
those managed ranges.

VM DNS servers, the recoverable password and customer-managed SSH keys are stored desired values.
Cloud-image create/reinstall jobs place them into a newly generated cloud-init or Cloudbase-Init
seed. When the administrator opts into Vexa Guest Tools for a compatible image, the same seed also
installs the digest-verified Linux/Windows Rust service from the signed Vexa release, a unique VM
secret and a libvirt virtio-serial channel. After exact authenticated bootstrap, Vexa ejects that
specific seed from the live and persistent domain definitions, verifies detachment, and unlinks it;
tools-off Cloudbase media remains a protected operator-retired asset because there is no trusted
completion signal. Later hostname, password, DNS and SSH-key responses report
`applied` only after an authenticated live
response; otherwise they report a saved/pending value. Manual installer images must configure the
guest independently: create and reinstall reject a supplied provisioning password, manual creation
stores none, and a successful manual reinstall clears any prior stored password.

## Metrics

Host discovery reads stable Linux sources and reports the exact bind port, interfaces, routes, CPU,
memory, disks and KVM/libvirt capability. Host samples distinguish live use from VM allocations.
VM samples should use libvirt CPU-time deltas, balloon/QGA memory, block counters and interface
counters. Guest filesystem utilization remains `null` when the guest agent cannot supply it.

## Scaling path

For multi-node or untrusted tenancy, split the binary into an unprivileged web/control-plane service
and a minimal local agent, authenticate them with mutually authenticated TLS, move jobs to a durable
queue, and use PostgreSQL for shared control-plane state. The trait and job boundaries are designed to
permit that split without changing the public API.
