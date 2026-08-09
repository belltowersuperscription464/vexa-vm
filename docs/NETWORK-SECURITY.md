# Network and disk protection

Vexa-VM separates tenant-selectable VM policy from host-wide anti-spoofing. Upgrading or installing
the application does not enable a packet filter, rate limit, blocked port, deletion lock, automatic
snapshot, or BCP38 policy. An administrator must review and enable each control explicitly.

## Safe defaults

The database creates every VM network-security profile with these values:

- VM firewall: off;
- DDoS enforcement: off (conservative editable thresholds are stored but inert);
- invalid-packet filtering: off;
- each individual firewall rule: off;
- default ingress and egress action: accept; and
- host BCP38 source-address validation: off.

When every control is off, the reconciler emits no active forwarding policy and removes only the
`bridge vexa_vm` table previously owned by Vexa-VM. It does not edit another nftables table, the host
input chain, SSH access, the distribution firewall, or a datacenter firewall.

## VM firewall and DDoS controls

An administrator configures a VM from its **Network protection** card. A policy is matched to the
host-owned libvirt TAP interface in the bridge forwarding path; a guest-controlled source MAC is
never treated as a security identity. Rules support ingress or egress, IPv4 or
IPv6 CIDRs, TCP/UDP source and destination port ranges, ICMP/ICMPv6, priorities, accept/drop/reject,
and optional rate-limited nftables logging. A rule has its own enabled switch and remains inert until
both the rule and the VM firewall are enabled.

The DDoS profile provides deliberately simple node-edge limits for TCP SYN packets, UDP packets,
ICMP packets, new TCP connections, invalid connection-tracking states, and basic scan throttling.
These controls reduce noisy traffic; they are not a replacement for upstream scrubbing. Set limits
from measurements taken on the actual workload. A threshold that is too low can drop legitimate
traffic.

Policy changes are compiled, checked with `nft --check`, and then applied as one nftables
transaction. The panel reports the desired revision separately from the applied revision and stores
the last apply error. A failed apply must not be described as active protection.

The packaged systemd unit grants the unprivileged `vexa` process only `CAP_NET_ADMIN`, in both its
ambient and bounding capability sets, because nftables netlink updates require it. It does not grant
`CAP_NET_RAW`, `CAP_SYS_ADMIN`, or passwordless sudo. `CAP_NET_ADMIN` is still host-sensitive: keep
the fixed nft binary paths, Vexa-owned `bridge vexa_vm` table boundary, checked transaction, and
systemd sandbox intact, and do not run unreviewed extensions in the web process.

## Customer status links

Firewall access is never added to an existing status link. While creating a new link, an
administrator may explicitly grant the VM firewall scope. A scoped customer can toggle only that
VM's firewall/DDoS switches and manage inbound TCP/UDP destination-port drop rules owned by that
specific status-link token. Rules created by another link for the same VM are hidden and immutable.
Thresholds, packet-check presets, default actions, and administrator/system rules are neither
returned as editable customer policy nor mutable in the public API. The customer cannot:

- enable, disable, or inspect host BCP38 policy;
- change CPU, RAM, disk capacity, bandwidth, traffic quota, IP ownership, or another VM;
- edit the IP blacklist or abuse log; or
- create allow rules, egress rules, CIDR rules, source-port rules or packet-logging rules; or
- change DDoS thresholds, invalid-packet/scan checks, or default ingress/egress actions; or
- bypass a provider maintenance lock.

Revoking the status link immediately removes this access. Audit entries identify the token/session
actor and affected VM without recording credentials.

## Host-only BCP38

BCP38 is a separate administrator-only setting. When enabled, Vexa-VM permits a guest to originate
traffic only from IPv4 and IPv6 addresses assigned to that VM, plus the minimal unspecified and
IPv6 link-local sources required during address configuration. The same TAP-scoped chain pins the
configured Ethernet source MAC, preventing a guest from poisoning the shared bridge FDB by claiming
another tenant's MAC. Enabling the switch validates every managed VM and fails closed if a domain
has no detected host interface or configured MAC. Vexa-created domains receive a persistent
host-side interface target. An imported domain that relies on libvirt's changing
automatic `vnetN` names must be given a persistent target before this policy can be treated as a
durable security boundary.

Because source validation adds work on every forwarded packet, it remains off on low-end nodes until
an administrator chooses to use it. Customers and customer tokens have no API route or scope for
this switch.

## IP blacklist and abuse records

The IP blacklist accepts an exact IPv4/IPv6 address or CIDR, a reason, an optional expiry, and an
enabled state. An active, unexpired entry prevents a matching address from being newly assigned to a
VM. It does not silently disconnect a currently assigned address; operators should first preserve
evidence and decide whether an emergency network action is appropriate.

Abuse records are immutable observations containing the address, optional VM, category, severity,
summary, reporter, provider reference, timestamps, and structured evidence. Resolving a record adds
a resolution and actor; it does not erase the original event. Recording abuse does not automatically
blacklist or suspend a VM.

## Traffic quota enforcement

Traffic usage is RX plus TX for the current accounting period. A null or zero allowance is
unlimited. When usage reaches a positive allowance, Vexa-VM sets the primary libvirt interface link
down in both the live domain and persistent definition. The durable enforcement flag is reconciled
after restart and VM lifecycle operations. Increasing/removing the allowance, or an explicit traffic
reset, restores only a link that Vexa-VM itself disabled.

## Disk protection and lifecycle controls

The deletion lock and snapshot-before-reinstall switches are off by default. A deletion-locked VM
must be explicitly unlocked before its domain or managed disk can be removed. When automatic
pre-reinstall snapshots are enabled, failure to create the snapshot aborts reinstall before the
system disk is replaced.

Administrators can start, gracefully stop, force off, reboot, reset, pause, resume, snapshot,
reinstall, and delete a VM subject to its locks. A maintenance lock keeps status and console access
readable but blocks customer mutations until an administrator clears it.

## Host prerequisites

Enforcement requires nftables with bridge-family support and a libvirt network path visible to the
bridge forward hook. Routed, Open vSwitch, SR-IOV, macvtap, and provider-managed networks require a
deployment-specific validation before relying on this policy. Always verify the effective ruleset
and run an allowed/blocked connectivity test on a disposable VM before enabling protection for a
production guest.
