# Activity and IP-abuse records

Vexa-VM uses the append-only `audit_log` table as its authoritative activity stream. SQLite triggers
reject updates and deletes even from code with a direct database connection. Activity records should
be written for every requested VM operation and its final outcome, including panel, API, customer
status-link, guest-tool, background enforcement and update-helper actions.

Each event records UTC time, actor type and ID, action, resource type and ID, request ID, source IP,
user agent, success/failure and bounded JSON details. The activity service canonicalizes source IPs,
limits untrusted strings and collections, and recursively redacts passwords, passphrases, private
keys, cookies, authorization values, session secrets and tokens. Callers must still avoid adding
secret material to an event in the first place.

Current VM mutation handlers include the sanitized Guest Tools result in their parent VM audit event,
and a direct authenticated health probe records `vm.guest_tools.probe`. Do not claim a separate
per-command event unless both request and completion events are actually emitted. When that dedicated
stream is implemented, use stable names such as `guest_tools.command.request` and
`guest_tools.command.completed` and keep command payloads out of both.

Other stable action names include:

- `vm.create.request`, `vm.create.completed`, `vm.power`, `vm.suspend`, `vm.resume`;
- `vm.password.update`, `vm.ssh_keys.update`, `vm.reinstall.request`;
- `vm.provisioning_seed.retired` after authenticated Guest Tools bootstrap has verified live and
  persistent seed-media detachment and unlinked the generated ISO;
- `vm.firewall.policy.update`, `vm.traffic.blocked`, `vm.traffic.restored`;
- `update.check`, `update.stage`, `update.activation.approve`, and `update.rollback.approve` for
  current web-side update events;
- `update.activate` and `update.rollback` only when a verified privileged-helper outcome has been
  imported exactly once for that helper request, never merely because a request was queued; and
- `ip.abuse.reported`, `ip.abuse.status_changed`.

## Datacenter abuse log

The dedicated `ip_abuse_records` table is the authoritative case/workflow store for provider details,
status and bounded evidence. Each create or status transition also emits an activity event with
`resource_type=ip_abuse`, the canonical IPv4/IPv6 address as resource ID, and the case record UUID.
The activity event is actor/request evidence, not a second copy of the case or its attachments.

Reports start as `open`. Acknowledgement, resolution or false-positive classification changes the
workflow row and appends an `ip.abuse.status_changed` event containing the record UUID. Never replace
the original provider notice. Store large packet captures or attachments in a restricted evidence
store; keep only its bounded metadata/digest in the case record, not in general activity details.

Suggested categories are brute force, command-and-control, copyright, DDoS, fraud, malware,
phishing, port scan, spam, spoofing and other. An abuse report is evidence and does not automatically
disable a VM or blacklist an address. Enforcement requires a separate administrator decision and
must generate its own audit event.

## Retention and export

Protect database backups with the same access controls as the panel because source addresses and
customer activity are personal/operational data. Configure retention according to the operator's
contracts and jurisdiction. Since the live table is append-only, retention should export a signed,
hash-chained archive and rotate through a controlled maintenance operation rather than issuing ad-hoc
deletes from the web application. Exports should use UTC, canonical addresses and stable event IDs so
datacenter abuse cases can be reproduced without exposing guest credentials.
