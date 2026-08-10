# Signed updates

Vexa-VM checks releases only in [`ItzGlace/vexa-vm`](https://github.com/ItzGlace/vexa-vm). An update
check is read-only. It does not install a release, invoke a package manager, restart a service or
change a VM. The updater trusts a release only when all of the following are true:

1. the GitHub release is published (and is not a prerelease unless that channel was explicitly
   enabled);
2. the release has exactly one `vexa-vm-update-manifest.json` and one
   `vexa-vm-update-manifest.json.sig` asset;
3. the detached Ed25519 signature verifies against an operator-pinned public key;
4. the manifest repository, tag, component allowlist, target, URLs, sizes and SHA-256 values pass
   validation; and
5. every downloaded archive is streamed into a unique staging file, bounded to 512 MiB, hashed and
   rehashed before activation.

GitHub HTTPS and a SHA-256 file alone are not release authorization. The signing key is the trust
root. Store trusted public keys in a root-owned file that is readable by the unprivileged panel but
not group/world writable (mode 0644 is suitable because public keys are not secret), or compile them
into a distribution build. Do not make the trust-key setting editable through the normal web panel.

## Manifest format

The signature is calculated over the exact bytes of the manifest. Do not reformat the JSON after
signing. Schema version 1 allows only `vexa-vm`, `qemu` and `libvirt` components:

```json
{
  "schema_version": 1,
  "repository": "ItzGlace/vexa-vm",
  "release": "1.2.3",
  "published_at": 1786000000,
  "components": [
    {
      "component": "vexa-vm",
      "version": "1.2.3",
      "delivery": {
        "type": "signed_archive",
        "url": "https://github.com/ItzGlace/vexa-vm/releases/download/v1.2.3/vexa-vm-x86_64-unknown-linux-gnu.tar.gz",
        "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS",
        "size_bytes": 12345678,
        "target": "x86_64-unknown-linux-gnu"
      }
    },
    {
      "component": "qemu",
      "version": "8.2.2",
      "delivery": {
        "type": "system_packages",
        "manager": "apt",
        "packages": [
          { "name": "qemu-system-x86", "candidate_version": "1:8.2.2+ds-0ubuntu1.4" },
          { "name": "qemu-utils", "candidate_version": "1:8.2.2+ds-0ubuntu1.4" }
        ]
      }
    }
  ]
}
```

Vexa-VM is the only component allowed to use a release archive. QEMU and libvirt remain owned by the
host distribution and may use only their short package allowlists. A manifest cannot provide a shell
command, script, repository URL or arbitrary package name. Kernel/KVM upgrades are intentionally not
offered by this mechanism because they require a coordinated host reboot and distribution-specific
dependency handling.

The detached signature asset is a small JSON envelope:

```json
{
  "algorithm": "ed25519",
  "key_id": "vexa-release-2026-01",
  "signature": "BASE64_OF_THE_RAW_64_BYTE_SIGNATURE"
}
```

Keep the Ed25519 private key offline or in a dedicated signing service. A publisher can use OpenSSL
3 to sign the final manifest bytes:

```bash
openssl genpkey -algorithm ED25519 -out vexa-release-signing-key.pem
openssl pkeyutl -sign -rawin -inkey vexa-release-signing-key.pem \
  -in vexa-vm-update-manifest.json -out manifest.signature.bin
base64 -w0 manifest.signature.bin
```

The updater accepts the raw 32-byte Ed25519 public key encoded with standard base64. Extract and pin
that value through a reviewed release-engineering process; publish its key ID and fingerprint through
a separate trusted channel. Rotate by shipping an overlap period in which both old and new public
keys are trusted, then remove the old key after all supported nodes have updated.

The bundled release workflow expects the PEM private key encoded as base64 in the protected GitHub
Actions secret `VEXA_RELEASE_PRIVATE_KEY_B64`, and the public key label in the repository variable
`VEXA_RELEASE_KEY_ID`. Protect the release environment with required reviewers. The workflow refuses
to publish a tagged release when either value is missing or malformed, generates the manifest from
the built archive, signs it, and uploads the manifest and signature beside the release archive.

Release builds pin the declared Rust 1.75.0 toolchain, use `npm ci` with `package-lock.json`, require
committed root and Guest Tools Cargo lockfiles, and pass `--locked` to every Rust test/build command.
Do not weaken those checks to make a tag pass; regenerate and review lockfile changes in a normal
source change first. The Windows Guest Tools executable is integrity-protected as a member of the
signed Vexa archive. This workflow does not Authenticode-sign it and does not provide a Windows
virtio-serial driver.

## Panel and helper contract

The web application may check, verify and stage an update as the unprivileged `vexa` account. It then
creates an `ActivationRequest` bound to the manifest digest, selected components, administrator ID and
maintenance acknowledgement. Creating the request performs no update.

Approval is deliberately short lived. An activation or rollback approval expires after 15 minutes,
is bound to the exact manifest/snapshot digest, and carries no caller-selected executable, command,
package repository or download URL. The panel serializes it as a schema-versioned
`PrivilegedUpdateRequest` in a dedicated request spool using a UUID filename and mode 0600.
`PrivilegedRequestSpool::fixed()` writes through a unique mode-0600 temporary inode, syncs its
contents, publishes it with a no-clobber hard link, removes the temporary name, and syncs the spool
directory so the helper never observes a partial, silently replaced, or non-durable approval.

The HTTP approval boundary is `POST /api/v1/updates/rollback`. It requires an authenticated
`super_admin` browser session, the `updates:write` scope, CSRF, and this closed request object:

```json
{
  "expected_activation_id": "00000000-0000-0000-0000-000000000000",
  "expected_previous_release": "1.2.2",
  "maintenance_impact_accepted": true
}
```

The server compares those two expected values with the current rollback point exposed by
`GET /api/v1/updates`. It derives the snapshot path and SHA-256, manifest SHA-256, release and exact
component set from validated root-owned helper status. None of those authority-bearing values is
accepted from the browser. A mismatch or stale point is rejected instead of silently rolling back a
different activation.

`vexa-update-helper validate <request-uuid>` is the read-only root-side validator. It opens the
request with `O_NOFOLLOW`, bounds it to 2 MiB, confines it to the configured request directory, loads
a root-owned non-writable trust store, and independently verifies the Ed25519 manifest and every
staged digest. For rollback it additionally loads a root-owned activation receipt and accepts only
the exact snapshot, prior release and component set recorded by that receipt. Its output is a typed
JSON plan and performs no mutation. `execute <request-uuid>` runs that same independent validation and
then executes only its typed plan. `dispatch` consumes queued UUID requests for the systemd watcher;
it does not accept a command, path, URL, package or component on the command line. Release archives
are capped at 512 MiB and application rollback snapshots at 16 GiB; VM disks are never included in an
application rollback snapshot.

The trust store format is:

```json
{
  "schema_version": 1,
  "keys": [
    {
      "key_id": "vexa-release-2026-01",
      "public_key_base64": "BASE64_OF_RAW_32_BYTE_ED25519_PUBLIC_KEY"
    }
  ]
}
```

Install it at `/etc/vexa-vm/update-trusted-keys.json`, owned by root and not group/world writable.
The helper uses these fixed roots:

- requests: `/var/lib/vexa-vm/updates/requests`;
- staged signed archives: `/var/lib/vexa-vm/updates/staged`;
- root-owned rollback snapshots: `/var/lib/vexa-vm/updates/rollback`; and
- root-owned activation receipts: `/var/lib/vexa-vm/update-helper/receipts`.

Consumed requests move through root-owned `updates/processing` into `updates/processed`. A request
UUID is never replayed after a crash: an interrupted processing inode is quarantined, and the admin
must create a fresh, short-lived approval. Durable, non-secret status is published as root-owned JSON
under `updates/status/<request-uuid>.json`; a successful application activation includes the
non-secret receipt fields needed to offer a later rollback, but never exposes the root-only snapshot
path. Raw APT output stays in the system journal.

`GET /api/v1/updates` exposes these records newest first as `executor_statuses`, mirrors the first as
`latest_executor_status`, and separately exposes the current `rollback_point` or `null`. Each record
contains bounded operation, release, phase/progress, outcome, timestamps, package-change summary,
rollback summary and sanitized message fields. The web process rechecks the fixed UUID filename,
root ownership, non-writable mode, no-follow regular-file semantics, JSON schema, digest formats and
state invariants before using a record. It never exposes a snapshot path or activation receipt.

These paths are compiled into the helper. Its only accepted caller-controlled argument is the UUID
of a request in the fixed spool. Paths, repositories, package names and commands cannot be supplied
on its command line or copied from an HTTP request.

The packaged root-owned executor has a fixed input schema and no general-purpose command field. It:

- lock updates so only one activation or rollback can run;
- reject requests whose component, package, path or digest differs from the approved request;
- freezes the unprivileged staged archive into a new root-only inode while verifying its signed size
  and SHA-256, then re-verifies that private inode before and after extraction and accepts only
  bounded regular files/directories under the release allowlist;
- refuses to activate an application archive missing any required panel template, compiled static
  asset, noVNC runtime, Vexa Guest Tools binary, service unit, license, or release metadata file;
- take a SQLite online backup and create an immutable rollback point before migration;
- install Vexa-VM into a versioned directory, atomically switch the active release, restart the
  service and require `/healthz` plus `/readyz` to pass;
- simulates APT first and rejects removals, dependency changes, non-allowlisted packages or versions
  that differ from the signed plan; it then verifies every installed version;
- automatically restores the prior application symlink and matching SQLite snapshot when the new
  application fails restart/readiness or its receipt cannot be recorded; and
- writes a terminal structured outcome (`succeeded`, `failed`, `rolled_back`, or
  `needs_intervention`) before archiving the consumed request.

The release packager requires the application and Guest Tools workspace versions to match, rejects
links and special filesystem entries, and emits a portable checksum file whose entry names only the
archive basename. Extraction assigns executable mode only to the two host binaries and the Linux
Guest Tools binary; every active or rollback release is rechecked against the same complete runtime
file contract before it can be selected. Bundled Guest Tools use the running application's compile-
time version, so switching the atomic `current` release cannot leave an old environment-file version
pin behind; `VEXA_GUEST_TOOLS_VERSION` is reserved for administrator-managed external artifacts. A
request-archive bookkeeping fault preserves the already recorded host outcome and rollback point,
leaving the processing inode for the next dispatcher run instead of misreporting a successful
activation as failed.

Distribution package transactions are not automatically downgraded: maintainer scripts and package
dependencies make that unsafe to generalize. If an application activation follows successful signed
package upgrades and the application fails, the application/database are restored but the package
upgrades remain installed; the durable status explicitly says so. A failed or interrupted APT/dpkg
operation is `needs_intervention` and must be repaired by an operator before another update. A
package-only operation creates a temporary consistency snapshot while it runs, but retains neither
that snapshot nor an unusable activation receipt after the unchanged application passes readiness.

## Privileged executor availability

The web process must consider activation available only when
`/run/vexa-vm/update-executor.ready` is a root-owned, non-group/world-writable regular file containing
this bounded schema:

```json
{"schema_version":1,"ready":true,"helper_schema":1}
```

`vexa-update-executor-ready.service` creates the marker only after checking the trust store,
versioned active release, loopback application bind address, fixed APT/dpkg/systemctl binaries and
private directory ownership. It removes the marker when stopped. `vexa-update-dispatch.path` wakes a
root oneshot service when the unprivileged panel atomically publishes a request; the dispatcher also
runs once at boot to cover requests queued while the watcher was offline. Missing/invalid trust,
failed self-checks or a non-loopback `VEXA_BIND` leave activation disabled rather than falling back to
an unsafe mechanism. Both helper units forbid privilege gain and changes to the host clock or
hostname; the readiness probe additionally denies namespace creation. The dispatcher retains only
the host filesystem, device and network access required by fixed APT/dpkg/systemd operations and
loopback readiness checks.

Before switching the application symlink, the executor writes a root-only recovery journal beside
the SQLite snapshot. Explicit rollback operations also record their pre-rollback release/database.
If the helper is killed after mutation begins, the next dispatch does not replay the approval: it
uses the journal either to recognize a fully receipted, healthy activation or to restore the release
and database active before the interrupted operation, then quarantines the consumed request. A crash
during a package-only transaction cannot be generically undone and is reported as
`needs_intervention`.

The confirmation page must show the signer key ID, current and target versions, exact components,
package changes, VM impact and rollback availability. It must default every component to unselected.
All check, stage, approve, activate, health-check and rollback transitions must be append-only audit
events. The helper should return structured progress rather than raw command output.

## Rollback

An activation receipt identifies the prior versioned install, pre-update database backup and the
digest of its rollback snapshot. Rollback needs a second explicit administrator acknowledgement bound
to that activation ID and prior release. The helper revalidates the snapshot before switching it.

Database migrations are forward-only. A binary rollback is safe only when the older application can
read the migrated schema; otherwise restore the matching pre-update database and application release
together. VM disks are outside the application-release snapshot and must never be deleted or rolled
back by the panel updater.

The active layout is `/opt/vexa-vm/releases/<semver>` with an atomic
`/opt/vexa-vm/current` symlink. Do not edit a release directory in place. A rollback request is a new
15-minute administrator approval bound to the original receipt; the executor verifies the snapshot
again, saves a pre-rollback recovery copy, and restores the release that was active before the
rollback request if the requested older release fails readiness.

After a successful explicit rollback, the helper first atomically publishes its successful terminal
status as the commit record. It then removes the consumed root-only activation receipt and clears the
original activation status's public rollback point. If either metadata cleanup write fails after the
release and database were already restored, the helper logs and reports an operator warning without
falsely relabeling the completed rollback as failed; the newer rollback status hides the stale offer
and the active-release check still rejects its replay. If the commit record itself cannot be written,
the helper restores the release and database active before the request while the original receipt is
still intact. Approval appends `update.rollback.approve`; a separate status importer appends the
terminal `update.rollback` result exactly once per helper request, so queued approval is never
presented as execution success.
