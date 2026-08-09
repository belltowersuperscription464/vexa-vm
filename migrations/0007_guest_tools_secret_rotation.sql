-- Two-phase Vexa Guest Tools channel-key rotation. A reinstall stages a fresh
-- key without replacing the active key. Only an authenticated post-install
-- handshake may promote the pending generation to the active channel.
BEGIN IMMEDIATE;

ALTER TABLE vm_guest_tools ADD COLUMN pending_secret_envelope TEXT;
ALTER TABLE vm_guest_tools ADD COLUMN pending_platform TEXT
    CHECK (pending_platform IS NULL OR pending_platform IN ('linux', 'windows'));
ALTER TABLE vm_guest_tools ADD COLUMN pending_provisioner TEXT
    CHECK (pending_provisioner IS NULL OR pending_provisioner IN ('cloud_init', 'cloudbase_nocloud'));
ALTER TABLE vm_guest_tools ADD COLUMN pending_desired_version TEXT;
ALTER TABLE vm_guest_tools ADD COLUMN pending_generation TEXT;
ALTER TABLE vm_guest_tools ADD COLUMN pending_installed INTEGER NOT NULL DEFAULT 0
    CHECK (pending_installed IN (0, 1));

CREATE UNIQUE INDEX idx_vm_guest_tools_pending_generation
    ON vm_guest_tools(pending_generation)
    WHERE pending_generation IS NOT NULL;

-- SQLite cannot add a table-level CHECK constraint with ALTER TABLE. These
-- triggers enforce the all-or-none pending tuple for inserts and updates.
CREATE TRIGGER validate_vm_guest_tools_pending_insert
BEFORE INSERT ON vm_guest_tools
WHEN NOT (
    (
        NEW.pending_secret_envelope IS NULL
        AND NEW.pending_platform IS NULL
        AND NEW.pending_provisioner IS NULL
        AND NEW.pending_desired_version IS NULL
        AND NEW.pending_generation IS NULL
        AND NEW.pending_installed = 0
    )
    OR
    (
        NEW.pending_secret_envelope IS NOT NULL
        AND NEW.pending_platform IS NOT NULL
        AND NEW.pending_provisioner IS NOT NULL
        AND NEW.pending_desired_version IS NOT NULL
        AND NEW.pending_generation IS NOT NULL
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid guest-tools pending rotation state');
END;

CREATE TRIGGER validate_vm_guest_tools_pending_update
BEFORE UPDATE OF
    pending_secret_envelope, pending_platform, pending_provisioner,
    pending_desired_version, pending_generation, pending_installed
ON vm_guest_tools
WHEN NOT (
    (
        NEW.pending_secret_envelope IS NULL
        AND NEW.pending_platform IS NULL
        AND NEW.pending_provisioner IS NULL
        AND NEW.pending_desired_version IS NULL
        AND NEW.pending_generation IS NULL
        AND NEW.pending_installed = 0
    )
    OR
    (
        NEW.pending_secret_envelope IS NOT NULL
        AND NEW.pending_platform IS NOT NULL
        AND NEW.pending_provisioner IS NOT NULL
        AND NEW.pending_desired_version IS NOT NULL
        AND NEW.pending_generation IS NOT NULL
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid guest-tools pending rotation state');
END;

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (7, '0007_guest_tools_secret_rotation', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 7;

COMMIT;
