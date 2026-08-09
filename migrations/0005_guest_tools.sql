-- Optional authenticated Vexa Guest Tools state. The per-VM channel secret is
-- stored only as an AES-GCM envelope bound to the VM ID.
BEGIN IMMEDIATE;

CREATE TABLE vm_guest_tools (
    vm_id               TEXT PRIMARY KEY REFERENCES vms(id) ON DELETE CASCADE,
    enabled             INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    platform            TEXT NOT NULL CHECK (platform IN ('linux', 'windows')),
    provisioner         TEXT NOT NULL CHECK (provisioner IN ('cloud_init', 'cloudbase_nocloud')),
    secret_envelope     TEXT NOT NULL,
    desired_version     TEXT NOT NULL,
    installed_version   TEXT,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'ready', 'unavailable', 'error')),
    last_seen_at        INTEGER,
    last_error          TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE INDEX idx_vm_guest_tools_status
    ON vm_guest_tools(enabled, status, last_seen_at);

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (5, '0005_guest_tools', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 5;

COMMIT;
