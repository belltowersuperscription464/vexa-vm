-- Persist the network link state owned by Vexa-VM's traffic quota enforcer.
-- A row with blocked = 1 means Vexa-VM deliberately disabled the VM link and
-- is therefore responsible for restoring it when the allowance is reset.
BEGIN IMMEDIATE;

CREATE TABLE vm_traffic_enforcement (
    vm_id       TEXT PRIMARY KEY REFERENCES vms(id) ON DELETE CASCADE,
    blocked     INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
    blocked_at  INTEGER,
    last_error  TEXT,
    updated_at  INTEGER NOT NULL,
    CHECK (blocked = 1 OR blocked_at IS NULL)
);

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (3, '0003_vm_traffic_enforcement', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 3;

COMMIT;
