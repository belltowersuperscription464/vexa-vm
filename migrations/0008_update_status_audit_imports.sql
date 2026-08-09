-- Idempotency ledger for importing root-helper terminal update outcomes into
-- the application audit log. The helper remains a single root-owned writer of
-- status JSON; the panel imports each request UUID at most once.
BEGIN IMMEDIATE;

CREATE TABLE update_status_audit_imports (
    request_id   TEXT PRIMARY KEY,
    outcome      TEXT NOT NULL CHECK (
        outcome IN ('succeeded', 'failed', 'rolled_back', 'needs_intervention')
    ),
    imported_at  INTEGER NOT NULL
);

CREATE TRIGGER update_status_audit_imports_no_update
BEFORE UPDATE ON update_status_audit_imports
BEGIN
    SELECT RAISE(ABORT, 'update status imports are append-only');
END;

CREATE TRIGGER update_status_audit_imports_no_delete
BEFORE DELETE ON update_status_audit_imports
BEGIN
    SELECT RAISE(ABORT, 'update status imports are append-only');
END;

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (8, '0008_update_status_audit_imports', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 8;

COMMIT;
