-- Protect addresses inside Vexa-managed pools independently from optional
-- full BCP38 source validation. The guard is enabled by default because IP
-- ownership is an allocation invariant, not a tenant firewall preference.
BEGIN IMMEDIATE;

ALTER TABLE hypervisor_network_security
    ADD COLUMN ip_ownership_guard_enabled INTEGER NOT NULL DEFAULT 1
    CHECK (ip_ownership_guard_enabled IN (0, 1));

UPDATE hypervisor_network_security
   SET revision = revision + 1,
       applied_revision = NULL,
       last_error = NULL,
       updated_at = CAST(strftime('%s', 'now') AS INTEGER)
 WHERE singleton_id = 1;

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (10, '0010_ip_ownership_guard', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 10;

COMMIT;
