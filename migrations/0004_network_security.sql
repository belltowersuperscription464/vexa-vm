-- Disabled-by-default VM firewall, DDoS, anti-spoofing, blacklist, and abuse
-- records.  This migration only stores desired/applied state; no host packet
-- filter is enabled merely by upgrading the database.
BEGIN IMMEDIATE;

CREATE TABLE vm_network_security (
    vm_id                         TEXT PRIMARY KEY REFERENCES vms(id) ON DELETE CASCADE,
    firewall_enabled              INTEGER NOT NULL DEFAULT 0 CHECK (firewall_enabled IN (0, 1)),
    ddos_enabled                  INTEGER NOT NULL DEFAULT 0 CHECK (ddos_enabled IN (0, 1)),
    default_ingress_action        TEXT NOT NULL DEFAULT 'accept'
                                  CHECK (default_ingress_action IN ('accept', 'drop', 'reject')),
    default_egress_action         TEXT NOT NULL DEFAULT 'accept'
                                  CHECK (default_egress_action IN ('accept', 'drop', 'reject')),
    syn_rate_limit_pps            INTEGER CHECK (syn_rate_limit_pps IS NULL OR syn_rate_limit_pps > 0),
    udp_rate_limit_pps            INTEGER CHECK (udp_rate_limit_pps IS NULL OR udp_rate_limit_pps > 0),
    icmp_rate_limit_pps           INTEGER CHECK (icmp_rate_limit_pps IS NULL OR icmp_rate_limit_pps > 0),
    new_connection_limit_pps      INTEGER CHECK (new_connection_limit_pps IS NULL OR new_connection_limit_pps > 0),
    concurrent_connection_limit   INTEGER CHECK (concurrent_connection_limit IS NULL OR concurrent_connection_limit > 0),
    port_scan_protection          INTEGER NOT NULL DEFAULT 0 CHECK (port_scan_protection IN (0, 1)),
    drop_invalid_packets          INTEGER NOT NULL DEFAULT 0 CHECK (drop_invalid_packets IN (0, 1)),
    revision                      INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    applied_revision              INTEGER CHECK (applied_revision IS NULL OR applied_revision >= 0),
    last_applied_at               INTEGER,
    last_error                    TEXT,
    created_at                    INTEGER NOT NULL,
    updated_at                    INTEGER NOT NULL,
    CHECK (applied_revision IS NULL OR applied_revision <= revision)
);

CREATE TABLE vm_firewall_rules (
    id                    TEXT PRIMARY KEY,
    vm_id                 TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    priority              INTEGER NOT NULL DEFAULT 1000 CHECK (priority BETWEEN 0 AND 65535),
    direction             TEXT NOT NULL CHECK (direction IN ('ingress', 'egress')),
    action                TEXT NOT NULL CHECK (action IN ('accept', 'drop', 'reject')),
    protocol              TEXT NOT NULL DEFAULT 'any'
                          CHECK (protocol IN ('any', 'tcp', 'udp', 'icmp', 'icmpv6')),
    source_cidr           TEXT,
    destination_cidr      TEXT,
    source_ports_json     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(source_ports_json)),
    destination_ports_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(destination_ports_json)),
    log                   INTEGER NOT NULL DEFAULT 0 CHECK (log IN (0, 1)),
    enabled               INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    description           TEXT NOT NULL DEFAULT '',
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
);

CREATE INDEX idx_vm_firewall_rules_order
    ON vm_firewall_rules(vm_id, enabled, direction, priority, created_at);

-- BCP38 is deliberately a host-only switch, separate from customer-editable
-- VM profiles.  It remains completely disabled until an administrator opts in.
CREATE TABLE hypervisor_network_security (
    singleton_id       INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    bcp38_enabled      INTEGER NOT NULL DEFAULT 0 CHECK (bcp38_enabled IN (0, 1)),
    revision           INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    applied_revision   INTEGER CHECK (applied_revision IS NULL OR applied_revision >= 0),
    last_applied_at    INTEGER,
    last_error         TEXT,
    updated_by         TEXT,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    CHECK (applied_revision IS NULL OR applied_revision <= revision)
);

CREATE TABLE ip_blacklist (
    id                 TEXT PRIMARY KEY,
    cidr               TEXT NOT NULL UNIQUE,
    family             INTEGER NOT NULL CHECK (family IN (4, 6)),
    reason             TEXT NOT NULL,
    source             TEXT NOT NULL DEFAULT 'manual',
    enabled            INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at         INTEGER,
    created_by         TEXT,
    metadata_json      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX idx_ip_blacklist_active
    ON ip_blacklist(enabled, expires_at, family, cidr);

CREATE TABLE ip_abuse_records (
    id                    TEXT PRIMARY KEY,
    address               TEXT NOT NULL,
    family                INTEGER NOT NULL CHECK (family IN (4, 6)),
    vm_id                 TEXT REFERENCES vms(id) ON DELETE SET NULL,
    category              TEXT NOT NULL,
    severity              INTEGER NOT NULL DEFAULT 1 CHECK (severity BETWEEN 1 AND 10),
    summary               TEXT NOT NULL,
    reporter              TEXT,
    provider_reference    TEXT,
    observed_at           INTEGER NOT NULL,
    reported_at           INTEGER NOT NULL,
    resolved_at           INTEGER,
    resolved_by           TEXT,
    resolution            TEXT,
    metadata_json         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    CHECK ((resolved_at IS NULL AND resolved_by IS NULL AND resolution IS NULL)
        OR (resolved_at IS NOT NULL AND resolution IS NOT NULL))
);

CREATE INDEX idx_ip_abuse_address
    ON ip_abuse_records(address, observed_at DESC);
CREATE INDEX idx_ip_abuse_vm
    ON ip_abuse_records(vm_id, observed_at DESC);
CREATE INDEX idx_ip_abuse_unresolved
    ON ip_abuse_records(resolved_at, severity DESC, observed_at DESC);

CREATE TRIGGER create_vm_network_security_profile
AFTER INSERT ON vms
BEGIN
    INSERT INTO vm_network_security(vm_id, created_at, updated_at)
    VALUES (NEW.id, CAST(strftime('%s', 'now') AS INTEGER), CAST(strftime('%s', 'now') AS INTEGER));
END;

INSERT INTO vm_network_security(vm_id, created_at, updated_at)
SELECT id, CAST(strftime('%s', 'now') AS INTEGER), CAST(strftime('%s', 'now') AS INTEGER)
  FROM vms;

INSERT INTO hypervisor_network_security(singleton_id, created_at, updated_at)
VALUES (1, CAST(strftime('%s', 'now') AS INTEGER), CAST(strftime('%s', 'now') AS INTEGER));

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (4, '0004_network_security', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 4;

COMMIT;
