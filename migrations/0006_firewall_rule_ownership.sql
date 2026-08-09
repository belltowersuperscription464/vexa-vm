-- Distinguish administrator policy from the narrow port-block rules that a
-- customer may create through an explicitly scoped status link.
BEGIN IMMEDIATE;

ALTER TABLE vm_firewall_rules
    ADD COLUMN owner_type TEXT NOT NULL DEFAULT 'admin'
    CHECK (owner_type IN ('admin', 'customer_token', 'system'));

ALTER TABLE vm_firewall_rules
    ADD COLUMN owner_id TEXT;

CREATE INDEX idx_vm_firewall_rules_owner
    ON vm_firewall_rules(vm_id, owner_type, owner_id);

-- Keep enforcement and every packet-check switch off, but provide conservative
-- editable thresholds so a status-link customer explicitly granted firewall
-- access can enable flood protection without inventing host policy. Thresholds
-- are inert while ddos_enabled remains 0; drop-invalid must still be selected
-- explicitly by an administrator.
UPDATE vm_network_security
   SET syn_rate_limit_pps = COALESCE(syn_rate_limit_pps, 5000),
       udp_rate_limit_pps = COALESCE(udp_rate_limit_pps, 25000),
       icmp_rate_limit_pps = COALESCE(icmp_rate_limit_pps, 1000),
       new_connection_limit_pps = COALESCE(new_connection_limit_pps, 10000)
 WHERE syn_rate_limit_pps IS NULL
    OR udp_rate_limit_pps IS NULL
    OR icmp_rate_limit_pps IS NULL
    OR new_connection_limit_pps IS NULL;

DROP TRIGGER create_vm_network_security_profile;
CREATE TRIGGER create_vm_network_security_profile
AFTER INSERT ON vms
BEGIN
    INSERT INTO vm_network_security(
        vm_id, syn_rate_limit_pps, udp_rate_limit_pps,
        icmp_rate_limit_pps, new_connection_limit_pps,
        drop_invalid_packets, created_at, updated_at
    ) VALUES (
        NEW.id, 5000, 25000, 1000, 10000, 0,
        CAST(strftime('%s', 'now') AS INTEGER),
        CAST(strftime('%s', 'now') AS INTEGER)
    );
END;

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (6, '0006_firewall_rule_ownership', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 6;

COMMIT;
