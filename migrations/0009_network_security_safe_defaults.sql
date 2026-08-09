-- Correct the pre-release firewall ownership preset so upgrades are as safe as
-- fresh installs. Only untouched revision-zero profiles are normalized; any
-- profile an administrator has edited keeps its chosen packet-check state.
BEGIN IMMEDIATE;

UPDATE vm_network_security
   SET drop_invalid_packets = 0,
       updated_at = CAST(strftime('%s', 'now') AS INTEGER)
 WHERE revision = 0
   AND firewall_enabled = 0
   AND ddos_enabled = 0
   AND port_scan_protection = 0
   AND drop_invalid_packets = 1;

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
VALUES (9, '0009_network_security_safe_defaults', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 9;

COMMIT;
