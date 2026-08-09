-- Restrict individual API keys to explicit IPv4/IPv6 client networks.
BEGIN IMMEDIATE;

ALTER TABLE api_keys
    ADD COLUMN ip_allowlist_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(ip_allowlist_json));

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (2, '0002_api_key_ip_allowlist', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 2;

COMMIT;
