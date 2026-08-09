-- Vexa VM initial schema. All timestamps are Unix seconds in UTC.
-- Secret material is never stored directly: password_envelope contains an
-- AES-256-GCM envelope and every bearer credential column contains SHA-256.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version       INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    applied_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id                TEXT PRIMARY KEY,
    username          TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash     TEXT NOT NULL,
    role              TEXT NOT NULL DEFAULT 'admin'
                      CHECK (role IN ('super_admin', 'admin', 'read_only')),
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    last_login_at     INTEGER
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash        BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    csrf_hash         BLOB NOT NULL UNIQUE CHECK (length(csrf_hash) = 32),
    admin_id          TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    source_ip         TEXT,
    user_agent        TEXT,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    last_seen_at      INTEGER NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin
    ON admin_sessions(admin_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry
    ON admin_sessions(expires_at);

CREATE TABLE IF NOT EXISTS api_keys (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    token_hash        BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    prefix            TEXT NOT NULL,
    permissions_json  TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(permissions_json)),
    created_by        TEXT REFERENCES admins(id) ON DELETE SET NULL,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER,
    last_used_at      INTEGER,
    revoked_at        INTEGER,
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_active
    ON api_keys(token_hash, expires_at, revoked_at);

CREATE TABLE IF NOT EXISTS settings (
    key               TEXT PRIMARY KEY,
    value_json        TEXT NOT NULL CHECK (json_valid(value_json)),
    encrypted         INTEGER NOT NULL DEFAULT 0 CHECK (encrypted IN (0, 1)),
    updated_by        TEXT REFERENCES admins(id) ON DELETE SET NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS iso_images (
    id                    TEXT PRIMARY KEY,
    slug                  TEXT NOT NULL COLLATE NOCASE UNIQUE,
    name                  TEXT NOT NULL,
    version               TEXT,
    os_family             TEXT NOT NULL DEFAULT '',
    architecture          TEXT NOT NULL DEFAULT 'x86_64',
    install_mode          TEXT NOT NULL DEFAULT 'manual'
                          CHECK (install_mode IN ('cloud_init', 'automatic', 'manual')),
    source_url            TEXT,
    local_path            TEXT,
    checksum_sha256       TEXT,
    size_bytes            INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    supports_guest_agent  INTEGER NOT NULL DEFAULT 0 CHECK (supports_guest_agent IN (0, 1)),
    supports_cloud_init   INTEGER NOT NULL DEFAULT 0 CHECK (supports_cloud_init IN (0, 1)),
    uefi                  INTEGER NOT NULL DEFAULT 0 CHECK (uefi IN (0, 1)),
    enabled               INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    metadata_json         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    CHECK (source_url IS NOT NULL OR local_path IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_iso_images_enabled
    ON iso_images(enabled, os_family, architecture);

CREATE TABLE IF NOT EXISTS vms (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL COLLATE NOCASE UNIQUE,
    hostname              TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    os_family             TEXT NOT NULL DEFAULT '',
    iso_id                TEXT REFERENCES iso_images(id) ON DELETE SET NULL,
    state                 TEXT NOT NULL DEFAULT 'creating'
                          CHECK (state IN ('creating', 'running', 'stopped', 'paused',
                                           'reinstalling', 'migrating', 'error', 'unknown')),
    desired_state         TEXT NOT NULL DEFAULT 'stopped'
                          CHECK (desired_state IN ('creating', 'running', 'stopped', 'paused',
                                                   'reinstalling', 'migrating', 'error', 'unknown')),
    vcpus                 INTEGER NOT NULL CHECK (vcpus > 0),
    memory_mib            INTEGER NOT NULL CHECK (memory_mib >= 256),
    disk_gib              INTEGER NOT NULL CHECK (disk_gib >= 1),
    disk_format           TEXT NOT NULL DEFAULT 'qcow2',
    firmware              TEXT NOT NULL DEFAULT 'bios' CHECK (firmware IN ('bios', 'uefi')),
    machine_type          TEXT,
    bridge                TEXT,
    tap_name              TEXT UNIQUE,
    mac_address           TEXT UNIQUE,
    network_limit_mbps    INTEGER CHECK (network_limit_mbps IS NULL OR network_limit_mbps > 0),
    traffic_limit_bytes   INTEGER CHECK (traffic_limit_bytes IS NULL OR traffic_limit_bytes >= 0),
    traffic_used_bytes    INTEGER NOT NULL DEFAULT 0 CHECK (traffic_used_bytes >= 0),
    root_username         TEXT NOT NULL DEFAULT 'root',
    password_envelope     TEXT,
    password_updated_at   INTEGER,
    guest_agent           INTEGER NOT NULL DEFAULT 0 CHECK (guest_agent IN (0, 1)),
    autostart             INTEGER NOT NULL DEFAULT 0 CHECK (autostart IN (0, 1)),
    timezone              TEXT,
    libvirt_uuid          TEXT UNIQUE,
    vnc_display           INTEGER,
    metadata_json         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vms_state ON vms(state, desired_state);
CREATE INDEX IF NOT EXISTS idx_vms_iso ON vms(iso_id);

CREATE TABLE IF NOT EXISTS vm_disks (
    id                TEXT PRIMARY KEY,
    vm_id             TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    path              TEXT NOT NULL UNIQUE,
    format            TEXT NOT NULL DEFAULT 'qcow2',
    bus               TEXT NOT NULL DEFAULT 'virtio',
    size_bytes        INTEGER NOT NULL CHECK (size_bytes > 0),
    boot_order        INTEGER,
    read_only         INTEGER NOT NULL DEFAULT 0 CHECK (read_only IN (0, 1)),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    UNIQUE(vm_id, name)
);

CREATE TABLE IF NOT EXISTS ip_pools (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL COLLATE NOCASE UNIQUE,
    cidr              TEXT NOT NULL UNIQUE,
    family            INTEGER NOT NULL CHECK (family IN (4, 6)),
    scope             TEXT NOT NULL CHECK (scope IN ('public', 'private')),
    gateway           TEXT,
    bridge            TEXT,
    vlan_id           INTEGER CHECK (vlan_id IS NULL OR vlan_id BETWEEN 1 AND 4094),
    mtu               INTEGER NOT NULL DEFAULT 1500 CHECK (mtu BETWEEN 576 AND 9216),
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_addresses (
    id                TEXT PRIMARY KEY,
    pool_id           TEXT REFERENCES ip_pools(id) ON DELETE SET NULL,
    address           TEXT NOT NULL UNIQUE,
    family            INTEGER NOT NULL CHECK (family IN (4, 6)),
    prefix_length     INTEGER NOT NULL,
    scope             TEXT NOT NULL CHECK (scope IN ('public', 'private')),
    status            TEXT NOT NULL DEFAULT 'free'
                      CHECK (status IN ('free', 'reserved', 'used', 'main')),
    gateway           TEXT,
    assigned_vm_id    TEXT REFERENCES vms(id) ON DELETE SET NULL,
    primary_for_vm    INTEGER NOT NULL DEFAULT 0 CHECK (primary_for_vm IN (0, 1)),
    reverse_dns       TEXT,
    metadata_json     TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    CHECK ((family = 4 AND prefix_length BETWEEN 0 AND 32)
        OR (family = 6 AND prefix_length BETWEEN 0 AND 128)),
    CHECK ((status = 'used' AND assigned_vm_id IS NOT NULL)
        OR (status <> 'used' AND assigned_vm_id IS NULL)),
    CHECK (primary_for_vm = 0 OR assigned_vm_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_ip_addresses_pool_status
    ON ip_addresses(pool_id, family, scope, status, address);
CREATE INDEX IF NOT EXISTS idx_ip_addresses_vm
    ON ip_addresses(assigned_vm_id, primary_for_vm);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_addresses_one_primary_per_family
    ON ip_addresses(assigned_vm_id, family)
    WHERE assigned_vm_id IS NOT NULL AND primary_for_vm = 1;

CREATE TRIGGER IF NOT EXISTS release_ip_addresses_before_vm_delete
BEFORE DELETE ON vms
BEGIN
    UPDATE ip_addresses
       SET status = 'free', assigned_vm_id = NULL, primary_for_vm = 0,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER)
     WHERE assigned_vm_id = OLD.id;
END;

CREATE TABLE IF NOT EXISTS dns_servers (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    address           TEXT NOT NULL,
    family            INTEGER NOT NULL CHECK (family IN (4, 6)),
    priority          INTEGER NOT NULL DEFAULT 0,
    pool_id           TEXT REFERENCES ip_pools(id) ON DELETE CASCADE,
    vm_id             TEXT REFERENCES vms(id) ON DELETE CASCADE,
    CHECK (pool_id IS NULL OR vm_id IS NULL),
    UNIQUE(address, pool_id, vm_id)
);

CREATE INDEX IF NOT EXISTS idx_dns_servers_scope
    ON dns_servers(vm_id, pool_id, priority);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_servers_unique_scope
    ON dns_servers(address, COALESCE(pool_id, ''), COALESCE(vm_id, ''));

CREATE TABLE IF NOT EXISTS customer_tokens (
    id                TEXT PRIMARY KEY,
    vm_id             TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    token_hash        BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    session_hash      BLOB UNIQUE CHECK (session_hash IS NULL OR length(session_hash) = 32),
    scopes_json       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(scopes_json)),
    bound_ip          TEXT,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    consumed_at       INTEGER,
    session_expires_at INTEGER,
    last_used_at      INTEGER,
    revoked_at        INTEGER,
    CHECK (expires_at > created_at),
    CHECK ((session_hash IS NULL AND session_expires_at IS NULL)
        OR (session_hash IS NOT NULL AND session_expires_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_customer_tokens_active
    ON customer_tokens(token_hash, expires_at, consumed_at, revoked_at);
CREATE INDEX IF NOT EXISTS idx_customer_sessions_active
    ON customer_tokens(session_hash, session_expires_at, revoked_at);

-- A one-time VNC link token is exchanged for a separately random, hashed
-- browser-session cookie. Both are bound to the same absolute ten-minute TTL.
CREATE TABLE IF NOT EXISTS vnc_tokens (
    id                    TEXT PRIMARY KEY,
    vm_id                 TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    token_hash            BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    session_hash          BLOB UNIQUE CHECK (session_hash IS NULL OR length(session_hash) = 32),
    bound_ip              TEXT,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    consumed_at           INTEGER,
    session_expires_at    INTEGER,
    revoked_at            INTEGER,
    CHECK (expires_at > created_at),
    CHECK ((session_hash IS NULL AND session_expires_at IS NULL)
        OR (session_hash IS NOT NULL AND session_expires_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_vnc_tokens_link_active
    ON vnc_tokens(token_hash, expires_at, consumed_at, revoked_at);
CREATE INDEX IF NOT EXISTS idx_vnc_tokens_session_active
    ON vnc_tokens(session_hash, session_expires_at, revoked_at);

CREATE TABLE IF NOT EXISTS host_inventory (
    singleton_id            INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    hostname                TEXT NOT NULL,
    architecture            TEXT NOT NULL,
    kernel                  TEXT NOT NULL,
    cpu_model               TEXT,
    cpu_cores               INTEGER NOT NULL CHECK (cpu_cores > 0),
    memory_total_bytes      INTEGER NOT NULL CHECK (memory_total_bytes >= 0),
    root_disk_total_bytes   INTEGER NOT NULL CHECK (root_disk_total_bytes >= 0),
    listen_port             INTEGER NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    public_interface        TEXT,
    detected_addresses_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(detected_addresses_json)),
    metadata_json           TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    updated_at              INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS host_metrics (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    sampled_at            INTEGER NOT NULL,
    cpu_percent           REAL NOT NULL DEFAULT 0,
    load_one              REAL NOT NULL DEFAULT 0,
    load_five             REAL NOT NULL DEFAULT 0,
    load_fifteen          REAL NOT NULL DEFAULT 0,
    memory_total_bytes    INTEGER NOT NULL DEFAULT 0,
    memory_used_bytes     INTEGER NOT NULL DEFAULT 0,
    swap_total_bytes      INTEGER NOT NULL DEFAULT 0,
    swap_used_bytes       INTEGER NOT NULL DEFAULT 0,
    disk_total_bytes      INTEGER NOT NULL DEFAULT 0,
    disk_used_bytes       INTEGER NOT NULL DEFAULT 0,
    disk_read_bps         REAL NOT NULL DEFAULT 0,
    disk_write_bps        REAL NOT NULL DEFAULT 0,
    network_rx_bytes      INTEGER NOT NULL DEFAULT 0,
    network_tx_bytes      INTEGER NOT NULL DEFAULT 0,
    network_rx_bps        REAL NOT NULL DEFAULT 0,
    network_tx_bps        REAL NOT NULL DEFAULT 0,
    uptime_seconds        INTEGER NOT NULL DEFAULT 0,
    metadata_json         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_metrics_sampled_at
    ON host_metrics(sampled_at);

CREATE TABLE IF NOT EXISTS vm_metrics (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id                 TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    sampled_at            INTEGER NOT NULL,
    cpu_percent           REAL NOT NULL DEFAULT 0,
    memory_used_bytes     INTEGER NOT NULL DEFAULT 0,
    memory_total_bytes    INTEGER NOT NULL DEFAULT 0,
    disk_read_bytes       INTEGER NOT NULL DEFAULT 0,
    disk_write_bytes      INTEGER NOT NULL DEFAULT 0,
    disk_read_bps         REAL NOT NULL DEFAULT 0,
    disk_write_bps        REAL NOT NULL DEFAULT 0,
    network_rx_bytes      INTEGER NOT NULL DEFAULT 0,
    network_tx_bytes      INTEGER NOT NULL DEFAULT 0,
    network_rx_bps        REAL NOT NULL DEFAULT 0,
    network_tx_bps        REAL NOT NULL DEFAULT 0,
    traffic_used_bytes    INTEGER NOT NULL DEFAULT 0,
    traffic_limit_bytes   INTEGER,
    metadata_json         TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(vm_id, sampled_at)
);

CREATE INDEX IF NOT EXISTS idx_vm_metrics_vm_sample
    ON vm_metrics(vm_id, sampled_at DESC);

CREATE TABLE IF NOT EXISTS jobs (
    id                  TEXT PRIMARY KEY,
    kind                TEXT NOT NULL,
    vm_id               TEXT REFERENCES vms(id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    payload_json        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json)),
    result_json         TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
    error               TEXT,
    progress_percent    REAL NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
    idempotency_key     TEXT,
    attempts            INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts        INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
    run_after           INTEGER NOT NULL,
    locked_by           TEXT,
    locked_at           INTEGER,
    actor_type          TEXT,
    actor_id            TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    finished_at         INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency
    ON jobs(idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_jobs_claim
    ON jobs(status, run_after, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_vm
    ON jobs(vm_id, created_at DESC);

CREATE TABLE IF NOT EXISTS snapshots (
    id                TEXT PRIMARY KEY,
    vm_id             TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    state             TEXT NOT NULL DEFAULT 'creating'
                      CHECK (state IN ('creating', 'ready', 'reverting', 'deleting', 'error')),
    disk_path         TEXT,
    size_bytes        INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    memory_included   INTEGER NOT NULL DEFAULT 0 CHECK (memory_included IN (0, 1)),
    metadata_json     TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    completed_at      INTEGER,
    UNIQUE(vm_id, name)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_vm
    ON snapshots(vm_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at       INTEGER NOT NULL,
    actor_type        TEXT NOT NULL,
    actor_id          TEXT,
    action            TEXT NOT NULL,
    resource_type     TEXT NOT NULL,
    resource_id       TEXT,
    request_id        TEXT,
    source_ip         TEXT,
    user_agent        TEXT,
    success           INTEGER NOT NULL CHECK (success IN (0, 1)),
    details_json      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_occurred
    ON audit_log(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource
    ON audit_log(resource_type, resource_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor
    ON audit_log(actor_type, actor_id, occurred_at DESC);

-- Audit records are append-only even for code holding a direct DB connection.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (1, '0001_init', CAST(strftime('%s', 'now') AS INTEGER));

PRAGMA user_version = 1;

COMMIT;
