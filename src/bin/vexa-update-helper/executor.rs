use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use reqwest::redirect::Policy;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{process::Command, time::Instant};
use uuid::Uuid;
use vexa_vm::services::updater::{
    load_fixed_trusted_release_keys, validate_privileged_request, ApprovedComponentAction,
    HelperActivationReceipt, PackageManager, PrivilegedUpdateRequest, SystemPackage,
    UpdateComponent, ValidatedHelperPlan, MAX_PRIVILEGED_REQUEST_BYTES, UPDATE_RECEIPT_ROOT,
    UPDATE_REQUEST_ROOT, UPDATE_ROLLBACK_ROOT, UPDATE_STAGING_ROOT,
};

use crate::{
    current_unix_time, read_confined_file, read_fixed_file,
    update_archive::{extract_release, REQUIRED_RELEASE_FILES},
    update_status::{
        PackageChangeStatus, PublicRollbackPointStatus, StatusWriter, UpdateOutcome,
    },
};

const INSTALL_ROOT: &str = "/opt/vexa-vm";
const RELEASES_ROOT: &str = "/opt/vexa-vm/releases";
const CURRENT_LINK: &str = "/opt/vexa-vm/current";
const DATABASE_PATH: &str = "/var/lib/vexa-vm/vexa.db";
const UPDATES_ROOT: &str = "/var/lib/vexa-vm/updates";
const PROCESSING_ROOT: &str = "/var/lib/vexa-vm/updates/processing";
const PROCESSED_ROOT: &str = "/var/lib/vexa-vm/updates/processed";
const HELPER_STATE_ROOT: &str = "/var/lib/vexa-vm/update-helper";
const UPDATE_LOCK_PATH: &str = "/run/lock/vexa-vm-update.lock";
pub const READY_MARKER: &str = "/run/vexa-vm/update-executor.ready";
const ENVIRONMENT_PATH: &str = "/etc/vexa-vm/vexa-vm.env";
const SYSTEMD_UNIT_ROOT: &str = "/etc/systemd/system";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const APT_GET: &str = "/usr/bin/apt-get";
const DPKG_QUERY: &str = "/usr/bin/dpkg-query";
const SERVICE: &str = "vexa-vm.service";
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_ENVIRONMENT_BYTES: u64 = 128 * 1024;
const MAX_DATABASE_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_DISPATCH_REQUESTS: usize = 128;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(90);
const HEALTH_WINDOW: Duration = Duration::from_secs(90);

pub async fn dispatch() -> Result<()> {
    require_root()?;
    let root = Path::new(UPDATE_REQUEST_ROOT);
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut request_ids = Vec::new();
    for entry in entries.take(MAX_DISPATCH_REQUESTS) {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(stem) = file_name.strip_suffix(".json") else {
            continue;
        };
        if let Ok(request_id) = Uuid::parse_str(stem) {
            request_ids.push(request_id);
        }
    }
    request_ids.sort_unstable();
    for request_id in request_ids {
        if let Err(error) = execute(request_id).await {
            eprintln!("vexa update request {request_id} failed: {error}");
        }
    }
    Ok(())
}

pub fn mark_ready() -> Result<()> {
    require_root()?;
    // Never leave a stale availability assertion behind when a self-check
    // fails partway through refresh.
    mark_unready()?;
    prepare_private_directories()?;
    load_fixed_trusted_release_keys().context("release trust store is not ready")?;
    current_release()?;
    validate_fixed_executable(SYSTEMCTL)?;
    validate_fixed_executable(APT_GET)?;
    validate_fixed_executable(DPKG_QUERY)?;
    read_loopback_bind_address()?;

    let runtime_root = Path::new(READY_MARKER)
        .parent()
        .ok_or_else(|| anyhow!("ready marker has no parent"))?;
    ensure_root_directory(runtime_root, 0o755)?;
    let marker = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "ready": true,
        "helper_schema": 1,
    }))?;
    let temporary = runtime_root.join(format!(".update-executor.{}.tmp", Uuid::new_v4()));
    let cleanup = TemporaryFile::new(temporary.clone());
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    file.write_all(&marker)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, READY_MARKER)?;
    drop(cleanup);
    sync_directory(runtime_root)?;
    Ok(())
}

pub fn mark_unready() -> Result<()> {
    require_root()?;
    let marker = Path::new(READY_MARKER);
    match std::fs::symlink_metadata(marker) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("refusing to remove an unsafe update-executor marker");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 {
                    bail!("update-executor marker is not root-owned");
                }
            }
            std::fs::remove_file(marker)?;
            if let Some(parent) = marker.parent() {
                sync_directory(parent)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub async fn execute(request_id: Uuid) -> Result<()> {
    require_root()?;
    let _lock = UpdateLock::acquire()?;
    prepare_private_directories()?;

    if let Some(existing) = StatusWriter::existing(request_id)? {
        if existing.completed_at.is_some() {
            reconcile_completed_request(request_id)?;
            bail!("update request {request_id} was already consumed");
        }
    }
    let mut status = StatusWriter::start(request_id, current_unix_time()?)?;
    if interrupted_request_exists(request_id) {
        let recovery = recover_interrupted_activation(request_id, &mut status).await;
        let recovery_error = match recovery {
            Ok(InterruptedRecovery::Committed) => {
                status.finish(
                    UpdateOutcome::Succeeded,
                    "recovered_committed",
                    "A committed activation was recovered after the helper was interrupted",
                    current_unix_time()?,
                )?;
                None
            }
            Ok(InterruptedRecovery::RolledBack) => {
                status.finish(
                    UpdateOutcome::RolledBack,
                    "recovered_rollback",
                    "An interrupted application operation was restored to its prior application and database",
                    current_unix_time()?,
                )?;
                None
            }
            Ok(InterruptedRecovery::NoApplicationMutation) => {
                status.finish(
                    UpdateOutcome::NeedsIntervention,
                    "interrupted",
                    "An interrupted non-application update was quarantined; inspect package-manager state",
                    current_unix_time()?,
                )?;
                None
            }
            Err(error) => {
                status.finish(
                    UpdateOutcome::NeedsIntervention,
                    "interrupted_recovery_failed",
                    "An interrupted activation could not be recovered automatically",
                    current_unix_time()?,
                )?;
                Some(error)
            }
        };
        // Publish the terminal recovery outcome before removing the consumed
        // request. If status persistence fails, the processing inode remains
        // available for the next root-helper reconciliation attempt.
        cleanup_interrupted_artifacts(request_id)?;
        quarantine_interrupted_request(
            request_id,
            &Path::new(PROCESSING_ROOT).join(format!("{request_id}.json")),
            &Path::new(PROCESSING_ROOT).join(format!(".{request_id}.incoming")),
        )?;
        if let Some(error) = recovery_error {
            return Err(error);
        }
        bail!("interrupted update request {request_id} was reconciled and will not be replayed");
    }
    let request_bytes = match consume_request(request_id) {
        Ok(bytes) => bytes,
        Err(error) => {
            status.finish(
                UpdateOutcome::Failed,
                "request_rejected",
                "The request could not be consumed exactly once",
                current_unix_time()?,
            )?;
            return Err(error);
        }
    };

    let execution = execute_consumed(request_id, &request_bytes, &mut status).await;
    if let Err(error) = &execution {
        if status.snapshot().completed_at.is_none() {
            status.finish(
                UpdateOutcome::Failed,
                "failed",
                "The update failed before activation completed",
                current_unix_time()?,
            )?;
        }
        eprintln!("vexa update request {request_id}: {error}");
    }

    if let Err(error) = archive_consumed_request(request_id) {
        // Archival is exactly-once bookkeeping, not the host mutation's
        // outcome. Preserve the already-persisted terminal result (including
        // a successful activation's rollback point) so the public status
        // remains schema-valid and does not falsely report a completed update
        // as failed. The processing inode remains for reconciliation on the
        // next dispatcher run.
        let outcome = status.snapshot().outcome.clone();
        status.finish(
            outcome,
            "archival_pending",
            "The operation ended with the recorded outcome, but its consumed request still requires archival reconciliation",
            current_unix_time()?,
        )?;
        return Err(error);
    }
    execution
}

fn interrupted_request_exists(request_id: Uuid) -> bool {
    Path::new(PROCESSING_ROOT)
        .join(format!("{request_id}.json"))
        .exists()
        || Path::new(PROCESSING_ROOT)
            .join(format!(".{request_id}.incoming"))
            .exists()
}

fn reconcile_completed_request(request_id: Uuid) -> Result<()> {
    cleanup_interrupted_artifacts(request_id)?;
    let processing = Path::new(PROCESSING_ROOT).join(format!("{request_id}.json"));
    let processed = Path::new(PROCESSED_ROOT).join(format!("{request_id}.json"));
    if processing.exists() && !processed.exists() {
        std::fs::rename(&processing, &processed)?;
        sync_directory(Path::new(PROCESSING_ROOT))?;
        sync_directory(Path::new(PROCESSED_ROOT))?;
    } else if processing.exists() {
        quarantine_replay_file(&processing, request_id, "completed-processing")?;
    }
    let incoming = Path::new(PROCESSING_ROOT).join(format!(".{request_id}.incoming"));
    if incoming.exists() {
        quarantine_replay_file(&incoming, request_id, "completed-incoming")?;
    }
    let replay = Path::new(UPDATE_REQUEST_ROOT).join(format!("{request_id}.json"));
    if replay.exists() {
        quarantine_replay_file(&replay, request_id, "replayed")?;
    }
    Ok(())
}

fn cleanup_interrupted_artifacts(request_id: Uuid) -> Result<()> {
    let private_archive =
        Path::new(PROCESSING_ROOT).join(format!("{request_id}.release-archive"));
    match std::fs::symlink_metadata(&private_archive) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("interrupted private archive is not a regular file");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 {
                    bail!("interrupted private archive is not root-owned");
                }
            }
            std::fs::remove_file(&private_archive)?;
            sync_directory(Path::new(PROCESSING_ROOT))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let partial = Path::new(RELEASES_ROOT).join(format!(".partial-{request_id}"));
    match std::fs::symlink_metadata(&partial) {
        Ok(metadata) => {
            if !is_direct_partial_release(&partial)
                || !metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
            {
                bail!("interrupted release extraction path is unsafe");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 {
                    bail!("interrupted release extraction is not root-owned");
                }
            }
            std::fs::remove_dir_all(&partial)?;
            sync_directory(Path::new(RELEASES_ROOT))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn quarantine_replay_file(source: &Path, request_id: Uuid, suffix: &str) -> Result<()> {
    let target = Path::new(PROCESSED_ROOT).join(format!("{request_id}.{suffix}"));
    if target.exists() {
        let metadata = std::fs::symlink_metadata(source)?;
        if !metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
            bail!("replayed request path is not a file");
        }
        std::fs::remove_file(source)?;
    } else {
        std::fs::rename(source, &target)?;
    }
    if let Some(parent) = source.parent() {
        sync_directory(parent)?;
    }
    sync_directory(Path::new(PROCESSED_ROOT))?;
    Ok(())
}

async fn execute_consumed(
    request_id: Uuid,
    request_bytes: &[u8],
    status: &mut StatusWriter,
) -> Result<()> {
    let request: PrivilegedUpdateRequest = serde_json::from_slice(request_bytes)
        .context("privileged update request is invalid")?;
    let trusted_keys =
        load_fixed_trusted_release_keys().context("release trust store could not be loaded")?;
    let receipt = load_rollback_receipt(&request)?;
    let plan = validate_privileged_request(
        &request,
        &trusted_keys,
        Path::new(UPDATE_STAGING_ROOT),
        Path::new(UPDATE_ROLLBACK_ROOT),
        receipt.as_ref(),
        current_unix_time()?,
    )
    .await
    .context("privileged update request failed independent validation")?;

    match plan {
        ValidatedHelperPlan::Activate {
            activation_id,
            release,
            manifest_sha256,
            actions,
            ..
        } => {
            if Uuid::parse_str(&activation_id)? != request_id {
                bail!("activation ID does not match the consumed request UUID");
            }
            status.set_operation("activate", &release, current_unix_time()?)?;
            execute_activation(
                request_id,
                &release,
                &manifest_sha256,
                actions,
                status,
            )
            .await
        }
        ValidatedHelperPlan::Rollback {
            request_id: plan_request_id,
            activation_id,
            release,
            restore_release,
            snapshot_path,
            snapshot_sha256,
            snapshot_size_bytes,
            components,
            ..
        } => {
            if Uuid::parse_str(&plan_request_id)? != request_id {
                bail!("rollback ID does not match the consumed request UUID");
            }
            status.set_operation("rollback", &restore_release, current_unix_time()?)?;
            execute_rollback(
                request_id,
                &activation_id,
                &release,
                &restore_release,
                &snapshot_path,
                &snapshot_sha256,
                snapshot_size_bytes,
                &components,
                status,
            )
            .await
        }
    }
}

fn consume_request(request_id: Uuid) -> Result<Vec<u8>> {
    let source = Path::new(UPDATE_REQUEST_ROOT).join(format!("{request_id}.json"));
    let processing = Path::new(PROCESSING_ROOT).join(format!("{request_id}.json"));
    let incoming = Path::new(PROCESSING_ROOT).join(format!(".{request_id}.incoming"));
    let processed = Path::new(PROCESSED_ROOT).join(format!("{request_id}.json"));

    if processed.exists() {
        bail!("update request was already processed");
    }
    if processing.exists() || incoming.exists() {
        quarantine_interrupted_request(request_id, &processing, &incoming)?;
        bail!("an interrupted execution was detected; the request will not be replayed");
    }
    std::fs::rename(&source, &incoming).context("update request could not be atomically consumed")?;
    sync_directory(Path::new(UPDATE_REQUEST_ROOT))?;
    sync_directory(Path::new(PROCESSING_ROOT))?;

    let bytes = read_fixed_file(&incoming, MAX_PRIVILEGED_REQUEST_BYTES, false)
        .context("consumed update request could not be read")?;
    write_new_private_file(&processing, &bytes)?;
    std::fs::remove_file(&incoming)?;
    sync_directory(Path::new(PROCESSING_ROOT))?;
    Ok(bytes)
}

fn archive_consumed_request(request_id: Uuid) -> Result<()> {
    let processing = Path::new(PROCESSING_ROOT).join(format!("{request_id}.json"));
    let processed = Path::new(PROCESSED_ROOT).join(format!("{request_id}.json"));
    if processed.exists() {
        bail!("processed request record already exists");
    }
    std::fs::rename(&processing, &processed)?;
    sync_directory(Path::new(PROCESSING_ROOT))?;
    sync_directory(Path::new(PROCESSED_ROOT))?;
    Ok(())
}

fn quarantine_interrupted_request(
    request_id: Uuid,
    processing: &Path,
    incoming: &Path,
) -> Result<()> {
    let mut quarantined = false;
    for (source, suffix) in [(processing, "processing"), (incoming, "incoming")] {
        if !source.exists() {
            continue;
        }
        let processed = Path::new(PROCESSED_ROOT)
            .join(format!("{request_id}.interrupted-{suffix}"));
        if processed.exists() {
            let metadata = std::fs::symlink_metadata(source)?;
            if !metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
                bail!("interrupted request path is not a file");
            }
            std::fs::remove_file(source)?;
        } else {
            std::fs::rename(source, processed)?;
        }
        quarantined = true;
    }
    if !quarantined {
        bail!("interrupted request disappeared before quarantine");
    }
    sync_directory(Path::new(PROCESSING_ROOT))?;
    sync_directory(Path::new(PROCESSED_ROOT))?;
    Ok(())
}

fn load_rollback_receipt(
    request: &PrivilegedUpdateRequest,
) -> Result<Option<HelperActivationReceipt>> {
    let PrivilegedUpdateRequest::Rollback { rollback, .. } = request else {
        return Ok(None);
    };
    let activation_id = Uuid::parse_str(&rollback.activation_id)
        .context("rollback activation ID must be a UUID")?;
    let receipt_path = Path::new(UPDATE_RECEIPT_ROOT).join(format!("{activation_id}.json"));
    let bytes = read_confined_file(
        Path::new(UPDATE_RECEIPT_ROOT),
        &receipt_path,
        MAX_RECEIPT_BYTES,
        true,
    )?;
    Ok(Some(
        serde_json::from_slice(&bytes).context("activation receipt is invalid")?,
    ))
}

fn prepare_private_directories() -> Result<()> {
    ensure_root_directory(Path::new(UPDATES_ROOT), 0o755)?;
    validate_exchange_directory(Path::new(UPDATE_REQUEST_ROOT))?;
    validate_exchange_directory(Path::new(UPDATE_STAGING_ROOT))?;
    ensure_root_directory(Path::new(PROCESSING_ROOT), 0o700)?;
    ensure_root_directory(Path::new(PROCESSED_ROOT), 0o700)?;
    ensure_root_directory(Path::new(UPDATE_RECEIPT_ROOT), 0o700)?;
    ensure_root_directory(Path::new(UPDATE_ROLLBACK_ROOT), 0o700)?;
    ensure_root_directory(Path::new(HELPER_STATE_ROOT), 0o700)?;
    ensure_root_directory(Path::new(RELEASES_ROOT), 0o755)?;
    Ok(())
}

fn validate_exchange_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("{} is not a safe exchange directory", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            bail!("{} must not be group/world writable", path.display());
        }
    }
    Ok(())
}

fn ensure_root_directory(path: &Path, mode: u32) -> Result<()> {
    std::fs::create_dir_all(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("{} is not a safe directory", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 {
            bail!("{} must be root-owned", path.display());
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn require_root() -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata("/proc/self")?.uid() != 0 {
            bail!("vexa-update-helper execute/dispatch must run as root");
        }
    }
    Ok(())
}

struct UpdateLock(File);

impl UpdateLock {
    fn acquire() -> Result<Self> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(0x0002_0000);
        }
        let file = options.open(UPDATE_LOCK_PATH)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                bail!("update lock file must be root-owned and non-writable by other users");
            }
            const LOCK_EX: i32 = 2;
            const LOCK_NB: i32 = 4;
            // SAFETY: flock receives a live file descriptor and fixed flags.
            if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
                bail!("another Vexa-VM update operation is running");
            }
        }
        Ok(Self(file))
    }
}

#[cfg(unix)]
extern "C" {
    fn flock(file_descriptor: i32, operation: i32) -> i32;
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[derive(Clone)]
struct ActiveRelease {
    version: String,
    canonical_path: PathBuf,
}

struct DatabaseSnapshot {
    path: PathBuf,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationRecoveryJournal {
    schema_version: u32,
    request_id: String,
    previous_release: String,
    target_release: String,
    manifest_sha256: String,
    snapshot_path: PathBuf,
    snapshot_sha256: String,
    snapshot_size_bytes: u64,
    packages_changed: bool,
    created_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RollbackRecoveryJournal {
    schema_version: u32,
    request_id: String,
    recover_release: String,
    requested_release: String,
    snapshot_path: PathBuf,
    snapshot_sha256: String,
    snapshot_size_bytes: u64,
    created_at: i64,
}

enum InterruptedRecovery {
    Committed,
    RolledBack,
    NoApplicationMutation,
}

fn recovery_journal_path(request_id: Uuid) -> PathBuf {
    Path::new(UPDATE_ROLLBACK_ROOT).join(format!("{request_id}.activation.json"))
}

fn rollback_recovery_journal_path(request_id: Uuid) -> PathBuf {
    Path::new(UPDATE_ROLLBACK_ROOT).join(format!("{request_id}.rollback.json"))
}

fn write_recovery_journal(journal: &ActivationRecoveryJournal) -> Result<()> {
    let request_id = Uuid::parse_str(&journal.request_id)?;
    let final_path = recovery_journal_path(request_id);
    if final_path.exists() {
        bail!("activation recovery journal already exists");
    }
    let bytes = serde_json::to_vec_pretty(journal)?;
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES as usize {
        bail!("activation recovery journal is outside its size limit");
    }
    let temporary = Path::new(UPDATE_ROLLBACK_ROOT)
        .join(format!(".{request_id}.activation.{}.tmp", Uuid::new_v4()));
    let cleanup = TemporaryFile::new(temporary.clone());
    write_new_private_file(&temporary, &bytes)?;
    std::fs::hard_link(&temporary, &final_path)?;
    std::fs::remove_file(&temporary)?;
    drop(cleanup);
    sync_directory(Path::new(UPDATE_ROLLBACK_ROOT))?;
    Ok(())
}

fn write_rollback_recovery_journal(journal: &RollbackRecoveryJournal) -> Result<()> {
    let request_id = Uuid::parse_str(&journal.request_id)?;
    let final_path = rollback_recovery_journal_path(request_id);
    if final_path.exists() {
        bail!("rollback recovery journal already exists");
    }
    let bytes = serde_json::to_vec_pretty(journal)?;
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES as usize {
        bail!("rollback recovery journal is outside its size limit");
    }
    let temporary = Path::new(UPDATE_ROLLBACK_ROOT)
        .join(format!(".{request_id}.rollback.{}.tmp", Uuid::new_v4()));
    let cleanup = TemporaryFile::new(temporary.clone());
    write_new_private_file(&temporary, &bytes)?;
    std::fs::hard_link(&temporary, &final_path)?;
    std::fs::remove_file(&temporary)?;
    drop(cleanup);
    sync_directory(Path::new(UPDATE_ROLLBACK_ROOT))?;
    Ok(())
}

async fn recover_interrupted_activation(
    request_id: Uuid,
    status: &mut StatusWriter,
) -> Result<InterruptedRecovery> {
    let journal_path = recovery_journal_path(request_id);
    let Some(bytes) = read_optional_confined_file(
        Path::new(UPDATE_ROLLBACK_ROOT),
        &journal_path,
        MAX_RECEIPT_BYTES,
        true,
    )? else {
        return recover_interrupted_rollback(request_id, status).await;
    };
    let journal: ActivationRecoveryJournal = serde_json::from_slice(&bytes)
        .context("activation recovery journal is invalid")?;
    validate_recovery_journal(request_id, &journal)?;

    status.set_operation("recover", &journal.target_release, current_unix_time()?)?;
    let recovery_message = if journal.packages_changed {
        "Reconciling an interrupted application activation; completed distribution package changes will remain installed"
    } else {
        "Reconciling a previously interrupted application activation"
    };
    status.phase(
        "interrupted_recovery",
        35,
        recovery_message,
        current_unix_time()?,
    )?;
    if activation_receipt_matches(&journal)? {
        if let Ok(active) = current_release() {
            if active.version == normalized_release_name(&journal.target_release)? {
                if wait_for_health(Some(&journal.target_release)).await.is_ok() {
                    install_release_units(&active.canonical_path)?;
                    reload_systemd().await?;
                    mark_ready()?;
                    // Recovery has now proven that the original activation
                    // committed. Publish the terminal record as that
                    // activation (rather than as an in-progress recovery),
                    // because public rollback points are valid only on a
                    // successful activation status.
                    status.set_operation(
                        "activate",
                        &journal.target_release,
                        current_unix_time()?,
                    )?;
                    status.set_rollback(
                        true,
                        false,
                        false,
                        Some(journal.previous_release.clone()),
                        Some(journal.snapshot_sha256.clone()),
                        current_unix_time()?,
                    )?;
                    status.stage_rollback_point(
                        public_rollback_point(
                            request_id,
                            &journal.target_release,
                            &journal.previous_release,
                            &journal.manifest_sha256,
                            &journal.snapshot_sha256,
                            journal.snapshot_size_bytes,
                        ),
                    )?;
                    return Ok(InterruptedRecovery::Committed);
                }
            }
        }
    }

    let previous = release_path(&journal.previous_release)?;
    status.set_rollback(
        true,
        true,
        false,
        Some(journal.previous_release.clone()),
        Some(journal.snapshot_sha256.clone()),
        current_unix_time()?,
    )?;
    stop_service().await?;
    install_release_units(&previous)?;
    reload_systemd().await?;
    switch_current_release(&previous)?;
    restore_database(&journal.snapshot_path)?;
    start_service().await?;
    wait_for_health(Some(&journal.previous_release)).await?;
    mark_ready()?;
    remove_activation_receipt(request_id)?;
    status.clear_rollback_point(current_unix_time()?)?;
    status.set_rollback(
        true,
        true,
        true,
        Some(journal.previous_release.clone()),
        Some(journal.snapshot_sha256.clone()),
        current_unix_time()?,
    )?;
    Ok(InterruptedRecovery::RolledBack)
}

async fn recover_interrupted_rollback(
    request_id: Uuid,
    status: &mut StatusWriter,
) -> Result<InterruptedRecovery> {
    let journal_path = rollback_recovery_journal_path(request_id);
    let Some(bytes) = read_optional_confined_file(
        Path::new(UPDATE_ROLLBACK_ROOT),
        &journal_path,
        MAX_RECEIPT_BYTES,
        true,
    )? else {
        return Ok(InterruptedRecovery::NoApplicationMutation);
    };
    let journal: RollbackRecoveryJournal = serde_json::from_slice(&bytes)
        .context("rollback recovery journal is invalid")?;
    validate_rollback_recovery_journal(request_id, &journal)?;
    status.set_operation("recover_rollback", &journal.recover_release, current_unix_time()?)?;
    status.phase(
        "interrupted_rollback_recovery",
        35,
        "Restoring the application and database active before an interrupted rollback request",
        current_unix_time()?,
    )?;
    status.set_rollback(
        true,
        true,
        false,
        Some(journal.recover_release.clone()),
        Some(journal.snapshot_sha256.clone()),
        current_unix_time()?,
    )?;
    let recover_release = release_path(&journal.recover_release)?;
    stop_service().await?;
    install_release_units(&recover_release)?;
    reload_systemd().await?;
    switch_current_release(&recover_release)?;
    restore_database(&journal.snapshot_path)?;
    start_service().await?;
    wait_for_health(Some(&journal.recover_release)).await?;
    mark_ready()?;
    status.set_rollback(
        true,
        true,
        true,
        Some(journal.recover_release),
        Some(journal.snapshot_sha256),
        current_unix_time()?,
    )?;
    Ok(InterruptedRecovery::RolledBack)
}

fn validate_recovery_journal(
    request_id: Uuid,
    journal: &ActivationRecoveryJournal,
) -> Result<()> {
    if journal.schema_version != 1
        || Uuid::parse_str(&journal.request_id)? != request_id
        || journal.created_at <= 0
    {
        bail!("activation recovery journal identity is invalid");
    }
    normalized_release_name(&journal.previous_release)?;
    normalized_release_name(&journal.target_release)?;
    let expected_snapshot =
        Path::new(UPDATE_ROLLBACK_ROOT).join(format!("{request_id}.sqlite3"));
    if journal.snapshot_path != expected_snapshot
        || journal.snapshot_size_bytes == 0
        || journal.snapshot_size_bytes > MAX_DATABASE_SNAPSHOT_BYTES
        || journal.snapshot_sha256.len() != 64
        || journal.manifest_sha256.len() != 64
        || !journal
            .snapshot_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !journal
            .manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("activation recovery journal snapshot is invalid");
    }
    let (size, sha256) = hash_regular_file(
        &journal.snapshot_path,
        MAX_DATABASE_SNAPSHOT_BYTES,
    )?;
    if size != journal.snapshot_size_bytes || sha256 != journal.snapshot_sha256 {
        bail!("activation recovery snapshot no longer matches its journal");
    }
    release_path(&journal.previous_release)?;
    Ok(())
}

fn validate_rollback_recovery_journal(
    request_id: Uuid,
    journal: &RollbackRecoveryJournal,
) -> Result<()> {
    if journal.schema_version != 1
        || Uuid::parse_str(&journal.request_id)? != request_id
        || journal.created_at <= 0
    {
        bail!("rollback recovery journal identity is invalid");
    }
    normalized_release_name(&journal.recover_release)?;
    normalized_release_name(&journal.requested_release)?;
    let expected_snapshot = Path::new(UPDATE_ROLLBACK_ROOT)
        .join(format!("{request_id}.pre-rollback.sqlite3"));
    if journal.snapshot_path != expected_snapshot
        || journal.snapshot_size_bytes == 0
        || journal.snapshot_size_bytes > MAX_DATABASE_SNAPSHOT_BYTES
        || journal.snapshot_sha256.len() != 64
        || !journal
            .snapshot_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("rollback recovery journal snapshot is invalid");
    }
    let (size, sha256) = hash_regular_file(
        &journal.snapshot_path,
        MAX_DATABASE_SNAPSHOT_BYTES,
    )?;
    if size != journal.snapshot_size_bytes || sha256 != journal.snapshot_sha256 {
        bail!("rollback recovery snapshot no longer matches its journal");
    }
    release_path(&journal.recover_release)?;
    Ok(())
}

fn activation_receipt_matches(journal: &ActivationRecoveryJournal) -> Result<bool> {
    let request_id = Uuid::parse_str(&journal.request_id)?;
    let path = Path::new(UPDATE_RECEIPT_ROOT).join(format!("{request_id}.json"));
    let Some(bytes) = read_optional_confined_file(
        Path::new(UPDATE_RECEIPT_ROOT),
        &path,
        MAX_RECEIPT_BYTES,
        true,
    )? else {
        return Ok(false);
    };
    let receipt: HelperActivationReceipt =
        serde_json::from_slice(&bytes).context("activation receipt is invalid")?;
    Ok(receipt.schema_version == 1
        && receipt.activation_id == journal.request_id
        && normalized_release_name(&receipt.release)?
            == normalized_release_name(&journal.target_release)?
        && normalized_release_name(&receipt.previous_release)?
            == normalized_release_name(&journal.previous_release)?
        && receipt.manifest_sha256 == journal.manifest_sha256
        && receipt.snapshot_path == journal.snapshot_path
        && receipt.snapshot_sha256 == journal.snapshot_sha256
        && receipt.snapshot_size_bytes == journal.snapshot_size_bytes
        && receipt.components == BTreeSet::from([UpdateComponent::VexaVm]))
}

fn release_path(version: &str) -> Result<PathBuf> {
    let version = normalized_release_name(version)?;
    let releases_root = std::fs::canonicalize(RELEASES_ROOT)?;
    let path = std::fs::canonicalize(Path::new(RELEASES_ROOT).join(version))?;
    if path.parent() != Some(releases_root.as_path()) {
        bail!("versioned release escaped the releases root");
    }
    require_release_payload(&path)?;
    Ok(path)
}

fn public_rollback_point(
    activation_id: Uuid,
    release: &str,
    previous_release: &str,
    manifest_sha256: &str,
    snapshot_sha256: &str,
    snapshot_size_bytes: u64,
) -> PublicRollbackPointStatus {
    PublicRollbackPointStatus {
        activation_id: activation_id.to_string(),
        release: release.to_owned(),
        previous_release: previous_release.to_owned(),
        manifest_sha256: manifest_sha256.to_owned(),
        snapshot_sha256: snapshot_sha256.to_owned(),
        snapshot_size_bytes,
        components: vec![UpdateComponent::VexaVm.as_str().to_owned()],
    }
}

fn read_optional_confined_file(
    root: &Path,
    path: &Path,
    maximum: u64,
    require_root_owned: bool,
) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => read_confined_file(root, path, maximum, require_root_owned).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

struct ApplicationAction {
    version: String,
    staged_path: PathBuf,
    sha256: String,
    size_bytes: u64,
}

async fn execute_activation(
    request_id: Uuid,
    release: &str,
    manifest_sha256: &str,
    actions: Vec<ApprovedComponentAction>,
    status: &mut StatusWriter,
) -> Result<()> {
    let active = current_release()?;
    let expected_release = normalized_release_name(release)?;
    let mut application = None;
    let mut package_actions = Vec::new();
    for action in actions {
        match action {
            ApprovedComponentAction::InstallStagedArchive {
                component,
                version,
                staged_path,
                sha256,
                size_bytes,
            } => {
                if component != UpdateComponent::VexaVm || application.is_some() {
                    bail!("activation contains an unsupported archive action");
                }
                if normalized_release_name(&version)? != expected_release {
                    bail!("application archive version does not match the release");
                }
                application = Some(ApplicationAction {
                    version,
                    staged_path,
                    sha256,
                    size_bytes,
                });
            }
            ApprovedComponentAction::UpgradeSystemPackages {
                component,
                version: _,
                manager,
                packages,
            } => {
                if manager != PackageManager::Apt {
                    bail!("activation contains an unsupported package manager");
                }
                validate_package_action(component, &packages)?;
                package_actions.push((component, packages));
            }
        }
    }

    let prepared_release = if let Some(application) = &application {
        if active.version == normalized_release_name(&application.version)? {
            bail!("the selected application release is already active");
        }
        status.phase(
            "extracting",
            25,
            "Verifying and extracting the signed application archive",
            current_unix_time()?,
        )?;
        Some(prepare_application_release(request_id, application)?)
    } else {
        None
    };

    if !package_actions.is_empty() {
        status.phase(
            "packages",
            45,
            "Applying exact signed operating-system package versions",
            current_unix_time()?,
        )?;
        if let Err(error) = apply_package_actions(&package_actions, status).await {
            status.finish(
                UpdateOutcome::NeedsIntervention,
                "package_update_failed",
                "A distribution package update failed; inspect dpkg/APT before retrying",
                current_unix_time()?,
            )?;
            return Err(error);
        }
    }

    status.phase(
        "database_backup",
        60,
        "Creating a consistent pre-activation SQLite backup",
        current_unix_time()?,
    )?;
    let snapshot_path =
        Path::new(UPDATE_ROLLBACK_ROOT).join(format!("{request_id}.sqlite3"));
    let snapshot = match backup_database(&snapshot_path) {
        Ok(snapshot) => snapshot,
        Err(error) if !package_actions.is_empty() => {
            status.finish(
                UpdateOutcome::NeedsIntervention,
                "post_package_backup_failed",
                "Package changes completed, but the application database backup failed",
                current_unix_time()?,
            )?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let application_rollback = application.as_ref().map(|_| {
        (
            active.version.clone(),
            snapshot.sha256.clone(),
        )
    });
    status.set_rollback(
        application_rollback.is_some(),
        false,
        false,
        application_rollback
            .as_ref()
            .map(|(previous_release, _)| previous_release.clone()),
        application_rollback
            .as_ref()
            .map(|(_, snapshot_sha256)| snapshot_sha256.clone()),
        current_unix_time()?,
    )?;

    let application_activation = prepared_release.is_some();
    if let Some(prepared_release) = prepared_release {
        status.phase(
            "activating",
            70,
            "Atomically switching the active Vexa-VM release",
            current_unix_time()?,
        )?;
        let journal = ActivationRecoveryJournal {
            schema_version: 1,
            request_id: request_id.to_string(),
            previous_release: active.version.clone(),
            target_release: expected_release.clone(),
            manifest_sha256: manifest_sha256.to_owned(),
            snapshot_path: snapshot.path.clone(),
            snapshot_sha256: snapshot.sha256.clone(),
            snapshot_size_bytes: snapshot.size_bytes,
            packages_changed: !package_actions.is_empty(),
            created_at: current_unix_time()?,
        };
        if let Err(error) = write_recovery_journal(&journal) {
            if !package_actions.is_empty() {
                status.finish(
                    UpdateOutcome::NeedsIntervention,
                    "post_package_journal_failed",
                    "Package changes completed, but the application recovery journal could not be created",
                    current_unix_time()?,
                )?;
            }
            return Err(error);
        }
        let activation = async {
            stop_service().await?;
            install_release_units(&prepared_release)?;
            reload_systemd().await?;
            switch_current_release(&prepared_release)?;
            start_service().await?;
            wait_for_health(Some(&expected_release)).await?;
            mark_ready()
        }
        .await;
        if let Err(error) = activation {
            return automatic_application_rollback(
                request_id,
                &active,
                &snapshot,
                !package_actions.is_empty(),
                status,
                error,
            )
            .await;
        }

        let receipt_time = match current_unix_time() {
            Ok(now) => now,
            Err(error) => {
                return automatic_application_rollback(
                    request_id,
                    &active,
                    &snapshot,
                    !package_actions.is_empty(),
                    status,
                    error,
                )
                .await;
            }
        };
        if let Err(error) = status.phase(
            "recording_receipt",
            94,
            "Recording the immutable application rollback point",
            receipt_time,
        ) {
            return automatic_application_rollback(
                request_id,
                &active,
                &snapshot,
                !package_actions.is_empty(),
                status,
                error,
            )
            .await;
        }
        let receipt = HelperActivationReceipt {
            schema_version: 1,
            activation_id: request_id.to_string(),
            release: release.to_owned(),
            previous_release: active.version.clone(),
            manifest_sha256: manifest_sha256.to_owned(),
            snapshot_path: snapshot.path.clone(),
            snapshot_sha256: snapshot.sha256.clone(),
            snapshot_size_bytes: snapshot.size_bytes,
            components: BTreeSet::from([UpdateComponent::VexaVm]),
            completed_at: receipt_time,
        };
        if let Err(error) = write_activation_receipt(&receipt) {
            return automatic_application_rollback(
                request_id,
                &active,
                &snapshot,
                !package_actions.is_empty(),
                status,
                error,
            )
            .await;
        }
        if let Err(error) = status.stage_rollback_point(
            public_rollback_point(
                request_id,
                release,
                &active.version,
                manifest_sha256,
                &snapshot.sha256,
                snapshot.size_bytes,
            ),
        ) {
            return automatic_application_rollback(
                request_id,
                &active,
                &snapshot,
                !package_actions.is_empty(),
                status,
                error,
            )
            .await;
        }
    } else {
        status.phase(
            "restarting",
            75,
            "Restarting Vexa-VM after the approved package changes",
            current_unix_time()?,
        )?;
        let health = match restart_service().await {
            Ok(()) => wait_for_health(None).await,
            Err(error) => Err(error),
        };
        if let Err(error) = health.and_then(|_| mark_ready()) {
            status.finish(
                UpdateOutcome::NeedsIntervention,
                "post_package_health_failed",
                "Package changes completed, but panel readiness did not recover",
                current_unix_time()?,
            )?;
            return Err(error);
        }
        // Package transactions cannot be generically rolled back, so do not
        // retain an unusable activation receipt or an ever-growing orphaned
        // database snapshot after the restarted panel is healthy.
        if let Err(error) = remove_database_snapshot(&snapshot.path) {
            status.finish(
                UpdateOutcome::NeedsIntervention,
                "package_snapshot_cleanup_failed",
                "Package changes completed, but their temporary database snapshot requires operator cleanup",
                current_unix_time()?,
            )?;
            return Err(error);
        }
        status.set_rollback(false, false, false, None, None, current_unix_time()?)?;
    }

    let completion_time = match current_unix_time() {
        Ok(now) => now,
        Err(error) if application_activation => {
            return automatic_application_rollback(
                request_id,
                &active,
                &snapshot,
                !package_actions.is_empty(),
                status,
                error,
            )
            .await;
        }
        Err(error) => return Err(error),
    };
    if let Err(error) = status.finish(
        UpdateOutcome::Succeeded,
        "completed",
        "The approved update completed and readiness checks passed",
        completion_time,
    ) {
        if application_activation {
            return automatic_application_rollback(
                request_id,
                &active,
                &snapshot,
                !package_actions.is_empty(),
                status,
                error,
            )
            .await;
        }
        return Err(error);
    }
    Ok(())
}

fn prepare_application_release(request_id: Uuid, action: &ApplicationAction) -> Result<PathBuf> {
    let version = normalized_release_name(&action.version)?;
    let releases_root = Path::new(RELEASES_ROOT);
    let destination = releases_root.join(&version);
    if std::fs::symlink_metadata(&destination).is_ok() {
        bail!("application release {version} already exists");
    }
    let partial = releases_root.join(format!(".partial-{request_id}"));
    if std::fs::symlink_metadata(&partial).is_ok() {
        bail!("application extraction directory already exists");
    }
    // The staging inode is owned by the unprivileged panel and can be changed
    // in place even when opened with O_NOFOLLOW. Freeze the verified bytes in
    // a new root-only inode before parsing any archive metadata.
    let private_archive = copy_archive_to_private_inode(request_id, action)?;
    let archive_cleanup = TemporaryFile::new(private_archive.clone());
    let mut cleanup = TemporaryDirectory::new(partial.clone());
    let extracted = extract_release(
        &private_archive,
        &partial,
        action.size_bytes,
        &action.sha256,
    )?;
    if normalized_release_name(&extracted.version)? != version {
        bail!("archive VERSION does not match the approved component version");
    }
    std::fs::rename(&partial, &destination)?;
    cleanup.retain();
    sync_directory(releases_root)?;
    drop(archive_cleanup);
    Ok(destination)
}

fn copy_archive_to_private_inode(
    request_id: Uuid,
    action: &ApplicationAction,
) -> Result<PathBuf> {
    let destination =
        Path::new(PROCESSING_ROOT).join(format!("{request_id}.release-archive"));
    if std::fs::symlink_metadata(&destination).is_ok() {
        bail!("private release archive already exists");
    }
    let mut cleanup = TemporaryFile::new(destination.clone());
    let mut source = open_regular_nofollow(&action.staged_path)?;
    let source_metadata = source.metadata()?;
    if source_metadata.len() != action.size_bytes {
        bail!("staged release archive changed before it could be frozen");
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut target = options.open(&destination)?;
    let mut digest = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("release archive size overflow"))?;
        if copied > action.size_bytes {
            bail!("staged release archive grew while it was being frozen");
        }
        digest.update(&buffer[..read]);
        target.write_all(&buffer[..read])?;
    }
    if copied != action.size_bytes
        || format!("{:x}", digest.finalize()) != action.sha256
    {
        bail!("staged release archive changed while it was being frozen");
    }
    target.sync_all()?;
    drop(target);
    sync_directory(Path::new(PROCESSING_ROOT))?;
    cleanup.retain();
    Ok(destination)
}

async fn automatic_application_rollback(
    request_id: Uuid,
    previous: &ActiveRelease,
    snapshot: &DatabaseSnapshot,
    packages_changed: bool,
    status: &mut StatusWriter,
    activation_error: anyhow::Error,
) -> Result<()> {
    let mut reporting_errors = Vec::new();
    // Status persistence must never prevent the actual recovery mutation.
    // A broken/pre-epoch host clock must not leave the failed release active;
    // zero is used only for best-effort recovery reporting in that case.
    let status_now = || current_unix_time().unwrap_or_default();
    if let Err(error) = status.phase(
        "automatic_rollback",
        90,
        "The new application failed readiness checks; restoring the prior release",
        status_now(),
    ) {
        reporting_errors.push(format!("could not record rollback phase: {error}"));
    }
    if let Err(error) = status.set_rollback(
        true,
        true,
        false,
        Some(previous.version.clone()),
        Some(snapshot.sha256.clone()),
        status_now(),
    ) {
        reporting_errors.push(format!("could not record rollback start: {error}"));
    }
    let rollback = async {
        stop_service().await?;
        install_release_units(&previous.canonical_path)?;
        reload_systemd().await?;
        switch_current_release(&previous.canonical_path)?;
        restore_database(&snapshot.path)?;
        start_service().await?;
        wait_for_health(Some(&previous.version)).await?;
        mark_ready()
    }
    .await;
    match rollback {
        Ok(()) => {
            if let Err(error) = remove_activation_receipt(request_id) {
                reporting_errors.push(format!("could not remove activation receipt: {error}"));
            }
            if let Err(error) = status.clear_rollback_point(status_now()) {
                reporting_errors.push(format!("could not clear rollback point: {error}"));
            }
            if let Err(error) = status.set_rollback(
                true,
                true,
                true,
                Some(previous.version.clone()),
                Some(snapshot.sha256.clone()),
                status_now(),
            ) {
                reporting_errors.push(format!("could not record rollback completion: {error}"));
            }
            let message = if packages_changed {
                "The prior application and database were restored; signed package upgrades remain installed"
            } else {
                "The prior application and database were restored automatically"
            };
            if let Err(error) = status.finish(
                UpdateOutcome::RolledBack,
                "rolled_back",
                message,
                status_now(),
            ) {
                reporting_errors.push(format!("could not record rollback outcome: {error}"));
            }
            if reporting_errors.is_empty() {
                Err(activation_error.context("new release failed and was rolled back"))
            } else {
                Err(anyhow!(
                    "new release failed and was rolled back: {activation_error}; rollback reporting requires attention: {}",
                    reporting_errors.join("; ")
                ))
            }
        }
        Err(rollback_error) => {
            if let Err(error) = status.finish(
                UpdateOutcome::NeedsIntervention,
                "rollback_failed",
                "The new release failed and automatic restoration also failed; operator intervention is required",
                status_now(),
            ) {
                reporting_errors.push(format!("could not record rollback failure: {error}"));
            }
            Err(anyhow!(
                "activation failed: {activation_error}; automatic rollback failed: {rollback_error}; reporting: {}",
                if reporting_errors.is_empty() {
                    "no additional reporting error".to_owned()
                } else {
                    reporting_errors.join("; ")
                }
            ))
        }
    }
}

fn remove_activation_receipt(request_id: Uuid) -> Result<()> {
    let receipt = Path::new(UPDATE_RECEIPT_ROOT).join(format!("{request_id}.json"));
    match std::fs::symlink_metadata(&receipt) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("activation receipt is not a safe regular file");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    bail!("activation receipt has unsafe ownership or permissions");
                }
            }
            std::fs::remove_file(receipt)?;
            sync_directory(Path::new(UPDATE_RECEIPT_ROOT))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

struct TemporaryDirectory {
    path: PathBuf,
    retain: bool,
}

impl TemporaryDirectory {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            retain: false,
        }
    }

    fn retain(&mut self) {
        self.retain = true;
    }
}

impl From<PathBuf> for TemporaryDirectory {
    fn from(path: PathBuf) -> Self {
        Self::new(path)
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        if !self.retain && is_direct_partial_release(&self.path) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn is_direct_partial_release(path: &Path) -> bool {
    path.parent() == Some(Path::new(RELEASES_ROOT))
        && path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with(".partial-") && name.len() <= 128)
}

fn backup_database(destination: &Path) -> Result<DatabaseSnapshot> {
    if destination.parent() != Some(Path::new(UPDATE_ROLLBACK_ROOT)) {
        bail!("database snapshot path escaped the fixed rollback root");
    }
    let database = Path::new(DATABASE_PATH);
    let metadata = std::fs::symlink_metadata(database)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_DATABASE_SNAPSHOT_BYTES
    {
        bail!("Vexa-VM database is not a safe regular file");
    }
    if std::fs::symlink_metadata(destination).is_ok() {
        bail!("database rollback snapshot already exists");
    }
    let file_name = destination
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("database snapshot name is invalid"))?;
    let temporary = Path::new(UPDATE_ROLLBACK_ROOT).join(format!(".{file_name}.tmp"));
    if std::fs::symlink_metadata(&temporary).is_ok() {
        bail!("database backup temporary file already exists");
    }
    let cleanup = TemporaryFile::new(temporary.clone());
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(30))?;
    let temporary_text = temporary
        .to_str()
        .ok_or_else(|| anyhow!("database snapshot path is not UTF-8"))?;
    connection.execute("VACUUM main INTO ?1", params![temporary_text])?;
    drop(connection);

    let snapshot_metadata = std::fs::symlink_metadata(&temporary)?;
    if !snapshot_metadata.file_type().is_file()
        || snapshot_metadata.file_type().is_symlink()
        || snapshot_metadata.len() == 0
        || snapshot_metadata.len() > MAX_DATABASE_SNAPSHOT_BYTES
    {
        bail!("created database snapshot is outside the supported size limit");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
    }
    File::open(&temporary)?.sync_all()?;
    let (size_bytes, sha256) = hash_regular_file(&temporary, MAX_DATABASE_SNAPSHOT_BYTES)?;
    std::fs::rename(&temporary, destination)?;
    drop(cleanup);
    sync_directory(Path::new(UPDATE_ROLLBACK_ROOT))?;
    Ok(DatabaseSnapshot {
        path: destination.to_path_buf(),
        sha256,
        size_bytes,
    })
}

fn remove_database_snapshot(snapshot: &Path) -> Result<()> {
    if snapshot.parent() != Some(Path::new(UPDATE_ROLLBACK_ROOT)) {
        bail!("database snapshot escaped the fixed rollback root");
    }
    let metadata = std::fs::symlink_metadata(snapshot)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("database snapshot is not a safe regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("database snapshot has unsafe ownership or permissions");
        }
    }
    std::fs::remove_file(snapshot)?;
    sync_directory(Path::new(UPDATE_ROLLBACK_ROOT))
}

fn restore_database(snapshot: &Path) -> Result<()> {
    if snapshot.parent() != Some(Path::new(UPDATE_ROLLBACK_ROOT)) {
        bail!("database snapshot escaped the fixed rollback root");
    }
    let (snapshot_size, _) = hash_regular_file(snapshot, MAX_DATABASE_SNAPSHOT_BYTES)?;
    if snapshot_size == 0 {
        bail!("database snapshot is empty");
    }
    let database = Path::new(DATABASE_PATH);
    let database_metadata = std::fs::symlink_metadata(database)?;
    if !database_metadata.file_type().is_file() || database_metadata.file_type().is_symlink() {
        bail!("Vexa-VM database is not a safe regular file");
    }
    let parent = database
        .parent()
        .ok_or_else(|| anyhow!("database path has no parent"))?;
    let temporary = parent.join(format!(".vexa.db.restore.{}", Uuid::new_v4()));
    let cleanup = TemporaryFile::new(temporary.clone());
    let mut source = open_regular_nofollow(snapshot)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut target = options.open(&temporary)?;
    let copied = std::io::copy(
        &mut std::io::Read::take(
            std::io::Read::by_ref(&mut source),
            MAX_DATABASE_SNAPSHOT_BYTES.saturating_add(1),
        ),
        &mut target,
    )?;
    if copied != snapshot_size {
        bail!("database snapshot changed during restoration");
    }
    target.sync_all()?;
    drop(target);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        std::fs::set_permissions(
            &temporary,
            std::fs::Permissions::from_mode(database_metadata.mode() & 0o777),
        )?;
        chown_path(
            &temporary,
            database_metadata.uid(),
            database_metadata.gid(),
        )?;
    }
    remove_sqlite_sidecar(database, "-wal")?;
    remove_sqlite_sidecar(database, "-shm")?;
    std::fs::rename(&temporary, database)?;
    drop(cleanup);
    sync_directory(parent)?;
    Ok(())
}

fn remove_sqlite_sidecar(database: &Path, suffix: &str) -> Result<()> {
    let mut name = database.as_os_str().to_os_string();
    name.push(suffix);
    let sidecar = PathBuf::from(name);
    match std::fs::symlink_metadata(&sidecar) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("SQLite sidecar is not a regular file");
            }
            std::fs::remove_file(sidecar)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn current_release() -> Result<ActiveRelease> {
    let releases_root = std::fs::canonicalize(RELEASES_ROOT)?;
    let current = Path::new(CURRENT_LINK);
    let metadata = std::fs::symlink_metadata(current)
        .context("the versioned Vexa-VM current symlink is not installed")?;
    if !metadata.file_type().is_symlink() {
        bail!("the active Vexa-VM path must be a symlink");
    }
    let link = std::fs::read_link(current)?;
    let candidate = if link.is_absolute() {
        link
    } else {
        Path::new(INSTALL_ROOT).join(link)
    };
    let canonical_path = std::fs::canonicalize(candidate)?;
    if canonical_path.parent() != Some(releases_root.as_path()) {
        bail!("the active release escaped the fixed releases directory");
    }
    let release_metadata = std::fs::symlink_metadata(&canonical_path)?;
    if !release_metadata.file_type().is_dir() || release_metadata.file_type().is_symlink() {
        bail!("the active release is not a safe directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if release_metadata.uid() != 0 || release_metadata.mode() & 0o022 != 0 {
            bail!("the active release must be root-owned and non-writable by other users");
        }
    }
    let version = canonical_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("active release name is invalid"))?;
    let version = normalized_release_name(version)?;
    require_release_payload(&canonical_path)?;
    Ok(ActiveRelease {
        version,
        canonical_path,
    })
}

fn switch_current_release(release_path: &Path) -> Result<()> {
    let releases_root = std::fs::canonicalize(RELEASES_ROOT)?;
    let release_path = std::fs::canonicalize(release_path)?;
    if release_path.parent() != Some(releases_root.as_path()) {
        bail!("requested release escaped the fixed releases directory");
    }
    require_release_payload(&release_path)?;
    let version = release_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("release directory name is invalid"))?;
    normalized_release_name(version)?;
    let current = Path::new(CURRENT_LINK);
    if let Ok(metadata) = std::fs::symlink_metadata(current) {
        if !metadata.file_type().is_symlink() {
            bail!("refusing to replace a non-symlink active release path");
        }
    }
    let temporary = Path::new(INSTALL_ROOT).join(format!(".current.{}.tmp", Uuid::new_v4()));
    let cleanup = TemporaryFile::new(temporary.clone());
    let relative_target = Path::new("releases").join(version);
    #[cfg(unix)]
    std::os::unix::fs::symlink(relative_target, &temporary)?;
    #[cfg(not(unix))]
    bail!("the update executor requires Unix symlinks");
    std::fs::rename(&temporary, current)?;
    drop(cleanup);
    sync_directory(Path::new(INSTALL_ROOT))?;
    Ok(())
}

fn require_release_payload(path: &Path) -> Result<()> {
    for &relative in REQUIRED_RELEASE_FILES {
        let candidate = path.join(relative);
        let metadata = std::fs::symlink_metadata(&candidate)
            .with_context(|| format!("release payload is missing {relative}"))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
        {
            bail!("release payload entry {relative} is not a non-empty regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                bail!("release payload entry {relative} has unsafe ownership or permissions");
            }
            if (relative.starts_with("bin/")
                || relative == "guest-tools/vexa-guest-tools-linux-x86_64")
                && metadata.mode() & 0o111 == 0
            {
                bail!("release payload entry {relative} is not executable");
            }
        }
    }
    let directory_version = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("release directory name is invalid"))?;
    let version_file = read_fixed_file(&path.join("VERSION"), 128, true)?;
    let version_file = std::str::from_utf8(&version_file)
        .context("release VERSION file is not UTF-8")?
        .trim_end_matches(|character| matches!(character, '\r' | '\n'));
    if version_file.contains('\r')
        || version_file.contains('\n')
        || normalized_release_name(version_file)? != normalized_release_name(directory_version)?
    {
        bail!("release VERSION does not match its versioned directory");
    }
    Ok(())
}

fn normalized_release_name(value: &str) -> Result<String> {
    let value = value.strip_prefix('v').unwrap_or(value);
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte))
    {
        bail!("release version is not a safe semantic version");
    }
    if value.matches('+').count() > 1 {
        bail!("release version is not a safe semantic version");
    }
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(version, build)| (version, Some(build)));
    if build.is_some_and(|build| !valid_semver_identifiers(build, false)) {
        bail!("release version is not a safe semantic version");
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(version, prerelease)| {
            (version, Some(prerelease))
        });
    if prerelease.is_some_and(|prerelease| !valid_semver_identifiers(prerelease, true)) {
        bail!("release version is not a safe semantic version");
    }
    let numbers = core.split('.').collect::<Vec<_>>();
    if numbers.len() != 3
        || numbers.iter().any(|number| {
            number.is_empty()
                || !number.bytes().all(|byte| byte.is_ascii_digit())
                || (number.len() > 1 && number.starts_with('0'))
        })
    {
        bail!("release version is not a safe semantic version");
    }
    Ok(value.to_owned())
}

fn valid_semver_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !(reject_numeric_leading_zero
                    && identifier.len() > 1
                    && identifier.bytes().all(|byte| byte.is_ascii_digit())
                    && identifier.starts_with('0'))
        })
}

fn write_activation_receipt(receipt: &HelperActivationReceipt) -> Result<()> {
    let activation_id = Uuid::parse_str(&receipt.activation_id)?;
    let final_path = Path::new(UPDATE_RECEIPT_ROOT).join(format!("{activation_id}.json"));
    if final_path.exists() {
        bail!("activation receipt already exists");
    }
    let bytes = serde_json::to_vec_pretty(receipt)?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        bail!("activation receipt exceeded its size limit");
    }
    let temporary = Path::new(UPDATE_RECEIPT_ROOT).join(format!(
        ".{activation_id}.{}.tmp",
        Uuid::new_v4()
    ));
    let cleanup = TemporaryFile::new(temporary.clone());
    write_new_private_file(&temporary, &bytes)?;
    std::fs::hard_link(&temporary, &final_path)?;
    std::fs::remove_file(&temporary)?;
    drop(cleanup);
    sync_directory(Path::new(UPDATE_RECEIPT_ROOT))?;
    Ok(())
}

fn hash_regular_file(path: &Path, maximum: u64) -> Result<(u64, String)> {
    let mut file = open_regular_nofollow(path)?;
    let metadata = file.metadata()?;
    if metadata.len() == 0 || metadata.len() > maximum {
        bail!("file is outside its supported size limit");
    }
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("file size overflow"))?;
        if size > maximum {
            bail!("file exceeded its supported size limit");
        }
        digest.update(&buffer[..read]);
    }
    Ok((size, format!("{:x}", digest.finalize())))
}

fn open_regular_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x0002_0000);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        bail!("file is not regular");
    }
    Ok(file)
}

struct TemporaryFile {
    path: PathBuf,
    retain: bool,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            retain: false,
        }
    }

    fn retain(&mut self) {
        self.retain = true;
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.retain {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn chown_path(path: &Path, user: u32, group: u32) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: the path is NUL-terminated and uid/gid came from trusted file metadata.
    if unsafe { chown(path.as_ptr(), user, group) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
extern "C" {
    fn chown(path: *const std::os::raw::c_char, owner: u32, group: u32) -> i32;
}

fn validate_package_action(component: UpdateComponent, packages: &[SystemPackage]) -> Result<()> {
    let allowed: &[&str] = match component {
        UpdateComponent::Qemu => &["qemu-kvm", "qemu-system-x86", "qemu-utils"],
        UpdateComponent::Libvirt => &[
            "libvirt-clients",
            "libvirt-daemon-driver-qemu",
            "libvirt-daemon-system",
        ],
        UpdateComponent::VexaVm => bail!("Vexa-VM cannot be updated through APT"),
    };
    if packages.is_empty() || packages.len() > 8 {
        bail!("package action is outside its fixed size limit");
    }
    let mut seen = BTreeSet::new();
    for package in packages {
        if !allowed.contains(&package.name.as_str()) || !seen.insert(package.name.as_str()) {
            bail!("package action contains an unallowlisted or duplicate package");
        }
        if package.candidate_version.is_empty()
            || package.candidate_version.len() > 128
            || !package
                .candidate_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".+:~_-".contains(&byte))
        {
            bail!("package action contains an invalid candidate version");
        }
    }
    Ok(())
}

async fn apply_package_actions(
    actions: &[(UpdateComponent, Vec<SystemPackage>)],
    status: &mut StatusWriter,
) -> Result<()> {
    let mut packages = Vec::new();
    let mut seen = BTreeSet::new();
    for (component, action_packages) in actions {
        validate_package_action(*component, action_packages)?;
        for package in action_packages {
            if !seen.insert(package.name.clone()) {
                bail!("the package plan contains a duplicate package");
            }
            packages.push((*component, package.clone()));
        }
    }
    if packages.is_empty() || packages.len() > 16 {
        bail!("the package plan is outside its fixed size limit");
    }

    let mut changes = Vec::with_capacity(packages.len());
    for (component, package) in &packages {
        changes.push(PackageChangeStatus {
            component: component.as_str().to_owned(),
            package: package.name.clone(),
            previous_version: query_installed_version(&package.name).await?,
            requested_version: package.candidate_version.clone(),
            applied: false,
        });
    }
    status.set_package_changes(changes.clone(), current_unix_time()?)?;

    run_inherited_command(APT_GET, &[OsString::from("update")], COMMAND_TIMEOUT).await?;
    let mut arguments = vec![
        OsString::from("-y"),
        OsString::from("--no-install-recommends"),
        OsString::from("--only-upgrade"),
        OsString::from("-o"),
        OsString::from("Dpkg::Options::=--force-confold"),
        OsString::from("install"),
    ];
    for (_, package) in &packages {
        arguments.push(OsString::from(format!(
            "{}={}",
            package.name, package.candidate_version
        )));
    }

    validate_apt_simulation(&arguments, &packages, &changes).await?;
    let install_result = run_inherited_command(APT_GET, &arguments, COMMAND_TIMEOUT).await;

    for (index, (_, package)) in packages.iter().enumerate() {
        let installed = query_installed_version(&package.name).await?;
        changes[index].applied = installed.as_deref() == Some(package.candidate_version.as_str());
    }
    status.set_package_changes(changes.clone(), current_unix_time()?)?;
    install_result?;
    for (index, (_, package)) in packages.iter().enumerate() {
        if !changes[index].applied {
            bail!(
                "APT did not install the exact approved version of {}",
                package.name
            );
        }
    }
    Ok(())
}

async fn validate_apt_simulation(
    install_arguments: &[OsString],
    packages: &[(UpdateComponent, SystemPackage)],
    changes: &[PackageChangeStatus],
) -> Result<()> {
    let mut arguments = Vec::with_capacity(install_arguments.len() + 2);
    arguments.push(OsString::from("--simulate"));
    arguments.push(OsString::from("-o"));
    arguments.push(OsString::from("Debug::NoLocking=true"));
    arguments.extend_from_slice(install_arguments);
    let output = run_output_command(APT_GET, &arguments, COMMAND_TIMEOUT).await?;
    if !output.status.success() {
        bail!("APT rejected the exact approved package plan during simulation");
    }
    if output.stdout.len() > 2 * 1024 * 1024 {
        bail!("APT simulation returned an oversized response");
    }
    let output = std::str::from_utf8(&output.stdout).context("APT simulation output is not UTF-8")?;
    let expected = packages
        .iter()
        .zip(changes)
        .filter(|((_, package), change)| {
            change.previous_version.as_deref() != Some(package.candidate_version.as_str())
        })
        .map(|((_, package), _)| (package.name.clone(), package.candidate_version.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    validate_apt_simulation_output(output, &expected)
}

fn validate_apt_simulation_output(
    output: &str,
    expected: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let mut observed = std::collections::BTreeMap::new();
    for line in output.lines() {
        if line.starts_with("Remv ") {
            bail!("APT simulation proposed removing a package");
        }
        let Some(change) = line.strip_prefix("Inst ") else {
            continue;
        };
        let mut fields = change.split_whitespace();
        let raw_name = fields
            .next()
            .ok_or_else(|| anyhow!("APT simulation returned an invalid install action"))?;
        let name = raw_name.split_once(':').map_or(raw_name, |(name, _)| name);
        let opening = change
            .find('(')
            .ok_or_else(|| anyhow!("APT simulation omitted a candidate version"))?;
        let version = change[opening + 1..]
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow!("APT simulation omitted a candidate version"))?;
        let Some(expected_version) = expected.get(name) else {
            bail!("APT simulation proposed changing non-allowlisted package {name}");
        };
        if version != expected_version.as_str()
            || observed
                .insert(name.to_owned(), version.to_owned())
                .is_some()
        {
            bail!("APT simulation changed the approved package/version plan");
        }
    }
    if observed.len() != expected.len()
        || expected
            .iter()
            .any(|(name, version)| observed.get(name) != Some(version))
    {
        bail!("APT simulation did not preserve the exact approved package/version plan");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_release_names_are_strict() {
        for valid in ["0.1.0", "1.2.3-rc.1", "1.2.3+build.7", "v2.0.0"] {
            assert!(normalized_release_name(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01",
            "1.2.3-", "1.2.3+", "1.2.3+a..b", "../../1.2.3",
        ] {
            assert!(normalized_release_name(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn apt_simulation_accepts_only_the_exact_plan() {
        let expected = std::collections::BTreeMap::from([
            ("qemu-system-x86".to_owned(), "1:8.2.2-1ubuntu1".to_owned()),
            ("qemu-utils".to_owned(), "1:8.2.2-1ubuntu1".to_owned()),
        ]);
        let output = "Inst qemu-system-x86 [1:8.2.1] (1:8.2.2-1ubuntu1 Ubuntu [amd64])\n\
                      Inst qemu-utils [1:8.2.1] (1:8.2.2-1ubuntu1 Ubuntu [amd64])\n";
        assert!(validate_apt_simulation_output(output, &expected).is_ok());

        let dependency = format!("{output}Inst libc6 [2.39] (2.40 Ubuntu [amd64])\n");
        assert!(validate_apt_simulation_output(&dependency, &expected).is_err());
        assert!(validate_apt_simulation_output("Remv qemu-utils [1:8.2.1]\n", &expected).is_err());
    }
}

async fn query_installed_version(package: &str) -> Result<Option<String>> {
    if package.is_empty()
        || package.len() > 64
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte))
    {
        bail!("invalid package name at the privileged boundary");
    }
    let arguments = [
        OsString::from("-W"),
        OsString::from("-f=${db:Status-Abbrev}\t${Version}\n"),
        OsString::from(package),
    ];
    let output = run_output_command(DPKG_QUERY, &arguments, Duration::from_secs(30)).await?;
    if !output.status.success() {
        return Ok(None);
    }
    if output.stdout.len() > 4096 {
        bail!("dpkg-query returned an oversized response");
    }
    let output = std::str::from_utf8(&output.stdout).context("dpkg-query output is not UTF-8")?;
    let line = output.trim_end_matches('\n');
    let (status, version) = line
        .split_once('\t')
        .ok_or_else(|| anyhow!("dpkg-query returned an unexpected response"))?;
    if !status.starts_with("ii") || version.is_empty() || version.len() > 128 {
        return Ok(None);
    }
    Ok(Some(version.to_owned()))
}

async fn restart_service() -> Result<()> {
    run_inherited_command(
        SYSTEMCTL,
        &[OsString::from("restart"), OsString::from(SERVICE)],
        SERVICE_TIMEOUT,
    )
    .await
}

async fn stop_service() -> Result<()> {
    run_inherited_command(
        SYSTEMCTL,
        &[OsString::from("stop"), OsString::from(SERVICE)],
        SERVICE_TIMEOUT,
    )
    .await
}

async fn start_service() -> Result<()> {
    run_inherited_command(
        SYSTEMCTL,
        &[OsString::from("start"), OsString::from(SERVICE)],
        SERVICE_TIMEOUT,
    )
    .await
}

fn install_release_units(release_path: &Path) -> Result<()> {
    let unit_root = Path::new(SYSTEMD_UNIT_ROOT);
    let root_metadata = std::fs::symlink_metadata(unit_root)?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        bail!("systemd unit root is not a safe directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if root_metadata.uid() != 0 || root_metadata.mode() & 0o022 != 0 {
            bail!("systemd unit root has unsafe ownership or permissions");
        }
    }
    for unit in [
        "vexa-vm.service",
        "vexa-update-executor-ready.service",
        "vexa-update-dispatch.service",
        "vexa-update-dispatch.path",
    ] {
        let source = release_path.join("deploy").join(unit);
        let bytes = read_fixed_file(&source, 256 * 1024, true)?;
        let target = unit_root.join(unit);
        if let Ok(metadata) = std::fs::symlink_metadata(&target) {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("refusing to replace unsafe systemd unit {unit}");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    bail!("installed systemd unit {unit} has unsafe permissions");
                }
            }
        }
        let temporary = unit_root.join(format!(".{unit}.{}.tmp", Uuid::new_v4()));
        let cleanup = TemporaryFile::new(temporary.clone());
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut file = options.open(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &target)?;
        drop(cleanup);
    }
    sync_directory(unit_root)
}

async fn reload_systemd() -> Result<()> {
    run_inherited_command(
        SYSTEMCTL,
        &[OsString::from("daemon-reload")],
        SERVICE_TIMEOUT,
    )
    .await
}

async fn run_inherited_command(
    executable: &str,
    arguments: &[OsString],
    timeout: Duration,
) -> Result<()> {
    validate_fixed_executable(executable)?;
    let mut command = Command::new(executable);
    configure_command(&mut command);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let status = tokio::time::timeout(timeout, command.status())
        .await
        .map_err(|_| anyhow!("fixed privileged command timed out"))??;
    if !status.success() {
        bail!(
            "fixed privileged command failed with exit status {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

async fn run_output_command(
    executable: &str,
    arguments: &[OsString],
    timeout: Duration,
) -> Result<std::process::Output> {
    validate_fixed_executable(executable)?;
    let mut command = Command::new(executable);
    configure_command(&mut command);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| anyhow!("fixed privileged query timed out"))?
        .map_err(Into::into)
}

fn configure_command(command: &mut Command) {
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("APT_LISTCHANGES_FRONTEND", "none");
}

fn validate_fixed_executable(path: &str) -> Result<()> {
    if path != SYSTEMCTL && path != APT_GET && path != DPKG_QUERY {
        bail!("privileged executable is outside the fixed allowlist");
    }
    let metadata = std::fs::metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("fixed privileged executable is unavailable");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.permissions().mode() & 0o111 == 0
        {
            bail!("fixed privileged executable has unsafe ownership or permissions");
        }
    }
    Ok(())
}

async fn wait_for_health(expected_version: Option<&str>) -> Result<()> {
    let address = read_loopback_bind_address()?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .read_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(4))
        .build()?;
    let deadline = Instant::now() + HEALTH_WINDOW;
    let mut last_error = "service did not answer".to_owned();
    while Instant::now() < deadline {
        match check_health_once(&client, address, expected_version).await {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(anyhow!("service readiness timed out: {last_error}"))
}

async fn check_health_once(
    client: &reqwest::Client,
    address: SocketAddr,
    expected_version: Option<&str>,
) -> Result<()> {
    let health = fetch_local_json(client, address, "/healthz").await?;
    if health.get("ok").and_then(Value::as_bool) != Some(true) {
        bail!("health endpoint did not report ok");
    }
    if let Some(expected_version) = expected_version {
        if health.get("version").and_then(Value::as_str) != Some(expected_version) {
            bail!("health endpoint reported the wrong application version");
        }
    }
    let ready = fetch_local_json(client, address, "/readyz").await?;
    if ready.get("ready").and_then(Value::as_bool) != Some(true) {
        bail!("readiness endpoint is not ready");
    }
    Ok(())
}

async fn fetch_local_json(
    client: &reqwest::Client,
    address: SocketAddr,
    path: &str,
) -> Result<Value> {
    if !matches!(path, "/healthz" | "/readyz") || !address.ip().is_loopback() {
        bail!("health request escaped the fixed loopback policy");
    }
    let response = client
        .get(format!("http://{address}{path}"))
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("health endpoint returned HTTP {}", response.status());
    }
    if response.content_length().is_some_and(|length| length > 64 * 1024) {
        bail!("health response exceeded its size limit");
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > 64 * 1024 {
            bail!("health response exceeded its size limit");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).context("health endpoint returned invalid JSON")
}

fn read_loopback_bind_address() -> Result<SocketAddr> {
    let path = Path::new(ENVIRONMENT_PATH);
    let bytes = match read_fixed_file(path, MAX_ENVIRONMENT_BYTES, true) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok("127.0.0.1:8080".parse().expect("fixed loopback address is valid"))
        }
        Err(error) => return Err(error),
    };
    let contents = std::str::from_utf8(&bytes).context("Vexa-VM environment is not UTF-8")?;
    let mut bind = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name == "VEXA_BIND" {
            if bind.replace(value).is_some() {
                bail!("VEXA_BIND is duplicated in the root-owned environment");
            }
        }
    }
    let address: SocketAddr = bind
        .unwrap_or("127.0.0.1:8080")
        .parse()
        .context("VEXA_BIND is not a socket address")?;
    if !address.ip().is_loopback() {
        bail!("the update executor requires VEXA_BIND to use a loopback address");
    }
    Ok(address)
}

#[allow(clippy::too_many_arguments)]
async fn execute_rollback(
    request_id: Uuid,
    activation_id: &str,
    release: &str,
    restore_release: &str,
    snapshot_path: &Path,
    snapshot_sha256: &str,
    snapshot_size_bytes: u64,
    components: &BTreeSet<UpdateComponent>,
    status: &mut StatusWriter,
) -> Result<()> {
    let activation_uuid =
        Uuid::parse_str(activation_id).context("rollback activation ID is invalid")?;
    if components != &BTreeSet::from([UpdateComponent::VexaVm]) {
        bail!("only the Vexa-VM application component supports automatic rollback");
    }
    let active = current_release()?;
    if active.version != normalized_release_name(release)? {
        bail!("the rollback point is stale because another release is active");
    }
    let restore_version = normalized_release_name(restore_release)?;
    let restore_path = Path::new(RELEASES_ROOT).join(&restore_version);
    let restore_path = std::fs::canonicalize(&restore_path)
        .context("the requested prior application release is unavailable")?;
    if restore_path.parent() != Some(std::fs::canonicalize(RELEASES_ROOT)?.as_path()) {
        bail!("the requested prior release escaped the releases root");
    }
    require_release_payload(&restore_path)?;

    let (verified_size, verified_sha256) =
        hash_regular_file(snapshot_path, MAX_DATABASE_SNAPSHOT_BYTES)?;
    if verified_size != snapshot_size_bytes
        || !verified_sha256.eq_ignore_ascii_case(snapshot_sha256)
    {
        bail!("rollback database snapshot changed after privileged validation");
    }

    status.phase(
        "rollback_backup",
        20,
        "Backing up the currently active database before rollback",
        current_unix_time()?,
    )?;
    let recovery_path = Path::new(UPDATE_ROLLBACK_ROOT)
        .join(format!("{request_id}.pre-rollback.sqlite3"));
    let recovery = backup_database(&recovery_path)?;
    status.set_rollback(
        true,
        true,
        false,
        Some(restore_version.clone()),
        Some(snapshot_sha256.to_owned()),
        current_unix_time()?,
    )?;
    write_rollback_recovery_journal(&RollbackRecoveryJournal {
        schema_version: 1,
        request_id: request_id.to_string(),
        recover_release: active.version.clone(),
        requested_release: restore_version.clone(),
        snapshot_path: recovery.path.clone(),
        snapshot_sha256: recovery.sha256.clone(),
        snapshot_size_bytes: recovery.size_bytes,
        created_at: current_unix_time()?,
    })?;

    status.phase(
        "rolling_back",
        55,
        "Restoring the selected application release and matching database",
        current_unix_time()?,
    )?;
    let rollback = async {
        stop_service().await?;
        install_release_units(&restore_path)?;
        reload_systemd().await?;
        switch_current_release(&restore_path)?;
        restore_database(snapshot_path)?;
        start_service().await?;
        wait_for_health(Some(&restore_version)).await?;
        mark_ready()
    }
    .await;

    match rollback {
        Ok(()) => {
            // The release/database switch is already complete at this point.
            // First publish the successful rollback as the commit record. If
            // the helper is killed after this atomic status write, the next
            // dispatcher run archives the request instead of using the
            // recovery journal to undo a rollback that had already passed
            // readiness. Authority cleanup follows the commit record; a
            // stale point is hidden by this newer rollback status and is also
            // rejected by the active-release check.
            let completion_time = current_unix_time().unwrap_or_else(|_| {
                status
                    .snapshot()
                    .updated_at
                    .max(status.snapshot().started_at)
            });
            let commit_status = status
                .set_rollback(
                    true,
                    true,
                    true,
                    Some(restore_version.clone()),
                    Some(snapshot_sha256.to_owned()),
                    completion_time,
                )
                .and_then(|_| {
                    status.finish(
                        UpdateOutcome::Succeeded,
                        "completed",
                        "The prior application release and database were restored successfully",
                        completion_time,
                    )
                });
            if let Err(commit_error) = commit_status {
                // Do not leave an unrecorded rollback committed. The original
                // receipt has not been removed yet, so restoring the
                // pre-rollback state preserves both host state and the
                // original rollback authority.
                let recovery_result = restore_pre_rollback_state(&active, &recovery).await;
                return match recovery_result {
                    Ok(()) => {
                        let reporting_time = current_unix_time().unwrap_or_default();
                        let reporting = status
                            .set_rollback(
                                true,
                                true,
                                false,
                                Some(restore_version.clone()),
                                Some(snapshot_sha256.to_owned()),
                                reporting_time,
                            )
                            .and_then(|_| {
                                status.finish(
                                    UpdateOutcome::Failed,
                                    "rollback_commit_not_recorded",
                                    "The rollback passed readiness but its commit status could not be recorded, so the original release was restored",
                                    reporting_time,
                                )
                            });
                        Err(anyhow!(
                            "rollback commit status failed and the original release was restored: {commit_error}; status: {}",
                            reporting
                                .err()
                                .map(|error| error.to_string())
                                .unwrap_or_else(|| "recovery recorded".to_owned())
                        ))
                    }
                    Err(recovery_error) => {
                        let reporting = status.finish(
                            UpdateOutcome::NeedsIntervention,
                            "rollback_commit_recovery_failed",
                            "Rollback status persistence and restoration of the original release both failed; operator intervention is required",
                            current_unix_time().unwrap_or_default(),
                        );
                        Err(anyhow!(
                            "rollback commit status failed: {commit_error}; recovery failed: {recovery_error}; status: {}",
                            reporting
                                .err()
                                .map(|error| error.to_string())
                                .unwrap_or_else(|| "operator intervention recorded".to_owned())
                        ))
                    }
                };
            }

            // Invalidate both rollback capabilities on a best-effort basis:
            // the root-only receipt is the privileged authority, while the
            // original activation status is the non-secret panel offer. A
            // cleanup/reporting fault must never relabel the completed host
            // mutation as a failed rollback.
            let mut cleanup_warnings = Vec::new();
            if let Err(error) = remove_activation_receipt(activation_uuid) {
                cleanup_warnings.push(format!("activation receipt: {error}"));
            }
            if let Err(error) =
                StatusWriter::clear_rollback_point_for_activation(activation_uuid, completion_time)
            {
                cleanup_warnings.push(format!("public rollback point: {error}"));
            }
            if !cleanup_warnings.is_empty() {
                eprintln!(
                    "rollback completed but stale rollback metadata cleanup requires attention: {}",
                    cleanup_warnings.join("; ")
                );
                if let Err(error) = status.finish(
                    UpdateOutcome::Succeeded,
                    "completed_with_warnings",
                    "The prior application release and database were restored successfully; stale rollback metadata cleanup requires operator attention",
                    completion_time,
                ) {
                    eprintln!(
                        "rollback completed but its cleanup warning could not be persisted: {error}"
                    );
                }
            }
            Ok(())
        }
        Err(rollback_error) => {
            // Status I/O must never prevent restoration of the release and
            // database that were active before this rollback request.
            if let Err(error) = status.phase(
                "rollback_recovery",
                82,
                "Rollback health checks failed; restoring the release active before this request",
                current_unix_time().unwrap_or_default(),
            ) {
                eprintln!("could not persist rollback recovery status: {error}");
            }
            let recovery_result = restore_pre_rollback_state(&active, &recovery).await;
            match recovery_result {
                Ok(()) => {
                    let reporting = status.finish(
                        UpdateOutcome::Failed,
                        "rollback_failed_recovered",
                        "The requested rollback failed, but the original release was recovered",
                        current_unix_time().unwrap_or_default(),
                    );
                    match reporting {
                        Ok(()) => Err(rollback_error
                            .context("requested rollback failed; original release recovered")),
                        Err(status_error) => Err(anyhow!(
                            "requested rollback failed but the original release was recovered: {rollback_error}; status persistence failed: {status_error}"
                        )),
                    }
                }
                Err(recovery_error) => {
                    let reporting = status.finish(
                        UpdateOutcome::NeedsIntervention,
                        "rollback_recovery_failed",
                        "Rollback and recovery both failed; operator intervention is required",
                        current_unix_time().unwrap_or_default(),
                    );
                    Err(anyhow!(
                        "rollback failed: {rollback_error}; recovery failed: {recovery_error}; status: {}",
                        reporting
                            .err()
                            .map(|error| error.to_string())
                            .unwrap_or_else(|| "operator intervention recorded".to_owned())
                    ))
                }
            }
        }
    }
}

async fn restore_pre_rollback_state(
    active: &ActiveRelease,
    recovery: &DatabaseSnapshot,
) -> Result<()> {
    stop_service().await?;
    install_release_units(&active.canonical_path)?;
    reload_systemd().await?;
    switch_current_release(&active.canonical_path)?;
    restore_database(&recovery.path)?;
    start_service().await?;
    wait_for_health(Some(&active.version)).await?;
    mark_ready()
}
