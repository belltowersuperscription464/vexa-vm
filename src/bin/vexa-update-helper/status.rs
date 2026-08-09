use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const STATUS_ROOT: &str = "/var/lib/vexa-vm/updates/status";
const MAX_STATUS_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateOutcome {
    Running,
    Succeeded,
    Failed,
    RolledBack,
    NeedsIntervention,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PackageChangeStatus {
    pub component: String,
    pub package: String,
    pub previous_version: Option<String>,
    pub requested_version: String,
    pub applied: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RollbackStatus {
    pub available: bool,
    pub attempted: bool,
    pub succeeded: bool,
    pub previous_release: Option<String>,
    pub snapshot_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRollbackPointStatus {
    pub activation_id: String,
    pub release: String,
    pub previous_release: String,
    pub manifest_sha256: String,
    pub snapshot_sha256: String,
    pub snapshot_size_bytes: u64,
    pub components: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DurableUpdateStatus {
    pub schema_version: u32,
    pub request_id: String,
    pub operation: Option<String>,
    pub release: Option<String>,
    pub phase: String,
    pub progress_percent: u8,
    pub outcome: UpdateOutcome,
    pub message: String,
    pub started_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
    pub package_changes: Vec<PackageChangeStatus>,
    pub rollback: RollbackStatus,
    #[serde(default)]
    pub rollback_point: Option<PublicRollbackPointStatus>,
}

pub struct StatusWriter {
    path: PathBuf,
    status: DurableUpdateStatus,
}

impl StatusWriter {
    pub fn start(request_id: Uuid, now: i64) -> Result<Self> {
        ensure_status_root()?;
        let path = Path::new(STATUS_ROOT).join(format!("{request_id}.json"));
        let writer = Self {
            path,
            status: DurableUpdateStatus {
                schema_version: 1,
                request_id: request_id.to_string(),
                operation: None,
                release: None,
                phase: "validating".into(),
                progress_percent: 1,
                outcome: UpdateOutcome::Running,
                message: "Validating the signed, approved update request".into(),
                started_at: now,
                updated_at: now,
                completed_at: None,
                package_changes: Vec::new(),
                rollback: RollbackStatus::default(),
                rollback_point: None,
            },
        };
        writer.persist()?;
        Ok(writer)
    }

    pub fn existing(request_id: Uuid) -> Result<Option<DurableUpdateStatus>> {
        ensure_status_root()?;
        let path = Path::new(STATUS_ROOT).join(format!("{request_id}.json"));
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x0002_0000); // Linux O_NOFOLLOW.
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_STATUS_BYTES as u64
        {
            return Err(anyhow!("durable update status is invalid"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(anyhow!(
                    "durable update status must be root-owned and non-writable by other users"
                ));
            }
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_STATUS_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
            return Err(anyhow!("durable update status is invalid"));
        }
        serde_json::from_slice(&bytes).context("durable update status is invalid")
    }

    pub fn set_operation(&mut self, operation: &str, release: &str, now: i64) -> Result<()> {
        let mut next = self.status.clone();
        next.operation = Some(operation.to_owned());
        next.release = Some(release.to_owned());
        next.updated_at = now;
        self.commit(next)
    }

    pub fn phase(
        &mut self,
        phase: &str,
        progress_percent: u8,
        message: &str,
        now: i64,
    ) -> Result<()> {
        if progress_percent > 100 || phase.is_empty() || phase.len() > 64 {
            return Err(anyhow!("invalid update status phase"));
        }
        let mut next = self.status.clone();
        next.phase = phase.to_owned();
        next.progress_percent = progress_percent;
        next.message = bounded_message(message);
        next.updated_at = now;
        self.commit(next)
    }

    pub fn set_package_changes(
        &mut self,
        changes: Vec<PackageChangeStatus>,
        now: i64,
    ) -> Result<()> {
        if changes.len() > 16 {
            return Err(anyhow!("too many package changes in update status"));
        }
        let mut next = self.status.clone();
        next.package_changes = changes;
        next.updated_at = now;
        self.commit(next)
    }

    pub fn set_rollback(
        &mut self,
        available: bool,
        attempted: bool,
        succeeded: bool,
        previous_release: Option<String>,
        snapshot_sha256: Option<String>,
        now: i64,
    ) -> Result<()> {
        let mut next = self.status.clone();
        next.rollback = RollbackStatus {
            available,
            attempted,
            succeeded,
            previous_release,
            snapshot_sha256,
        };
        next.updated_at = now;
        self.commit(next)
    }

    /// Stage a public rollback point in memory. The caller must immediately
    /// publish it together with a terminal successful status through
    /// `finish`; a running status with a rollback offer is intentionally never
    /// written to disk.
    pub fn stage_rollback_point(
        &mut self,
        rollback_point: PublicRollbackPointStatus,
    ) -> Result<()> {
        if rollback_point.activation_id.len() > 64
            || rollback_point.release.len() > 64
            || rollback_point.previous_release.len() > 64
            || rollback_point.manifest_sha256.len() != 64
            || rollback_point.snapshot_sha256.len() != 64
            || rollback_point.snapshot_size_bytes == 0
            || rollback_point.components.is_empty()
            || rollback_point.components.len() > 3
        {
            return Err(anyhow!("invalid public rollback point"));
        }
        self.status.rollback_point = Some(rollback_point);
        Ok(())
    }

    pub fn clear_rollback_point(&mut self, now: i64) -> Result<()> {
        let mut next = self.status.clone();
        next.rollback_point = None;
        next.updated_at = now;
        self.commit(next)
    }

    /// Invalidate the public rollback point published by a completed
    /// activation after an explicit rollback has consumed its root-only
    /// receipt. The path is derived exclusively from the validated UUID and
    /// the status identity is checked again before the terminal status is
    /// rewritten.
    pub fn clear_rollback_point_for_activation(
        activation_id: Uuid,
        now: i64,
    ) -> Result<bool> {
        let Some(status) = Self::existing(activation_id)? else {
            return Ok(false);
        };
        if status.schema_version != 1
            || status.request_id != activation_id.to_string()
            || status.operation.as_deref() != Some("activate")
            || status.outcome != UpdateOutcome::Succeeded
            || status.completed_at.is_none()
        {
            return Err(anyhow!("activation status identity is invalid"));
        }
        let Some(rollback_point) = status.rollback_point.as_ref() else {
            return Ok(false);
        };
        if rollback_point.activation_id != activation_id.to_string() {
            return Err(anyhow!("activation rollback point identity is invalid"));
        }

        let mut writer = Self {
            path: Path::new(STATUS_ROOT).join(format!("{activation_id}.json")),
            status,
        };
        writer.clear_rollback_point(now)?;
        Ok(true)
    }

    pub fn finish(
        &mut self,
        outcome: UpdateOutcome,
        phase: &str,
        message: &str,
        now: i64,
    ) -> Result<()> {
        let mut next = self.status.clone();
        next.outcome = outcome;
        next.phase = phase.to_owned();
        next.progress_percent = 100;
        next.message = bounded_message(message);
        next.updated_at = now;
        next.completed_at = Some(now);
        self.commit(next)
    }

    pub fn snapshot(&self) -> &DurableUpdateStatus {
        &self.status
    }

    fn commit(&mut self, next: DurableUpdateStatus) -> Result<()> {
        self.persist_status(&next)?;
        self.status = next;
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        self.persist_status(&self.status)
    }

    fn persist_status(&self, status: &DurableUpdateStatus) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(status)
            .context("durable update status could not be encoded")?;
        if bytes.len() > MAX_STATUS_BYTES {
            return Err(anyhow!("durable update status exceeded its size limit"));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| anyhow!("durable update status path has no parent"))?;
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            status.request_id,
            Uuid::new_v4()
        ));
        let cleanup = TemporaryFile(temporary.clone());
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut file = options
            .open(&temporary)
            .context("durable update status temporary file could not be created")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &self.path)?;
        drop(cleanup);
        sync_directory(parent)?;
        Ok(())
    }
}

fn ensure_status_root() -> Result<()> {
    let root = Path::new(STATUS_ROOT);
    std::fs::create_dir_all(root)?;
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(anyhow!("durable update status root is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 {
            return Err(anyhow!("durable update status root must be root-owned"));
        }
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn bounded_message(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    if sanitized.len() <= 512 {
        return sanitized;
    }
    // `String::len` and the panel-side schema limit are byte based. Reserve
    // space for the UTF-8 ellipsis so a truncated status is still accepted by
    // the reader (the ellipsis itself occupies three bytes).
    const ELLIPSIS: &str = "…";
    let mut end = 512 - ELLIPSIS.len();
    while !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{ELLIPSIS}", &sanitized[..end])
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::bounded_message;

    #[test]
    fn bounded_messages_never_exceed_the_public_schema_limit() {
        let ascii = bounded_message(&"a".repeat(600));
        assert_eq!(ascii.len(), 512);
        assert!(ascii.ends_with('…'));

        let unicode = bounded_message(&"🪐".repeat(200));
        assert!(unicode.len() <= 512);
        assert!(unicode.ends_with('…'));
        assert!(!unicode.chars().any(char::is_control));
    }
}
