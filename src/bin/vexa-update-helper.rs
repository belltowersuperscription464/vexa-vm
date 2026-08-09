//! Root-side validator and fixed-operation executor for Vexa-VM updates.
//!
//! No request field is interpreted as a command, executable, repository, or
//! download URL. `validate` is read-only; execution is available only through
//! fixed root-owned paths and operations.

#[path = "vexa-update-helper/archive.rs"]
mod update_archive;
#[path = "vexa-update-helper/executor.rs"]
mod update_executor;
#[path = "vexa-update-helper/status.rs"]
mod update_status;

use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use uuid::Uuid;
use vexa_vm::services::updater::{
    load_fixed_trusted_release_keys, validate_privileged_request, HelperActivationReceipt,
    PrivilegedUpdateRequest, MAX_PRIVILEGED_REQUEST_BYTES, UPDATE_RECEIPT_ROOT,
    UPDATE_REQUEST_ROOT, UPDATE_ROLLBACK_ROOT, UPDATE_STAGING_ROOT,
};

const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
enum Cli {
    Validate(Uuid),
    Execute(Uuid),
    Dispatch,
    Ready,
    Unready,
}

impl Cli {
    fn parse() -> Result<Self> {
        let mut arguments = std::env::args().skip(1);
        let command = arguments.next().ok_or_else(|| anyhow!(usage()))?;
        let parsed = match command.as_str() {
            "validate" | "execute" => {
                let request_id = arguments
                    .next()
                    .ok_or_else(|| anyhow!(usage()))?
                    .parse::<Uuid>()
                    .context("request ID must be a UUID")?;
                if command == "validate" {
                    Self::Validate(request_id)
                } else {
                    Self::Execute(request_id)
                }
            }
            "dispatch" => Self::Dispatch,
            "ready" => Self::Ready,
            "unready" => Self::Unready,
            _ => return Err(anyhow!(usage())),
        };
        if arguments.next().is_some() {
            return Err(anyhow!(usage()));
        }
        Ok(parsed)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse()? {
        Cli::Validate(request_id) => validate(request_id).await,
        Cli::Execute(request_id) => update_executor::execute(request_id).await,
        Cli::Dispatch => update_executor::dispatch().await,
        Cli::Ready => update_executor::mark_ready(),
        Cli::Unready => update_executor::mark_unready(),
    }
}

async fn validate(request_id: Uuid) -> Result<()> {
    let request_root = PathBuf::from(UPDATE_REQUEST_ROOT);
    let staging_root = PathBuf::from(UPDATE_STAGING_ROOT);
    let rollback_root = PathBuf::from(UPDATE_ROLLBACK_ROOT);
    let receipt_root = PathBuf::from(UPDATE_RECEIPT_ROOT);
    for (label, path) in [
        ("request root", &request_root),
        ("staging root", &staging_root),
        ("rollback root", &rollback_root),
        ("receipt root", &receipt_root),
    ] {
        validate_fixed_path(label, path)?;
    }
    let request_path = request_root.join(format!("{request_id}.json"));
    let request_bytes = read_confined_file(
        &request_root,
        &request_path,
        MAX_PRIVILEGED_REQUEST_BYTES,
        false,
    )?;
    let request: PrivilegedUpdateRequest = serde_json::from_slice(&request_bytes)
        .context("privileged update request is invalid")?;

    let trusted_keys =
        load_fixed_trusted_release_keys().context("release trust store could not be loaded")?;

    let receipt = match &request {
        PrivilegedUpdateRequest::Rollback { rollback, .. } => {
            let activation_id = rollback
                .activation_id
                .parse::<Uuid>()
                .context("rollback activation ID must be a UUID")?;
            let receipt_path = receipt_root.join(format!("{activation_id}.json"));
            let bytes = read_confined_file(
                &receipt_root,
                &receipt_path,
                MAX_RECEIPT_BYTES,
                true,
            )?;
            Some(
                serde_json::from_slice::<HelperActivationReceipt>(&bytes)
                    .context("activation receipt is invalid")?,
            )
        }
        PrivilegedUpdateRequest::Activate { .. } => None,
    };
    let now = current_unix_time()?;
    let plan = validate_privileged_request(
        &request,
        &trusted_keys,
        &staging_root,
        &rollback_root,
        receipt.as_ref(),
        now,
    )
    .await?;
    println!("{}", serde_json::to_string(&plan)?);
    Ok(())
}

pub(crate) fn read_confined_file(
    root: &Path,
    path: &Path,
    maximum: u64,
    require_root_owned: bool,
) -> Result<Vec<u8>> {
    let root = std::fs::canonicalize(root).context("helper input root could not be resolved")?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("helper input has no parent"))?;
    let parent = std::fs::canonicalize(parent).context("helper input parent could not be resolved")?;
    if parent != root {
        return Err(anyhow!("helper input escaped its configured root"));
    }
    read_fixed_file(path, maximum, require_root_owned)
}

pub(crate) fn read_fixed_file(
    path: &Path,
    maximum: u64,
    require_root_owned: bool,
) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux O_NOFOLLOW. Vexa-VM's supported hypervisor/helper platform is
        // Linux; opening the final component this way closes the symlink swap
        // race between metadata validation and read.
        options.custom_flags(0x0002_0000);
    }
    let file = options.open(path).context("helper input could not be opened")?;
    let metadata = file
        .metadata()
        .context("helper input metadata is unavailable")?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!("helper input is not a regular file"));
    }
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(anyhow!("helper input is outside its size limit"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            return Err(anyhow!("helper input must not be group/world writable"));
        }
        if require_root_owned && metadata.uid() != 0 {
            return Err(anyhow!("helper input must be root-owned"));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("helper input could not be read")?;
    if bytes.len() as u64 > maximum {
        return Err(anyhow!("helper input exceeded its size limit"));
    }
    Ok(bytes)
}

pub(crate) fn current_unix_time() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs()
        .try_into()
        .context("system clock is outside the supported range")
}

fn validate_fixed_path(label: &str, path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(anyhow!("{label} must be an absolute normalized path"));
    }
    Ok(())
}

fn usage() -> &'static str {
    "usage: vexa-update-helper validate|execute <request-uuid> | dispatch | ready | unready"
}
