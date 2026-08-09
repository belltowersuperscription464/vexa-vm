//! Signed release discovery and staging for Vexa-VM.
//!
//! This module deliberately does not execute installers, package managers, or
//! service-control commands. It verifies an Ed25519-signed release manifest,
//! stages bounded artifacts, and emits an approval-bound request for a small
//! privileged updater helper. Keeping discovery in the web process and
//! activation in a separately constrained helper prevents a compromised panel
//! account from turning the update feature into arbitrary command execution.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::StreamExt;
use reqwest::{
    header::{ACCEPT, ACCEPT_ENCODING, CONTENT_LENGTH, LOCATION},
    redirect::Policy,
    Response, StatusCode,
};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, RwLock},
};
use url::Url;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

pub const UPDATE_REPOSITORY: &str = "ItzGlace/vaxa-vm";
pub const RELEASE_MANIFEST_ASSET: &str = "vexa-vm-update-manifest.json";
pub const RELEASE_SIGNATURE_ASSET: &str = "vexa-vm-update-manifest.json.sig";
pub const UPDATE_REQUEST_ROOT: &str = "/var/lib/vexa-vm/updates/requests";
pub const UPDATE_STAGING_ROOT: &str = "/var/lib/vexa-vm/updates/staged";
pub const UPDATE_ROLLBACK_ROOT: &str = "/var/lib/vexa-vm/updates/rollback";
pub const UPDATE_STATUS_ROOT: &str = "/var/lib/vexa-vm/updates/status";
pub const UPDATE_RECEIPT_ROOT: &str = "/var/lib/vexa-vm/update-helper/receipts";
pub const UPDATE_TRUST_STORE_PATH: &str = "/etc/vexa-vm/update-trusted-keys.json";
pub const MAX_PRIVILEGED_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_TRUST_STORE_BYTES: u64 = 64 * 1024;

const RELEASE_API_URL: &str = "https://api.github.com/repos/ItzGlace/vaxa-vm/releases/latest";
const RELEASES_API_URL: &str =
    "https://api.github.com/repos/ItzGlace/vaxa-vm/releases?per_page=10";
const MAX_RELEASE_METADATA_BYTES: u64 = 512 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 4096;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ROLLBACK_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(90);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const UPDATE_APPROVAL_TTL_SECONDS: i64 = 15 * 60;
pub const PRIVILEGED_REQUEST_SCHEMA_VERSION: u32 = 1;
const MAX_DURABLE_STATUS_BYTES: u64 = 128 * 1024;
const MAX_DURABLE_STATUS_FILES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableUpdateOutcome {
    Running,
    Succeeded,
    Failed,
    RolledBack,
    NeedsIntervention,
}

impl DurableUpdateOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
            Self::NeedsIntervention => "needs_intervention",
        }
    }

    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurablePackageChangeStatus {
    pub component: String,
    pub package: String,
    pub previous_version: Option<String>,
    pub requested_version: String,
    pub applied: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableRollbackStatus {
    pub available: bool,
    pub attempted: bool,
    pub succeeded: bool,
    pub previous_release: Option<String>,
    pub snapshot_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRollbackPoint {
    pub activation_id: String,
    pub release: String,
    pub previous_release: String,
    pub manifest_sha256: String,
    pub snapshot_sha256: String,
    pub snapshot_size_bytes: u64,
    pub components: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableUpdateStatus {
    pub schema_version: u32,
    pub request_id: String,
    pub operation: Option<String>,
    pub release: Option<String>,
    pub phase: String,
    pub progress_percent: u8,
    pub outcome: DurableUpdateOutcome,
    pub message: String,
    pub started_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
    pub package_changes: Vec<DurablePackageChangeStatus>,
    pub rollback: DurableRollbackStatus,
    #[serde(default)]
    pub rollback_point: Option<PublicRollbackPoint>,
}

/// Read the root helper's public, non-secret status channel. Every path,
/// ownership bit, filename and bounded JSON field is revalidated because this
/// data drives panel rollback approval and audit import.
pub fn read_durable_update_statuses() -> AppResult<Vec<DurableUpdateStatus>> {
    let root = Path::new(UPDATE_STATUS_ROOT);
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AppError::Conflict(
            "durable update status root is not a safe directory".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(AppError::Conflict(
                "durable update status root has unsafe ownership or permissions".into(),
            ));
        }
    }

    let mut statuses = Vec::new();
    for entry in std::fs::read_dir(root)? {
        if statuses.len() >= MAX_DURABLE_STATUS_FILES {
            return Err(AppError::Conflict(
                "durable update status directory contains too many entries".into(),
            ));
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| AppError::Conflict("update status filename is invalid".into()))?;
        let Some(request_id) = name.strip_suffix(".json") else {
            continue;
        };
        Uuid::parse_str(request_id)
            .map_err(|_| AppError::Conflict("update status filename is invalid".into()))?;
        let path = entry.path();
        if path.parent() != Some(root) {
            return Err(AppError::Conflict("update status path escaped its root".into()));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x0002_0000); // Linux O_NOFOLLOW.
        }
        let file = options.open(&path)?;
        let file_metadata = file.metadata()?;
        if !file_metadata.file_type().is_file()
            || file_metadata.len() == 0
            || file_metadata.len() > MAX_DURABLE_STATUS_BYTES
        {
            return Err(AppError::Conflict("durable update status is invalid".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if file_metadata.uid() != 0 || file_metadata.mode() & 0o022 != 0 {
                return Err(AppError::Conflict(
                    "durable update status has unsafe ownership or permissions".into(),
                ));
            }
        }
        let mut bytes = Vec::with_capacity(file_metadata.len() as usize);
        file.take(MAX_DURABLE_STATUS_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_DURABLE_STATUS_BYTES {
            return Err(AppError::Conflict("durable update status is invalid".into()));
        }
        let status: DurableUpdateStatus = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::Conflict("durable update status JSON is invalid".into()))?;
        validate_durable_update_status(&status, request_id)?;
        statuses.push(status);
    }
    statuses.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            // Clearing an older activation's rollback point updates that
            // status in the same second as the rollback that consumed it.
            // Prefer the operation that actually started later for display;
            // rollback eligibility still fails closed on an updated-at tie.
            .then_with(|| right.started_at.cmp(&left.started_at))
            .then_with(|| right.request_id.cmp(&left.request_id))
    });
    Ok(statuses)
}

fn validate_durable_update_status(
    status: &DurableUpdateStatus,
    filename_request_id: &str,
) -> AppResult<()> {
    if status.schema_version != 1
        || status.request_id != filename_request_id
        || status.progress_percent > 100
        || status.phase.is_empty()
        || status.phase.len() > 64
        || status.message.len() > 512
        || status.phase.chars().any(char::is_control)
        || status.message.chars().any(char::is_control)
        || status.started_at <= 0
        || status.updated_at < status.started_at
        || status.package_changes.len() > 16
    {
        return Err(AppError::Conflict("durable update status is inconsistent".into()));
    }
    match (status.outcome.is_terminal(), status.completed_at) {
        (true, Some(completed))
            if completed >= status.started_at
                && completed <= status.updated_at
                && status.progress_percent == 100 => {}
        (false, None) => {}
        _ => {
            return Err(AppError::Conflict(
                "durable update status completion state is inconsistent".into(),
            ))
        }
    }
    if let Some(operation) = status.operation.as_deref() {
        if !matches!(operation, "activate" | "rollback" | "recover" | "recover_rollback") {
            return Err(AppError::Conflict(
                "durable update operation is unsupported".into(),
            ));
        }
    }
    if let Some(release) = status.release.as_deref() {
        ParsedVersion::parse(release)?;
    }
    for change in &status.package_changes {
        if change.component.is_empty()
            || change.component.len() > 32
            || change.package.is_empty()
            || change.package.len() > 128
            || change.requested_version.is_empty()
            || change.requested_version.len() > 256
            || change
                .previous_version
                .as_deref()
                .is_some_and(|value| {
                    value.is_empty()
                        || value.len() > 256
                        || value.chars().any(char::is_control)
                })
            || [&change.component, &change.package, &change.requested_version]
                .into_iter()
                .any(|value| value.chars().any(char::is_control))
        {
            return Err(AppError::Conflict(
                "durable package-change status is invalid".into(),
            ));
        }
    }
    if let Some(hash) = status.rollback.snapshot_sha256.as_deref() {
        if validate_sha256(hash)? != hash {
            return Err(AppError::Conflict(
                "durable rollback digest is not canonical".into(),
            ));
        }
    }
    if let Some(previous) = status.rollback.previous_release.as_deref() {
        ParsedVersion::parse(previous)?;
    }
    if (status.rollback.succeeded && !status.rollback.attempted)
        || (status.rollback.attempted && !status.rollback.available)
        || status.rollback.available
            != (status.rollback.previous_release.is_some()
                && status.rollback.snapshot_sha256.is_some())
    {
        return Err(AppError::Conflict(
            "durable rollback state is inconsistent".into(),
        ));
    }
    if let Some(point) = status.rollback_point.as_ref() {
        validate_uuid("rollback activation ID", &point.activation_id)?;
        if point.activation_id != status.request_id
            || status.operation.as_deref() != Some("activate")
            || status.outcome != DurableUpdateOutcome::Succeeded
            || !status.rollback.available
            || status.rollback.attempted
            || status.rollback.succeeded
            || status.release.as_deref() != Some(point.release.as_str())
            || status.rollback.previous_release.as_deref()
                != Some(point.previous_release.as_str())
            || status.rollback.snapshot_sha256.as_deref()
                != Some(point.snapshot_sha256.as_str())
            || point.snapshot_size_bytes == 0
            || point.snapshot_size_bytes > MAX_ROLLBACK_SNAPSHOT_BYTES
            || point.components.len() != 1
            || point.components.first().map(String::as_str) != Some("vexa-vm")
            || validate_sha256(&point.manifest_sha256)? != point.manifest_sha256
            || validate_sha256(&point.snapshot_sha256)? != point.snapshot_sha256
        {
            return Err(AppError::Conflict(
                "durable rollback point is invalid".into(),
            ));
        }
        ParsedVersion::parse(&point.release)?;
        ParsedVersion::parse(&point.previous_release)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateComponent {
    VexaVm,
    Qemu,
    Libvirt,
}

impl UpdateComponent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VexaVm => "vexa-vm",
            Self::Qemu => "qemu",
            Self::Libvirt => "libvirt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Apt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemPackage {
    pub name: String,
    pub candidate_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ComponentDelivery {
    SignedArchive {
        url: String,
        sha256: String,
        size_bytes: u64,
        target: String,
    },
    SystemPackages {
        manager: PackageManager,
        packages: Vec<SystemPackage>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRelease {
    pub component: UpdateComponent,
    pub version: String,
    pub delivery: ComponentDelivery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub schema_version: u32,
    pub repository: String,
    pub release: String,
    pub published_at: i64,
    pub components: Vec<ComponentRelease>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachedSignature {
    algorithm: String,
    key_id: String,
    signature: String,
}

#[derive(Clone, Debug)]
pub struct TrustedReleaseKeys {
    keys: BTreeMap<String, Vec<u8>>,
}

impl TrustedReleaseKeys {
    /// Construct a trust store from base64-encoded, raw 32-byte Ed25519 public
    /// keys. The key IDs are public labels and are recorded in the audit trail.
    pub fn new(keys: impl IntoIterator<Item = (String, String)>) -> AppResult<Self> {
        let mut trusted = BTreeMap::new();
        for (key_id, encoded) in keys {
            validate_identifier("release signing key ID", &key_id, 128)?;
            let key = BASE64.decode(encoded.trim()).map_err(|_| {
                AppError::Configuration(format!(
                    "release signing key {key_id} is not valid base64"
                ))
            })?;
            if key.len() != 32 {
                return Err(AppError::Configuration(format!(
                    "release signing key {key_id} must be a raw 32-byte Ed25519 public key"
                )));
            }
            if trusted.insert(key_id.clone(), key).is_some() {
                return Err(AppError::Configuration(format!(
                    "release signing key ID {key_id} is duplicated"
                )));
            }
        }
        if trusted.is_empty() {
            return Err(AppError::Configuration(
                "at least one trusted release signing key is required".into(),
            ));
        }
        Ok(Self { keys: trusted })
    }

    fn get(&self, key_id: &str) -> Option<&[u8]> {
        self.keys.get(key_id).map(Vec::as_slice)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifiedRelease {
    pub tag: String,
    pub html_url: String,
    pub signer_key_id: String,
    pub manifest_sha256: String,
    pub manifest: UpdateManifest,
    #[serde(skip)]
    manifest_bytes: Vec<u8>,
    #[serde(skip)]
    signature_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateCheck {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release: VerifiedRelease,
}

#[derive(Clone, Debug, Serialize)]
pub struct StagedArtifact {
    pub component: UpdateComponent,
    pub version: String,
    pub release: String,
    pub manifest_sha256: String,
    pub signer_key_id: String,
    #[serde(skip_serializing)]
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateApproval {
    pub approved_by: String,
    pub release: String,
    pub manifest_sha256: String,
    pub components: BTreeSet<UpdateComponent>,
    pub maintenance_impact_accepted: bool,
    pub approved_at: i64,
}

impl UpdateApproval {
    pub fn now(
        approved_by: impl Into<String>,
        release: impl Into<String>,
        manifest_sha256: impl Into<String>,
        components: BTreeSet<UpdateComponent>,
        maintenance_impact_accepted: bool,
    ) -> AppResult<Self> {
        Ok(Self {
            approved_by: approved_by.into(),
            release: release.into(),
            manifest_sha256: manifest_sha256.into(),
            components,
            maintenance_impact_accepted,
            approved_at: current_unix_time()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovedComponentAction {
    InstallStagedArchive {
        component: UpdateComponent,
        version: String,
        staged_path: PathBuf,
        sha256: String,
        size_bytes: u64,
    },
    UpgradeSystemPackages {
        component: UpdateComponent,
        version: String,
        manager: PackageManager,
        packages: Vec<SystemPackage>,
    },
}

/// A fully verified, approval-bound description for a separately sandboxed
/// privileged helper. Merely creating this value performs no host mutation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequest {
    pub id: String,
    pub repository: String,
    pub release: String,
    pub manifest_sha256: String,
    pub signer_key_id: String,
    pub approved_by: String,
    pub approved_at: i64,
    pub expires_at: i64,
    pub maintenance_impact_accepted: bool,
    pub actions: Vec<ApprovedComponentAction>,
    pub requires_privileged_helper: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPoint {
    pub activation_id: String,
    pub release: String,
    pub previous_release: String,
    pub manifest_sha256: String,
    #[serde(skip_serializing)]
    pub snapshot_path: PathBuf,
    pub snapshot_sha256: String,
    pub snapshot_size_bytes: u64,
    pub components: BTreeSet<UpdateComponent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RollbackApproval {
    pub approved_by: String,
    pub activation_id: String,
    pub previous_release: String,
    pub maintenance_impact_accepted: bool,
    pub approved_at: i64,
}

impl RollbackApproval {
    pub fn now(
        approved_by: impl Into<String>,
        activation_id: impl Into<String>,
        previous_release: impl Into<String>,
        maintenance_impact_accepted: bool,
    ) -> AppResult<Self> {
        Ok(Self {
            approved_by: approved_by.into(),
            activation_id: activation_id.into(),
            previous_release: previous_release.into(),
            maintenance_impact_accepted,
            approved_at: current_unix_time()?,
        })
    }
}

/// An approval-bound rollback description. A privileged helper must rehash the
/// snapshot and validate its own allowlisted install paths before activation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub id: String,
    pub activation_id: String,
    pub release: String,
    pub restore_release: String,
    pub manifest_sha256: String,
    pub snapshot_path: PathBuf,
    pub snapshot_sha256: String,
    pub snapshot_size_bytes: u64,
    pub components: BTreeSet<UpdateComponent>,
    pub approved_by: String,
    pub approved_at: i64,
    pub expires_at: i64,
    pub maintenance_impact_accepted: bool,
    pub requires_privileged_helper: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedReleaseKey {
    pub key_id: String,
    pub public_key_base64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedReleaseKeyStore {
    pub schema_version: u32,
    pub keys: Vec<TrustedReleaseKey>,
}

impl TrustedReleaseKeyStore {
    pub fn into_trusted_keys(self) -> AppResult<TrustedReleaseKeys> {
        if self.schema_version != 1 {
            return Err(AppError::Configuration(
                "release trust-store schema is not supported".into(),
            ));
        }
        if self.keys.len() > 8 {
            return Err(AppError::Configuration(
                "release trust store contains too many keys".into(),
            ));
        }
        TrustedReleaseKeys::new(
            self.keys
                .into_iter()
                .map(|key| (key.key_id, key.public_key_base64)),
        )
    }
}

/// Load the public release trust roots from the helper's fixed path. Public
/// keys are intentionally readable by the panel, but only root may replace
/// them. The private signing key is never present on a managed node.
pub fn load_fixed_trusted_release_keys() -> AppResult<TrustedReleaseKeys> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x0002_0000); // Linux O_NOFOLLOW.
    }
    let file = options.open(UPDATE_TRUST_STORE_PATH)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_TRUST_STORE_BYTES
    {
        return Err(AppError::Configuration(
            "release trust store is not a bounded regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(AppError::Configuration(
                "release trust store must be root-owned and not group/world writable".into(),
            ));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut limited = std::io::Read::take(file, MAX_TRUST_STORE_BYTES.saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut bytes)?;
    if bytes.len() as u64 > MAX_TRUST_STORE_BYTES {
        return Err(AppError::Configuration(
            "release trust store exceeded its size limit".into(),
        ));
    }
    serde_json::from_slice::<TrustedReleaseKeyStore>(&bytes)
        .map_err(|_| AppError::Configuration("release trust store is invalid".into()))?
        .into_trusted_keys()
}

/// Bounded data transferred from the unprivileged panel to the root-owned
/// helper. It contains no command, executable path, package repository, or
/// caller-selected network URL.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivilegedUpdateRequest {
    Activate {
        schema_version: u32,
        activation: ActivationRequest,
        manifest_base64: String,
        detached_signature_base64: String,
    },
    Rollback {
        schema_version: u32,
        rollback: RollbackRequest,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelperActivationReceipt {
    pub schema_version: u32,
    pub activation_id: String,
    pub release: String,
    pub previous_release: String,
    pub manifest_sha256: String,
    pub snapshot_path: PathBuf,
    pub snapshot_sha256: String,
    pub snapshot_size_bytes: u64,
    pub components: BTreeSet<UpdateComponent>,
    pub completed_at: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValidatedHelperPlan {
    Activate {
        activation_id: String,
        release: String,
        manifest_sha256: String,
        signer_key_id: String,
        approved_by: String,
        actions: Vec<ApprovedComponentAction>,
    },
    Rollback {
        request_id: String,
        activation_id: String,
        release: String,
        restore_release: String,
        snapshot_path: PathBuf,
        snapshot_sha256: String,
        snapshot_size_bytes: u64,
        components: BTreeSet<UpdateComponent>,
        approved_by: String,
    },
}

impl VerifiedRelease {
    pub fn privileged_activation_request(
        &self,
        activation: ActivationRequest,
    ) -> AppResult<PrivilegedUpdateRequest> {
        if activation.release != self.tag
            || activation.manifest_sha256 != self.manifest_sha256
            || activation.signer_key_id != self.signer_key_id
        {
            return Err(AppError::Conflict(
                "activation does not belong to this verified release".into(),
            ));
        }
        Ok(PrivilegedUpdateRequest::Activate {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            activation,
            manifest_base64: BASE64.encode(&self.manifest_bytes),
            detached_signature_base64: BASE64.encode(&self.signature_bytes),
        })
    }
}

pub fn privileged_rollback_request(rollback: RollbackRequest) -> PrivilegedUpdateRequest {
    PrivilegedUpdateRequest::Rollback {
        schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
        rollback,
    }
}

/// Atomically places a validated-shape request in the helper's fixed spool.
/// The caller still has to record approval/audit state and invoke the helper
/// through a separately configured privilege boundary.
#[derive(Clone, Debug)]
pub struct PrivilegedRequestSpool {
    root: PathBuf,
}

impl PrivilegedRequestSpool {
    pub fn fixed() -> Self {
        Self {
            root: PathBuf::from(UPDATE_REQUEST_ROOT),
        }
    }

    #[cfg(test)]
    fn for_test(root: impl Into<PathBuf>) -> AppResult<Self> {
        let root = root.into();
        validate_helper_root("update request root", &root)?;
        Ok(Self { root })
    }

    pub async fn store(&self, request: &PrivilegedUpdateRequest) -> AppResult<Uuid> {
        let request_id = match request {
            PrivilegedUpdateRequest::Activate { activation, .. } => &activation.id,
            PrivilegedUpdateRequest::Rollback { rollback, .. } => &rollback.id,
        };
        let request_id = Uuid::parse_str(request_id)
            .map_err(|_| AppError::Validation("privileged request ID must be a UUID".into()))?;
        let bytes = serde_json::to_vec(request)
            .map_err(|_| AppError::Internal("privileged update request could not be encoded".into()))?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_PRIVILEGED_REQUEST_BYTES {
            return Err(AppError::Validation(
                "privileged update request exceeded its size limit".into(),
            ));
        }

        tokio::fs::create_dir_all(&self.root).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(
                &self.root,
                std::fs::Permissions::from_mode(0o700),
            )
            .await?;
        }
        let root = tokio::fs::canonicalize(&self.root).await?;
        if !tokio::fs::metadata(&root).await?.is_dir() {
            return Err(AppError::Configuration(
                "update request root must be a directory".into(),
            ));
        }
        let final_path = root.join(format!("{request_id}.json"));
        let temporary_path = root.join(format!(".{request_id}.{}.tmp", Uuid::new_v4()));
        let cleanup = TemporaryRequestCleanup(temporary_path.clone());
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&temporary_path)?;
        let mut file = tokio::fs::File::from_std(file);
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        drop(file);
        match tokio::fs::hard_link(&temporary_path, &final_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(AppError::Conflict(
                    "privileged update request already exists".into(),
                ));
            }
            Err(error) => return Err(error.into()),
        }
        drop(cleanup);
        // The file contents were synced before publication; syncing the
        // directory makes the no-clobber hard-link publication durable too.
        std::fs::File::open(&root)?.sync_all()?;
        Ok(request_id)
    }
}

struct TemporaryRequestCleanup(PathBuf);

impl Drop for TemporaryRequestCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StagedComponentStatus {
    pub component: UpdateComponent,
    pub version: String,
    pub release: String,
    pub manifest_sha256: String,
    pub signer_key_id: String,
    pub size_bytes: u64,
    pub sha256: String,
}

impl From<&StagedArtifact> for StagedComponentStatus {
    fn from(artifact: &StagedArtifact) -> Self {
        Self {
            component: artifact.component,
            version: artifact.version.clone(),
            release: artifact.release.clone(),
            manifest_sha256: artifact.manifest_sha256.clone(),
            signer_key_id: artifact.signer_key_id.clone(),
            size_bytes: artifact.size_bytes,
            sha256: artifact.sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateCoordinatorSnapshot {
    pub current_version: Option<String>,
    pub checked_at: Option<i64>,
    pub release: Option<VerifiedRelease>,
    pub staged: Vec<StagedComponentStatus>,
    pub last_queued_request_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueuedUpdateRequest {
    pub request_id: String,
    pub release: String,
    pub components: BTreeSet<UpdateComponent>,
    pub expires_at: i64,
    pub rollback: bool,
}

#[derive(Default)]
struct UpdateCoordinatorState {
    current_version: Option<String>,
    checked_at: Option<i64>,
    release: Option<VerifiedRelease>,
    staged: BTreeMap<UpdateComponent, StagedArtifact>,
    last_queued_request_id: Option<String>,
}

/// Serializes release checks, staging and approval against one verified
/// manifest. This prevents one administrator from approving artifacts cached
/// for a release that another administrator replaced with a newer check.
pub struct UpdateCoordinator {
    updater: ReleaseUpdater,
    spool: PrivilegedRequestSpool,
    operation_lock: Mutex<()>,
    state: RwLock<UpdateCoordinatorState>,
}

impl UpdateCoordinator {
    pub fn fixed(updater: ReleaseUpdater) -> Self {
        Self {
            updater,
            spool: PrivilegedRequestSpool::fixed(),
            operation_lock: Mutex::new(()),
            state: RwLock::new(UpdateCoordinatorState::default()),
        }
    }

    pub async fn snapshot(&self) -> UpdateCoordinatorSnapshot {
        let state = self.state.read().await;
        UpdateCoordinatorSnapshot {
            current_version: state.current_version.clone(),
            checked_at: state.checked_at,
            release: state.release.clone(),
            staged: state
                .staged
                .values()
                .map(StagedComponentStatus::from)
                .collect(),
            last_queued_request_id: state.last_queued_request_id.clone(),
        }
    }

    pub async fn check_latest(
        &self,
        current_version: &str,
    ) -> AppResult<UpdateCheck> {
        let checked_at = current_unix_time()?;
        let _operation = self.operation_lock.lock().await;
        let check = self.updater.check_latest(current_version).await?;
        let stale = {
            let mut state = self.state.write().await;
            let release_changed = state.release.as_ref().is_some_and(|release| {
                release.manifest_sha256 != check.release.manifest_sha256
            });
            let stale = if release_changed {
                std::mem::take(&mut state.staged)
            } else {
                BTreeMap::new()
            };
            state.current_version = Some(check.current_version.clone());
            state.checked_at = Some(checked_at);
            state.release = Some(check.release.clone());
            stale
        };
        for artifact in stale.into_values() {
            if let Err(error) = self.updater.discard_staged_artifact(&artifact).await {
                tracing::warn!(error = %error, "could not remove stale staged update artifact");
            }
        }
        Ok(check)
    }

    pub async fn stage_component(
        &self,
        manifest_sha256: &str,
        component: UpdateComponent,
    ) -> AppResult<StagedComponentStatus> {
        let _operation = self.operation_lock.lock().await;
        let (release, current_version, existing) = {
            let state = self.state.read().await;
            (
                state
                    .release
                    .clone()
                    .ok_or_else(|| AppError::NotFound("verified update check".into()))?,
                state
                    .current_version
                    .clone()
                    .ok_or_else(|| AppError::NotFound("current application version".into()))?,
                state.staged.get(&component).cloned(),
            )
        };
        if release.manifest_sha256 != manifest_sha256 {
            return Err(AppError::Conflict(
                "staging request does not match the current verified release".into(),
            ));
        }
        ensure_application_release_order(&release, &current_version, true)?;
        if let Some(existing) = existing {
            if self.updater.verify_staged_artifact(&existing).await.is_ok() {
                return Ok(StagedComponentStatus::from(&existing));
            }
            self.state.write().await.staged.remove(&component);
            let _ = self.updater.discard_staged_artifact(&existing).await;
        }
        let artifact = self.updater.stage_component(&release, component).await?;
        let status = StagedComponentStatus::from(&artifact);
        self.state.write().await.staged.insert(component, artifact);
        Ok(status)
    }

    pub async fn queue_activation(
        &self,
        approved_by: &str,
        expected_release: &str,
        expected_manifest_sha256: &str,
        components: BTreeSet<UpdateComponent>,
        maintenance_impact_accepted: bool,
    ) -> AppResult<QueuedUpdateRequest> {
        let _operation = self.operation_lock.lock().await;
        let (release, current_version, staged) = {
            let state = self.state.read().await;
            (
                state
                    .release
                    .clone()
                    .ok_or_else(|| AppError::NotFound("verified update check".into()))?,
                state
                    .current_version
                    .clone()
                    .ok_or_else(|| AppError::NotFound("current application version".into()))?,
                state.staged.values().cloned().collect::<Vec<_>>(),
            )
        };
        ensure_application_release_order(
            &release,
            &current_version,
            components.contains(&UpdateComponent::VexaVm),
        )?;
        let approval = UpdateApproval::now(
            approved_by,
            expected_release,
            expected_manifest_sha256,
            components,
            maintenance_impact_accepted,
        )?;
        let activation = self
            .updater
            .build_activation_request(&release, &staged, &approval)
            .await?;
        let expires_at = activation.expires_at;
        let components = approval.components.clone();
        let request = release.privileged_activation_request(activation)?;
        let request_id = self.spool.store(&request).await?;
        self.state.write().await.last_queued_request_id = Some(request_id.to_string());
        Ok(QueuedUpdateRequest {
            request_id: request_id.to_string(),
            release: release.tag,
            components,
            expires_at,
            rollback: false,
        })
    }

    pub async fn queue_rollback(
        &self,
        point: &RollbackPoint,
        approved_by: &str,
        expected_activation_id: &str,
        expected_previous_release: &str,
        maintenance_impact_accepted: bool,
    ) -> AppResult<QueuedUpdateRequest> {
        let _operation = self.operation_lock.lock().await;
        let approval = RollbackApproval::now(
            approved_by,
            expected_activation_id,
            expected_previous_release,
            maintenance_impact_accepted,
        )?;
        let rollback = self.updater.build_rollback_request(point, &approval)?;
        let expires_at = rollback.expires_at;
        let release = rollback.restore_release.clone();
        let components = rollback.components.clone();
        let request = privileged_rollback_request(rollback);
        let request_id = self.spool.store(&request).await?;
        self.state.write().await.last_queued_request_id = Some(request_id.to_string());
        Ok(QueuedUpdateRequest {
            request_id: request_id.to_string(),
            release,
            components,
            expires_at,
            rollback: true,
        })
    }
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

#[derive(Clone)]
pub struct ReleaseUpdater {
    client: reqwest::Client,
    staging_root: PathBuf,
    trusted_keys: TrustedReleaseKeys,
    allow_prereleases: bool,
}

impl ReleaseUpdater {
    pub fn new(
        staging_root: impl Into<PathBuf>,
        trusted_keys: TrustedReleaseKeys,
        allow_prereleases: bool,
    ) -> AppResult<Self> {
        let staging_root = staging_root.into();
        if !staging_root.is_absolute()
            || staging_root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(AppError::Configuration(
                "release staging root must be an absolute normalized path".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .https_only(true)
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("vexa-vm/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| AppError::Internal("release update client could not be built".into()))?;
        Ok(Self {
            client,
            staging_root,
            trusted_keys,
            allow_prereleases,
        })
    }

    /// Discover and authenticate the newest GitHub release. This performs no
    /// downloads other than the small release metadata, manifest, and detached
    /// signature.
    pub async fn check_latest(&self, current_version: &str) -> AppResult<UpdateCheck> {
        let current = ParsedVersion::parse(current_version)?;
        let api_url = Url::parse(if self.allow_prereleases {
            RELEASES_API_URL
        } else {
            RELEASE_API_URL
        })
            .map_err(|_| AppError::Internal("release API URL is invalid".into()))?;
        let metadata = self
            .fetch_bounded(api_url, MAX_RELEASE_METADATA_BYTES, UrlPurpose::Api)
            .await?;
        let release: GitHubRelease = if self.allow_prereleases {
            let releases: Vec<GitHubRelease> = serde_json::from_slice(&metadata)
                .map_err(|_| AppError::Conflict("GitHub release metadata was invalid".into()))?;
            if releases.len() > 10 {
                return Err(AppError::Conflict(
                    "GitHub returned too many release records".into(),
                ));
            }
            releases
                .into_iter()
                .find(|release| !release.draft)
                .ok_or_else(|| AppError::NotFound("published GitHub release".into()))?
        } else {
            serde_json::from_slice(&metadata)
                .map_err(|_| AppError::Conflict("GitHub release metadata was invalid".into()))?
        };
        if release.draft {
            return Err(AppError::Conflict("the latest GitHub release is still a draft".into()));
        }
        if release.prerelease && !self.allow_prereleases {
            return Err(AppError::Conflict(
                "the latest GitHub release is a prerelease and this node follows stable releases".into(),
            ));
        }
        ParsedVersion::parse(&release.tag_name)?;
        validate_release_page_url(&release.html_url, &release.tag_name)?;

        let manifest_asset = required_asset(&release.assets, RELEASE_MANIFEST_ASSET)?;
        let signature_asset = required_asset(&release.assets, RELEASE_SIGNATURE_ASSET)?;
        if manifest_asset.size > MAX_MANIFEST_BYTES || signature_asset.size > MAX_SIGNATURE_BYTES {
            return Err(AppError::Conflict("release verification assets are unexpectedly large".into()));
        }
        let manifest_url = validate_release_asset_url(&manifest_asset.browser_download_url, &release.tag_name)?;
        let signature_url = validate_release_asset_url(&signature_asset.browser_download_url, &release.tag_name)?;
        if asset_filename(&manifest_url) != Some(RELEASE_MANIFEST_ASSET)
            || asset_filename(&signature_url) != Some(RELEASE_SIGNATURE_ASSET)
        {
            return Err(AppError::Conflict(
                "release verification asset names do not match their GitHub URLs".into(),
            ));
        }
        let manifest_bytes = self
            .fetch_bounded(manifest_url, MAX_MANIFEST_BYTES, UrlPurpose::Asset)
            .await?;
        let signature_bytes = self
            .fetch_bounded(signature_url, MAX_SIGNATURE_BYTES, UrlPurpose::Asset)
            .await?;
        let mut verified = verify_release_manifest(
            &manifest_bytes,
            &signature_bytes,
            &self.trusted_keys,
            &release.tag_name,
        )?;
        validate_manifest_assets(&verified.manifest, &release.assets)?;
        verified.html_url = release.html_url;

        let latest_component = verified
            .manifest
            .components
            .iter()
            .find(|component| component.component == UpdateComponent::VexaVm)
            .ok_or_else(|| AppError::Conflict("release manifest has no Vexa-VM component".into()))?;
        let latest = ParsedVersion::parse(&latest_component.version)?;
        Ok(UpdateCheck {
            current_version: current_version.trim_start_matches('v').to_owned(),
            latest_version: latest_component.version.clone(),
            update_available: latest > current,
            release: verified,
        })
    }

    /// Download and hash the signed Vexa-VM archive into the staging directory.
    /// QEMU and libvirt are distro-owned packages and therefore never enter the
    /// arbitrary-artifact staging path.
    pub async fn stage_component(
        &self,
        release: &VerifiedRelease,
        component: UpdateComponent,
    ) -> AppResult<StagedArtifact> {
        let entry = release
            .manifest
            .components
            .iter()
            .find(|entry| entry.component == component)
            .ok_or_else(|| AppError::NotFound(format!("{} update", component.as_str())))?;
        let ComponentDelivery::SignedArchive {
            url,
            sha256,
            size_bytes,
            ..
        } = &entry.delivery
        else {
            return Err(AppError::Validation(format!(
                "{} is managed by the operating-system package manager and has no downloadable archive",
                component.as_str()
            )));
        };
        if component != UpdateComponent::VexaVm {
            return Err(AppError::Validation(
                "only Vexa-VM release archives may be staged".into(),
            ));
        }
        let url = validate_release_asset_url(url, &release.tag)?;
        let expected_sha256 = validate_sha256(sha256)?;
        let expected_size = *size_bytes;
        if expected_size == 0 || expected_size > MAX_ARTIFACT_BYTES {
            return Err(AppError::Validation(
                "release artifact size must be between 1 byte and 512 MiB".into(),
            ));
        }

        tokio::fs::create_dir_all(&self.staging_root).await?;
        let staging_root = tokio::fs::canonicalize(&self.staging_root).await?;
        if !tokio::fs::metadata(&staging_root).await?.is_dir() {
            return Err(AppError::Configuration(
                "release staging root must be a directory".into(),
            ));
        }
        let basename = format!(
            "{}-{}-{}.tar.gz",
            component.as_str(),
            entry.version,
            Uuid::new_v4()
        );
        let final_path = staging_root.join(&basename);
        let partial_path = staging_root.join(format!("{basename}.part"));
        let mut cleanup = StagedFileCleanup::new(&partial_path, &final_path);

        let (size_bytes, sha256) = self
            .download_artifact(
                url,
                &partial_path,
                &final_path,
                expected_size,
                &expected_sha256,
            )
            .await?;
        cleanup.retain();
        Ok(StagedArtifact {
            component,
            version: entry.version.clone(),
            release: release.tag.clone(),
            manifest_sha256: release.manifest_sha256.clone(),
            signer_key_id: release.signer_key_id.clone(),
            path: final_path,
            size_bytes,
            sha256,
        })
    }

    /// Re-open and rehash a staged artifact immediately before handing it to
    /// the privileged helper. The helper must repeat the same verification.
    pub async fn verify_staged_artifact(&self, artifact: &StagedArtifact) -> AppResult<()> {
        let root = tokio::fs::canonicalize(&self.staging_root).await?;
        let metadata = tokio::fs::symlink_metadata(&artifact.path).await?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(AppError::Conflict(
                "staged update artifact is not a regular file".into(),
            ));
        }
        let path = tokio::fs::canonicalize(&artifact.path).await?;
        if path.parent() != Some(root.as_path()) {
            return Err(AppError::Conflict(
                "staged update artifact escaped the staging directory".into(),
            ));
        }
        let (size, sha256) = hash_file(&path, MAX_ARTIFACT_BYTES).await?;
        if size != artifact.size_bytes || sha256 != artifact.sha256 {
            return Err(AppError::Conflict(
                "staged update artifact no longer matches its verified digest".into(),
            ));
        }
        Ok(())
    }

    async fn discard_staged_artifact(&self, artifact: &StagedArtifact) -> AppResult<()> {
        let root = tokio::fs::canonicalize(&self.staging_root).await?;
        let metadata = tokio::fs::symlink_metadata(&artifact.path).await?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(AppError::Conflict(
                "staged update artifact is not a regular file".into(),
            ));
        }
        let path = tokio::fs::canonicalize(&artifact.path).await?;
        if path.parent() != Some(root.as_path()) {
            return Err(AppError::Conflict(
                "staged update artifact escaped the staging directory".into(),
            ));
        }
        tokio::fs::remove_file(path).await?;
        Ok(())
    }

    /// Bind selected, already-verified components to an explicit administrator
    /// approval. The result is data only; this process never executes it.
    pub async fn build_activation_request(
        &self,
        release: &VerifiedRelease,
        staged: &[StagedArtifact],
        approval: &UpdateApproval,
    ) -> AppResult<ActivationRequest> {
        validate_identifier("approving administrator", &approval.approved_by, 256)?;
        if approval.approved_at <= 0 {
            return Err(AppError::Validation(
                "update approval time is invalid".into(),
            ));
        }
        if !approval.maintenance_impact_accepted {
            return Err(AppError::Validation(
                "the administrator must accept the update maintenance impact".into(),
            ));
        }
        if approval.release != release.tag || approval.manifest_sha256 != release.manifest_sha256 {
            return Err(AppError::Conflict(
                "update approval does not match the verified release manifest".into(),
            ));
        }
        if approval.components.is_empty() {
            return Err(AppError::Validation(
                "at least one update component must be selected".into(),
            ));
        }

        let mut actions = Vec::with_capacity(approval.components.len());
        for component in &approval.components {
            let entry = release
                .manifest
                .components
                .iter()
                .find(|entry| entry.component == *component)
                .ok_or_else(|| AppError::NotFound(format!("{} update", component.as_str())))?;
            match &entry.delivery {
                ComponentDelivery::SignedArchive { .. } => {
                    let artifact = staged
                        .iter()
                        .find(|artifact| artifact.component == *component)
                        .ok_or_else(|| {
                            AppError::Conflict(format!(
                                "{} was approved but its archive is not staged",
                                component.as_str()
                            ))
                        })?;
                    if artifact.release != release.tag
                        || artifact.manifest_sha256 != release.manifest_sha256
                        || artifact.signer_key_id != release.signer_key_id
                        || artifact.version != entry.version
                    {
                        return Err(AppError::Conflict(
                            "staged artifact does not belong to the approved release".into(),
                        ));
                    }
                    self.verify_staged_artifact(artifact).await?;
                    actions.push(ApprovedComponentAction::InstallStagedArchive {
                        component: *component,
                        version: entry.version.clone(),
                        staged_path: artifact.path.clone(),
                        sha256: artifact.sha256.clone(),
                        size_bytes: artifact.size_bytes,
                    });
                }
                ComponentDelivery::SystemPackages { manager, packages } => {
                    actions.push(ApprovedComponentAction::UpgradeSystemPackages {
                        component: *component,
                        version: entry.version.clone(),
                        manager: *manager,
                        packages: packages.clone(),
                    });
                }
            }
        }
        let expires_at = approval
            .approved_at
            .checked_add(UPDATE_APPROVAL_TTL_SECONDS)
            .ok_or_else(|| AppError::Validation("update approval time is invalid".into()))?;
        Ok(ActivationRequest {
            id: Uuid::new_v4().to_string(),
            repository: UPDATE_REPOSITORY.into(),
            release: release.tag.clone(),
            manifest_sha256: release.manifest_sha256.clone(),
            signer_key_id: release.signer_key_id.clone(),
            approved_by: approval.approved_by.clone(),
            approved_at: approval.approved_at,
            expires_at,
            maintenance_impact_accepted: true,
            actions,
            requires_privileged_helper: true,
        })
    }

    pub fn build_rollback_request(
        &self,
        point: &RollbackPoint,
        approval: &RollbackApproval,
    ) -> AppResult<RollbackRequest> {
        validate_identifier("approving administrator", &approval.approved_by, 256)?;
        validate_uuid("activation ID", &point.activation_id)?;
        if approval.approved_at <= 0 {
            return Err(AppError::Validation(
                "rollback approval time is invalid".into(),
            ));
        }
        validate_sha256(&point.manifest_sha256)?;
        validate_sha256(&point.snapshot_sha256)?;
        if point.snapshot_size_bytes == 0
            || point.snapshot_size_bytes > MAX_ROLLBACK_SNAPSHOT_BYTES
        {
            return Err(AppError::Validation(
                "rollback snapshot is outside the supported size limit".into(),
            ));
        }
        if !point.snapshot_path.is_absolute() {
            return Err(AppError::Validation(
                "rollback snapshot path must be absolute".into(),
            ));
        }
        if point
            .snapshot_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(AppError::Validation(
                "rollback snapshot path must be normalized".into(),
            ));
        }
        if point.components.is_empty() {
            return Err(AppError::Validation(
                "rollback point contains no components".into(),
            ));
        }
        if !approval.maintenance_impact_accepted {
            return Err(AppError::Validation(
                "the administrator must accept the rollback maintenance impact".into(),
            ));
        }
        if approval.activation_id != point.activation_id
            || approval.previous_release != point.previous_release
        {
            return Err(AppError::Conflict(
                "rollback approval does not match the selected rollback point".into(),
            ));
        }
        let expires_at = approval
            .approved_at
            .checked_add(UPDATE_APPROVAL_TTL_SECONDS)
            .ok_or_else(|| AppError::Validation("rollback approval time is invalid".into()))?;
        Ok(RollbackRequest {
            id: Uuid::new_v4().to_string(),
            activation_id: point.activation_id.clone(),
            release: point.release.clone(),
            restore_release: point.previous_release.clone(),
            manifest_sha256: point.manifest_sha256.clone(),
            snapshot_path: point.snapshot_path.clone(),
            snapshot_sha256: point.snapshot_sha256.clone(),
            snapshot_size_bytes: point.snapshot_size_bytes,
            components: point.components.clone(),
            approved_by: approval.approved_by.clone(),
            approved_at: approval.approved_at,
            expires_at,
            maintenance_impact_accepted: true,
            requires_privileged_helper: true,
        })
    }

    async fn fetch_bounded(&self, url: Url, maximum: u64, purpose: UrlPurpose) -> AppResult<Vec<u8>> {
        let response = self.follow_redirects(url, purpose).await?;
        if response.content_length().is_some_and(|size| size > maximum) {
            return Err(AppError::Conflict("release response exceeded its size limit".into()));
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        let mut received = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| AppError::Conflict("release response stream failed".into()))?;
            received = received
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| AppError::Conflict("release response exceeded its size limit".into()))?;
            if received > maximum {
                return Err(AppError::Conflict("release response exceeded its size limit".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn follow_redirects(&self, mut url: Url, mut purpose: UrlPurpose) -> AppResult<Response> {
        for redirect_count in 0..=MAX_REDIRECTS {
            validate_github_url(&url, purpose)?;
            let response = self
                .client
                .get(url.clone())
                .header(ACCEPT, "application/vnd.github+json")
                .header(ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(|error| {
                    if error.is_timeout() {
                        AppError::Conflict("release request timed out".into())
                    } else {
                        AppError::Conflict("release request failed".into())
                    }
                })?;
            if is_redirect(response.status()) {
                if redirect_count == MAX_REDIRECTS {
                    return Err(AppError::Conflict(
                        "release request exceeded five redirects".into(),
                    ));
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| AppError::Conflict("release redirect has no location".into()))?
                    .to_str()
                    .map_err(|_| AppError::Conflict("release redirect was invalid".into()))?;
                url = url
                    .join(location)
                    .map_err(|_| AppError::Conflict("release redirect was invalid".into()))?;
                purpose = UrlPurpose::Redirect;
                continue;
            }
            if !response.status().is_success() {
                return Err(AppError::Conflict(format!(
                    "release server returned HTTP {}",
                    response.status().as_u16()
                )));
            }
            return Ok(response);
        }
        Err(AppError::Internal("release redirect handling failed".into()))
    }

    async fn download_artifact(
        &self,
        url: Url,
        partial_path: &Path,
        final_path: &Path,
        expected_size: u64,
        expected_sha256: &str,
    ) -> AppResult<(u64, String)> {
        let response = self.follow_redirects(url, UrlPurpose::Asset).await?;
        let declared_size = response.content_length().or_else(|| {
            response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
        });
        if declared_size.is_some_and(|size| size != expected_size) {
            return Err(AppError::Conflict(
                "release artifact Content-Length did not match the signed manifest".into(),
            ));
        }
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(partial_path)?;
        let mut file = tokio::fs::File::from_std(file);
        let mut digest = Sha256::new();
        let mut size = 0_u64;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| AppError::Conflict("release artifact stream failed".into()))?;
            size = size
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| AppError::Conflict("release artifact exceeded its signed size".into()))?;
            if size > expected_size || size > MAX_ARTIFACT_BYTES {
                return Err(AppError::Conflict(
                    "release artifact exceeded its signed size".into(),
                ));
            }
            digest.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        drop(file);
        if size != expected_size {
            return Err(AppError::Conflict(
                "release artifact size did not match the signed manifest".into(),
            ));
        }
        let sha256 = format!("{:x}", digest.finalize());
        if sha256 != expected_sha256 {
            return Err(AppError::Conflict(
                "release artifact digest did not match the signed manifest".into(),
            ));
        }
        tokio::fs::rename(partial_path, final_path).await?;
        // Do not report an artifact as staged until the directory entry is
        // durable. The helper may be woken immediately after approval.
        let parent = final_path.parent().ok_or_else(|| {
            AppError::Internal("staged update path has no parent directory".into())
        })?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok((size, sha256))
    }
}

/// Independently validate an unprivileged panel request at the privileged
/// boundary. A helper must call this immediately before any fixed activation
/// implementation and must never translate request data into a shell string.
pub async fn validate_privileged_request(
    request: &PrivilegedUpdateRequest,
    trusted_keys: &TrustedReleaseKeys,
    staging_root: &Path,
    rollback_root: &Path,
    receipt: Option<&HelperActivationReceipt>,
    now: i64,
) -> AppResult<ValidatedHelperPlan> {
    validate_helper_root("update staging root", staging_root)?;
    validate_helper_root("update rollback root", rollback_root)?;
    match request {
        PrivilegedUpdateRequest::Activate {
            schema_version,
            activation,
            manifest_base64,
            detached_signature_base64,
        } => {
            validate_helper_schema(*schema_version)?;
            validate_approval_window(
                activation.approved_at,
                activation.expires_at,
                activation.maintenance_impact_accepted,
                now,
            )?;
            validate_uuid("activation ID", &activation.id)?;
            validate_identifier("approving administrator", &activation.approved_by, 256)?;
            if !activation.requires_privileged_helper {
                return Err(AppError::Conflict(
                    "activation request did not require the privileged helper".into(),
                ));
            }
            if activation.repository != UPDATE_REPOSITORY {
                return Err(AppError::Conflict(
                    "activation request targets a different repository".into(),
                ));
            }
            if activation.actions.is_empty() || activation.actions.len() > 3 {
                return Err(AppError::Validation(
                    "activation request must contain between one and three actions".into(),
                ));
            }
            let manifest_bytes = decode_bounded_base64(
                manifest_base64,
                MAX_MANIFEST_BYTES,
                "release manifest",
            )?;
            let signature_bytes = decode_bounded_base64(
                detached_signature_base64,
                MAX_SIGNATURE_BYTES,
                "release signature",
            )?;
            let verified = verify_release_manifest(
                &manifest_bytes,
                &signature_bytes,
                trusted_keys,
                &activation.release,
            )?;
            if verified.manifest_sha256 != activation.manifest_sha256
                || verified.signer_key_id != activation.signer_key_id
            {
                return Err(AppError::Conflict(
                    "activation request does not match the independently verified manifest".into(),
                ));
            }

            let mut seen = BTreeSet::new();
            for action in &activation.actions {
                let component = match action {
                    ApprovedComponentAction::InstallStagedArchive { component, .. }
                    | ApprovedComponentAction::UpgradeSystemPackages { component, .. } => *component,
                };
                if !seen.insert(component) {
                    return Err(AppError::Conflict(format!(
                        "activation repeats the {} component",
                        component.as_str()
                    )));
                }
                let manifest_component = verified
                    .manifest
                    .components
                    .iter()
                    .find(|entry| entry.component == component)
                    .ok_or_else(|| {
                        AppError::Conflict(format!(
                            "activation component {} is absent from the signed manifest",
                            component.as_str()
                        ))
                    })?;
                match (action, &manifest_component.delivery) {
                    (
                        ApprovedComponentAction::InstallStagedArchive {
                            component: UpdateComponent::VexaVm,
                            version,
                            staged_path,
                            sha256,
                            size_bytes,
                        },
                        ComponentDelivery::SignedArchive {
                            sha256: signed_sha256,
                            size_bytes: signed_size,
                            ..
                        },
                    ) if version == &manifest_component.version
                        && *size_bytes == *signed_size
                        && validate_sha256(sha256)? == validate_sha256(signed_sha256)? =>
                    {
                        verify_confined_file(
                            staging_root,
                            staged_path,
                            *size_bytes,
                            sha256,
                            MAX_ARTIFACT_BYTES,
                            false,
                        )
                        .await?;
                    }
                    (
                        ApprovedComponentAction::UpgradeSystemPackages {
                            component,
                            version,
                            manager,
                            packages,
                        },
                        ComponentDelivery::SystemPackages {
                            manager: signed_manager,
                            packages: signed_packages,
                        },
                    ) if component == &manifest_component.component
                        && version == &manifest_component.version
                        && manager == signed_manager
                        && packages == signed_packages => {}
                    _ => {
                        return Err(AppError::Conflict(format!(
                            "activation action for {} differs from the signed manifest",
                            component.as_str()
                        )));
                    }
                }
            }
            Ok(ValidatedHelperPlan::Activate {
                activation_id: activation.id.clone(),
                release: activation.release.clone(),
                manifest_sha256: activation.manifest_sha256.clone(),
                signer_key_id: activation.signer_key_id.clone(),
                approved_by: activation.approved_by.clone(),
                actions: activation.actions.clone(),
            })
        }
        PrivilegedUpdateRequest::Rollback {
            schema_version,
            rollback,
        } => {
            validate_helper_schema(*schema_version)?;
            validate_approval_window(
                rollback.approved_at,
                rollback.expires_at,
                rollback.maintenance_impact_accepted,
                now,
            )?;
            validate_uuid("rollback request ID", &rollback.id)?;
            validate_uuid("activation ID", &rollback.activation_id)?;
            validate_identifier("approving administrator", &rollback.approved_by, 256)?;
            if !rollback.requires_privileged_helper {
                return Err(AppError::Conflict(
                    "rollback request did not require the privileged helper".into(),
                ));
            }
            let receipt = receipt.ok_or_else(|| {
                AppError::NotFound(format!(
                    "root-owned activation receipt {}",
                    rollback.activation_id
                ))
            })?;
            validate_helper_schema(receipt.schema_version)?;
            if receipt.completed_at <= 0
                || receipt.activation_id != rollback.activation_id
                || receipt.release != rollback.release
                || receipt.previous_release != rollback.restore_release
                || receipt.manifest_sha256 != rollback.manifest_sha256
                || receipt.snapshot_path != rollback.snapshot_path
                || receipt.snapshot_sha256 != rollback.snapshot_sha256
                || receipt.snapshot_size_bytes != rollback.snapshot_size_bytes
                || receipt.components != rollback.components
            {
                return Err(AppError::Conflict(
                    "rollback request differs from the root-owned activation receipt".into(),
                ));
            }
            if rollback.components.is_empty() {
                return Err(AppError::Validation(
                    "rollback request contains no components".into(),
                ));
            }
            validate_sha256(&rollback.manifest_sha256)?;
            verify_confined_file(
                rollback_root,
                &rollback.snapshot_path,
                rollback.snapshot_size_bytes,
                &rollback.snapshot_sha256,
                MAX_ROLLBACK_SNAPSHOT_BYTES,
                true,
            )
            .await?;
            Ok(ValidatedHelperPlan::Rollback {
                request_id: rollback.id.clone(),
                activation_id: rollback.activation_id.clone(),
                release: rollback.release.clone(),
                restore_release: rollback.restore_release.clone(),
                snapshot_path: rollback.snapshot_path.clone(),
                snapshot_sha256: rollback.snapshot_sha256.clone(),
                snapshot_size_bytes: rollback.snapshot_size_bytes,
                components: rollback.components.clone(),
                approved_by: rollback.approved_by.clone(),
            })
        }
    }
}

fn validate_helper_schema(schema_version: u32) -> AppResult<()> {
    if schema_version != PRIVILEGED_REQUEST_SCHEMA_VERSION {
        return Err(AppError::Conflict(
            "privileged update request schema is not supported".into(),
        ));
    }
    Ok(())
}

fn current_unix_time() -> AppResult<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Internal("system clock is before the Unix epoch".into()))?
        .as_secs()
        .try_into()
        .map_err(|_| AppError::Internal("system clock is outside the supported range".into()))
}

fn validate_approval_window(
    approved_at: i64,
    expires_at: i64,
    maintenance_impact_accepted: bool,
    now: i64,
) -> AppResult<()> {
    if !maintenance_impact_accepted {
        return Err(AppError::Validation(
            "maintenance impact was not accepted".into(),
        ));
    }
    if approved_at <= 0
        || expires_at != approved_at.saturating_add(UPDATE_APPROVAL_TTL_SECONDS)
        || now < approved_at.saturating_sub(300)
        || now > expires_at
    {
        return Err(AppError::Conflict(
            "update approval is expired or has an invalid lifetime".into(),
        ));
    }
    Ok(())
}

fn validate_helper_root(label: &str, path: &Path) -> AppResult<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(AppError::Configuration(format!(
            "{label} must be an absolute normalized path"
        )));
    }
    Ok(())
}

fn decode_bounded_base64(value: &str, maximum: u64, label: &str) -> AppResult<Vec<u8>> {
    if value.len() as u64 > maximum.saturating_mul(2) {
        return Err(AppError::Validation(format!("{label} is too large")));
    }
    let bytes = BASE64
        .decode(value.as_bytes())
        .map_err(|_| AppError::Validation(format!("{label} is not valid base64")))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(AppError::Validation(format!("{label} is too large")));
    }
    Ok(bytes)
}

async fn verify_confined_file(
    root: &Path,
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
    maximum_size: u64,
    require_root_owned: bool,
) -> AppResult<()> {
    if expected_size == 0 || expected_size > maximum_size {
        return Err(AppError::Validation(
            "update helper file has an unsafe size".into(),
        ));
    }
    let root = tokio::fs::canonicalize(root).await?;
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(AppError::Conflict(
            "update helper input is not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    if require_root_owned {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(AppError::Conflict(
                "rollback snapshot must be root-owned and not group/world writable".into(),
            ));
        }
    }
    let path = tokio::fs::canonicalize(path).await?;
    if path.parent() != Some(root.as_path()) {
        return Err(AppError::Conflict(
            "update helper input escaped its configured root".into(),
        ));
    }
    let expected_sha256 = validate_sha256(expected_sha256)?;
    let (size, sha256) = hash_file(&path, maximum_size).await?;
    if size != expected_size || sha256 != expected_sha256 {
        return Err(AppError::Conflict(
            "update helper input failed digest verification".into(),
        ));
    }
    Ok(())
}

pub fn verify_release_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trusted_keys: &TrustedReleaseKeys,
    expected_tag: &str,
) -> AppResult<VerifiedRelease> {
    if manifest_bytes.is_empty() || manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(AppError::Validation(
            "release manifest size is outside the accepted range".into(),
        ));
    }
    if signature_bytes.is_empty() || signature_bytes.len() as u64 > MAX_SIGNATURE_BYTES {
        return Err(AppError::Validation(
            "release signature size is outside the accepted range".into(),
        ));
    }
    let detached: DetachedSignature = serde_json::from_slice(signature_bytes)
        .map_err(|_| AppError::Conflict("release signature envelope was invalid".into()))?;
    if detached.algorithm != "ed25519" {
        return Err(AppError::Conflict(
            "release signature algorithm must be ed25519".into(),
        ));
    }
    let public_key = trusted_keys
        .get(&detached.key_id)
        .ok_or_else(|| AppError::Conflict("release was signed by an untrusted key".into()))?;
    let decoded_signature = BASE64
        .decode(detached.signature.as_bytes())
        .map_err(|_| AppError::Conflict("release signature was invalid".into()))?;
    if decoded_signature.len() != 64 {
        return Err(AppError::Conflict("release signature was invalid".into()));
    }
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(manifest_bytes, &decoded_signature)
        .map_err(|_| AppError::Conflict("release signature verification failed".into()))?;

    let manifest: UpdateManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|_| AppError::Conflict("signed release manifest was invalid".into()))?;
    validate_manifest(&manifest, expected_tag)?;
    Ok(VerifiedRelease {
        tag: expected_tag.to_owned(),
        html_url: String::new(),
        signer_key_id: detached.key_id,
        manifest_sha256: format!("{:x}", Sha256::digest(manifest_bytes)),
        manifest,
        manifest_bytes: manifest_bytes.to_vec(),
        signature_bytes: signature_bytes.to_vec(),
    })
}

fn validate_manifest(manifest: &UpdateManifest, expected_tag: &str) -> AppResult<()> {
    if manifest.schema_version != 1 {
        return Err(AppError::Conflict(
            "release manifest schema is not supported".into(),
        ));
    }
    if manifest.repository != UPDATE_REPOSITORY {
        return Err(AppError::Conflict(
            "release manifest targets a different repository".into(),
        ));
    }
    if manifest.published_at <= 0 {
        return Err(AppError::Conflict(
            "release manifest publication time is invalid".into(),
        ));
    }
    ParsedVersion::parse(&manifest.release)?;
    ParsedVersion::parse(expected_tag)?;
    if manifest.release != expected_tag.strip_prefix('v').unwrap_or(expected_tag) {
        return Err(AppError::Conflict(
            "release manifest version does not match the GitHub tag".into(),
        ));
    }
    if manifest.components.is_empty() {
        return Err(AppError::Conflict("release manifest has no components".into()));
    }
    let mut seen = BTreeSet::new();
    for component in &manifest.components {
        if !seen.insert(component.component) {
            return Err(AppError::Conflict(format!(
                "release manifest repeats the {} component",
                component.component.as_str()
            )));
        }
        ParsedVersion::parse(&component.version)?;
        match (&component.component, &component.delivery) {
            (
                UpdateComponent::VexaVm,
                ComponentDelivery::SignedArchive {
                    url,
                    sha256,
                    size_bytes,
                    target,
                },
            ) => {
                if component.version != manifest.release {
                    return Err(AppError::Conflict(
                        "Vexa-VM component version does not match the release".into(),
                    ));
                }
                let archive_url = validate_release_asset_url(url, expected_tag)?;
                validate_sha256(sha256)?;
                if *size_bytes == 0 || *size_bytes > MAX_ARTIFACT_BYTES {
                    return Err(AppError::Conflict(
                        "Vexa-VM release archive has an unsafe size".into(),
                    ));
                }
                validate_target(target)?;
                let expected_filename = format!("vexa-vm-{target}.tar.gz");
                if asset_filename(&archive_url) != Some(expected_filename.as_str()) {
                    return Err(AppError::Conflict(
                        "Vexa-VM release archive filename does not match its target".into(),
                    ));
                }
            }
            (UpdateComponent::Qemu | UpdateComponent::Libvirt, ComponentDelivery::SystemPackages {
                manager: PackageManager::Apt,
                packages,
            }) => validate_system_packages(component.component, packages)?,
            (UpdateComponent::VexaVm, ComponentDelivery::SystemPackages { .. }) => {
                return Err(AppError::Conflict(
                    "Vexa-VM must be delivered as a signed release archive".into(),
                ));
            }
            (_, ComponentDelivery::SignedArchive { .. }) => {
                return Err(AppError::Conflict(
                    "QEMU and libvirt may only be updated through allowlisted system packages".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_manifest_assets(manifest: &UpdateManifest, assets: &[GitHubAsset]) -> AppResult<()> {
    for component in &manifest.components {
        let ComponentDelivery::SignedArchive {
            url, size_bytes, ..
        } = &component.delivery
        else {
            continue;
        };
        let asset = assets
            .iter()
            .find(|asset| asset.browser_download_url == *url)
            .ok_or_else(|| AppError::Conflict("signed archive is not attached to the GitHub release".into()))?;
        if asset.size != *size_bytes {
            return Err(AppError::Conflict(
                "GitHub asset size does not match the signed manifest".into(),
            ));
        }
    }
    Ok(())
}

/// Updates may never use a stale signed release as an implicit downgrade.
/// Package-only maintenance may be approved from the manifest matching the
/// currently running application, while selecting Vexa-VM itself requires a
/// strict semantic-version upgrade. Explicit downgrade is available only via
/// the independently receipt-bound rollback workflow.
fn ensure_application_release_order(
    release: &VerifiedRelease,
    current_version: &str,
    application_selected: bool,
) -> AppResult<()> {
    let application = release
        .manifest
        .components
        .iter()
        .find(|component| component.component == UpdateComponent::VexaVm)
        .ok_or_else(|| AppError::Conflict("release manifest has no Vexa-VM component".into()))?;
    let current = ParsedVersion::parse(current_version)?;
    let target = ParsedVersion::parse(&application.version)?;
    if target < current || (application_selected && target == current) {
        return Err(AppError::Conflict(if target < current {
            "signed update releases cannot downgrade the running application; use an eligible rollback point"
                .into()
        } else {
            "the selected Vexa-VM release is already running".into()
        }));
    }
    Ok(())
}

fn validate_system_packages(component: UpdateComponent, packages: &[SystemPackage]) -> AppResult<()> {
    if packages.is_empty() || packages.len() > 8 {
        return Err(AppError::Conflict(
            "system package update must contain between one and eight packages".into(),
        ));
    }
    let allowed: &[&str] = match component {
        UpdateComponent::Qemu => &["qemu-kvm", "qemu-system-x86", "qemu-utils"],
        UpdateComponent::Libvirt => &[
            "libvirt-clients",
            "libvirt-daemon-driver-qemu",
            "libvirt-daemon-system",
        ],
        UpdateComponent::VexaVm => &[],
    };
    let mut seen = BTreeSet::new();
    for package in packages {
        if !allowed.contains(&package.name.as_str()) {
            return Err(AppError::Conflict(format!(
                "package {} is not allowlisted for {}",
                package.name,
                component.as_str()
            )));
        }
        if !seen.insert(&package.name) {
            return Err(AppError::Conflict(format!(
                "package {} is duplicated",
                package.name
            )));
        }
        validate_package_version(&package.candidate_version)?;
    }
    Ok(())
}

fn validate_package_version(version: &str) -> AppResult<()> {
    if version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+:~_-".contains(&byte))
    {
        return Err(AppError::Conflict(
            "system package candidate version is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_target(target: &str) -> AppResult<()> {
    let expected = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        _ => {
            return Err(AppError::Configuration(
                "this host target is not supported by the panel updater".into(),
            ));
        }
    };
    if target != expected {
        return Err(AppError::Conflict(format!(
            "release target {target} does not match this host ({expected})"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::Conflict(
            "release SHA-256 must contain exactly 64 hexadecimal characters".into(),
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn required_asset<'a>(assets: &'a [GitHubAsset], name: &str) -> AppResult<&'a GitHubAsset> {
    let matches = assets.iter().filter(|asset| asset.name == name).collect::<Vec<_>>();
    match matches.as_slice() {
        [asset] => Ok(*asset),
        [] => Err(AppError::Conflict(format!(
            "GitHub release is missing {name}"
        ))),
        _ => Err(AppError::Conflict(format!(
            "GitHub release contains duplicate {name} assets"
        ))),
    }
}

#[derive(Clone, Copy)]
enum UrlPurpose {
    Api,
    Asset,
    Redirect,
}

fn validate_github_url(url: &Url, purpose: UrlPurpose) -> AppResult<()> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.fragment().is_some()
        || (matches!(purpose, UrlPurpose::Asset) && url.query().is_some())
    {
        return Err(AppError::Conflict("release URL is not safe".into()));
    }
    let host = url.host_str().unwrap_or_default();
    let allowed = match purpose {
        UrlPurpose::Api => {
            host == "api.github.com"
                && ((url.path() == "/repos/ItzGlace/vaxa-vm/releases/latest"
                    && url.query().is_none())
                    || (url.path() == "/repos/ItzGlace/vaxa-vm/releases"
                        && url.query() == Some("per_page=10")))
        }
        UrlPurpose::Asset => host == "github.com" && url.path().starts_with("/ItzGlace/vaxa-vm/releases/download/"),
        UrlPurpose::Redirect => matches!(
            host,
            "github.com"
                | "objects.githubusercontent.com"
                | "release-assets.githubusercontent.com"
                | "github-releases.githubusercontent.com"
        ),
    };
    if !allowed {
        return Err(AppError::Conflict(
            "release URL host or path is outside the GitHub allowlist".into(),
        ));
    }
    Ok(())
}

fn validate_release_asset_url(value: &str, expected_tag: &str) -> AppResult<Url> {
    let url = Url::parse(value).map_err(|_| AppError::Conflict("release asset URL is invalid".into()))?;
    validate_github_url(&url, UrlPurpose::Asset)?;
    let expected_prefix = format!("/ItzGlace/vaxa-vm/releases/download/{expected_tag}/");
    let filename = url.path().strip_prefix(&expected_prefix).unwrap_or_default();
    if filename.is_empty()
        || filename.len() > 255
        || filename.contains('/')
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(AppError::Conflict(
            "release asset URL does not match the selected GitHub tag".into(),
        ));
    }
    Ok(url)
}

fn asset_filename(url: &Url) -> Option<&str> {
    url.path_segments()?.next_back()
}

fn validate_release_page_url(value: &str, expected_tag: &str) -> AppResult<()> {
    let url = Url::parse(value).map_err(|_| AppError::Conflict("release page URL is invalid".into()))?;
    let expected_path = format!("/ItzGlace/vaxa-vm/releases/tag/{expected_tag}");
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port_or_known_default() != Some(443)
        || url.path() != expected_path
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AppError::Conflict("release page URL is outside the repository".into()));
    }
    Ok(())
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

async fn hash_file(path: &Path, maximum: u64) -> AppResult<(u64, String)> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Conflict("staged update artifact is too large".into()))?;
        if size > maximum {
            return Err(AppError::Conflict(
                "staged update artifact is too large".into(),
            ));
        }
        digest.update(&buffer[..read]);
    }
    Ok((size, format!("{:x}", digest.finalize())))
}

struct StagedFileCleanup {
    partial_path: PathBuf,
    final_path: PathBuf,
    retain_final: bool,
}

impl StagedFileCleanup {
    fn new(partial_path: &Path, final_path: &Path) -> Self {
        Self {
            partial_path: partial_path.to_path_buf(),
            final_path: final_path.to_path_buf(),
            retain_final: false,
        }
    }

    fn retain(&mut self) {
        self.retain_final = true;
    }
}

impl Drop for StagedFileCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.partial_path);
        if !self.retain_final {
            let _ = std::fs::remove_file(&self.final_path);
        }
    }
}

fn validate_identifier(label: &str, value: &str, maximum: usize) -> AppResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
    {
        return Err(AppError::Validation(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_uuid(label: &str, value: &str) -> AppResult<()> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| AppError::Validation(format!("{label} must be a UUID")))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedVersion {
    core: [u64; 3],
    prerelease: Vec<VersionIdentifier>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum VersionIdentifier {
    Numeric(u64),
    Text(String),
}

impl ParsedVersion {
    fn parse(value: &str) -> AppResult<Self> {
        if value != value.trim() {
            return Err(AppError::Conflict(format!(
                "release version {value} is not valid semantic versioning"
            )));
        }
        let value = value.strip_prefix('v').unwrap_or(value);
        let (without_build, build) = value
            .split_once('+')
            .map_or((value, None), |(version, build)| (version, Some(build)));
        if let Some(build) = build {
            if build.is_empty()
                || build.contains('+')
                || build.split('.').any(|identifier| {
                    identifier.is_empty()
                        || !identifier
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
            {
                return Err(AppError::Conflict(format!(
                    "release version {value} is not valid semantic versioning"
                )));
            }
        }
        let (core, prerelease) = without_build
            .split_once('-')
            .map_or((without_build, None), |(core, pre)| (core, Some(pre)));
        let numbers = core.split('.').collect::<Vec<_>>();
        if numbers.len() != 3 {
            return Err(AppError::Conflict(format!(
                "release version {value} is not valid semantic versioning"
            )));
        }
        let mut parsed_core = [0_u64; 3];
        for (index, number) in numbers.into_iter().enumerate() {
            if number.is_empty()
                || (number.len() > 1 && number.starts_with('0'))
                || !number.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(AppError::Conflict(format!(
                    "release version {value} is not valid semantic versioning"
                )));
            }
            parsed_core[index] = number.parse().map_err(|_| {
                AppError::Conflict(format!(
                    "release version {value} is not valid semantic versioning"
                ))
            })?;
        }
        let mut parsed_prerelease = Vec::new();
        if let Some(prerelease) = prerelease {
            for identifier in prerelease.split('.') {
                if identifier.is_empty()
                    || !identifier
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                {
                    return Err(AppError::Conflict(format!(
                        "release version {value} is not valid semantic versioning"
                    )));
                }
                if identifier.bytes().all(|byte| byte.is_ascii_digit()) {
                    if identifier.len() > 1 && identifier.starts_with('0') {
                        return Err(AppError::Conflict(format!(
                            "release version {value} is not valid semantic versioning"
                        )));
                    }
                    parsed_prerelease.push(VersionIdentifier::Numeric(identifier.parse().map_err(
                        |_| {
                            AppError::Conflict(format!(
                                "release version {value} is not valid semantic versioning"
                            ))
                        },
                    )?));
                } else {
                    parsed_prerelease.push(VersionIdentifier::Text(identifier.into()));
                }
            }
        }
        Ok(Self {
            core: parsed_core,
            prerelease: parsed_prerelease,
        })
    }
}

impl Ord for ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core.cmp(&other.core).then_with(|| match (
            self.prerelease.is_empty(),
            other.prerelease.is_empty(),
        ) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => compare_prerelease(&self.prerelease, &other.prerelease),
        })
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(left: &[VersionIdentifier], right: &[VersionIdentifier]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = match (left, right) {
            (VersionIdentifier::Numeric(left), VersionIdentifier::Numeric(right)) => left.cmp(right),
            (VersionIdentifier::Numeric(_), VersionIdentifier::Text(_)) => Ordering::Less,
            (VersionIdentifier::Text(_), VersionIdentifier::Numeric(_)) => Ordering::Greater,
            (VersionIdentifier::Text(left), VersionIdentifier::Text(right)) => left.cmp(right),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn signed_manifest() -> (Vec<u8>, Vec<u8>, TrustedReleaseKeys) {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).unwrap();
        let artifact = b"release archive";
        let target = "x86_64-unknown-linux-gnu";
        let manifest = UpdateManifest {
            schema_version: 1,
            repository: UPDATE_REPOSITORY.into(),
            release: "1.2.3".into(),
            published_at: 1_786_000_000,
            components: vec![
                ComponentRelease {
                    component: UpdateComponent::VexaVm,
                    version: "1.2.3".into(),
                    delivery: ComponentDelivery::SignedArchive {
                        url: "https://github.com/ItzGlace/vaxa-vm/releases/download/v1.2.3/vexa-vm-x86_64-unknown-linux-gnu.tar.gz".into(),
                        sha256: format!("{:x}", Sha256::digest(artifact)),
                        size_bytes: artifact.len() as u64,
                        target: target.into(),
                    },
                },
                ComponentRelease {
                    component: UpdateComponent::Qemu,
                    version: "8.2.2".into(),
                    delivery: ComponentDelivery::SystemPackages {
                        manager: PackageManager::Apt,
                        packages: vec![SystemPackage {
                            name: "qemu-system-x86".into(),
                            candidate_version: "1:8.2.2+ds-0ubuntu1.4".into(),
                        }],
                    },
                },
            ],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let signature = key_pair.sign(&manifest_bytes);
        let signature_bytes = serde_json::to_vec(&serde_json::json!({
            "algorithm": "ed25519",
            "key_id": "test-2026",
            "signature": BASE64.encode(signature.as_ref()),
        }))
        .unwrap();
        let trust = TrustedReleaseKeys::new([(
            "test-2026".into(),
            BASE64.encode(key_pair.public_key().as_ref()),
        )])
        .unwrap();
        (manifest_bytes, signature_bytes, trust)
    }

    #[test]
    fn verifies_signed_manifest_and_rejects_tampering() {
        let (manifest, detached, trust) = signed_manifest();
        let verified = verify_release_manifest(&manifest, &detached, &trust, "v1.2.3").unwrap();
        assert_eq!(verified.signer_key_id, "test-2026");
        assert_eq!(verified.manifest.components.len(), 2);

        let mut tampered = manifest;
        tampered.push(b' ');
        assert!(verify_release_manifest(&tampered, &detached, &trust, "v1.2.3").is_err());
    }

    #[test]
    fn rejects_wrong_repository_and_unallowlisted_packages() {
        let (manifest, _, _) = signed_manifest();
        let mut manifest: UpdateManifest = serde_json::from_slice(&manifest).unwrap();
        manifest.repository = "attacker/project".into();
        assert!(validate_manifest(&manifest, "v1.2.3").is_err());

        manifest.repository = UPDATE_REPOSITORY.into();
        let qemu = manifest
            .components
            .iter_mut()
            .find(|component| component.component == UpdateComponent::Qemu)
            .unwrap();
        qemu.delivery = ComponentDelivery::SystemPackages {
            manager: PackageManager::Apt,
            packages: vec![SystemPackage {
                name: "curl".into(),
                candidate_version: "1.0.0".into(),
            }],
        };
        assert!(validate_manifest(&manifest, "v1.2.3").is_err());
    }

    #[test]
    fn semantic_versions_are_compared_correctly() {
        assert!(ParsedVersion::parse("1.2.4").unwrap() > ParsedVersion::parse("v1.2.3").unwrap());
        assert!(ParsedVersion::parse("1.2.3").unwrap() > ParsedVersion::parse("1.2.3-rc.1").unwrap());
        assert!(ParsedVersion::parse("1.2.3-rc.10").unwrap()
            > ParsedVersion::parse("1.2.3-rc.2").unwrap());
        assert!(ParsedVersion::parse("1.02.3").is_err());
    }

    #[test]
    fn github_asset_urls_are_repository_and_tag_bound() {
        assert!(validate_github_url(
            &Url::parse(RELEASE_API_URL).unwrap(),
            UrlPurpose::Api
        )
        .is_ok());
        assert!(validate_github_url(
            &Url::parse(RELEASES_API_URL).unwrap(),
            UrlPurpose::Api
        )
        .is_ok());
        assert!(validate_github_url(
            &Url::parse("https://api.github.com/repos/ItzGlace/vaxa-vm/releases?per_page=100")
                .unwrap(),
            UrlPurpose::Api
        )
        .is_err());
        assert!(validate_release_asset_url(
            "https://github.com/ItzGlace/vaxa-vm/releases/download/v1.2.3/archive.tar.gz",
            "v1.2.3"
        )
        .is_ok());
        for url in [
            "http://github.com/ItzGlace/vaxa-vm/releases/download/v1.2.3/archive.tar.gz",
            "https://evil.example/ItzGlace/vaxa-vm/releases/download/v1.2.3/archive.tar.gz",
            "https://github.com/other/repo/releases/download/v1.2.3/archive.tar.gz",
            "https://github.com/ItzGlace/vaxa-vm/releases/download/v9.9.9/archive.tar.gz",
        ] {
            assert!(validate_release_asset_url(url, "v1.2.3").is_err(), "accepted {url}");
        }
        assert!(validate_release_page_url(
            "https://github.com/ItzGlace/vaxa-vm/releases/tag/v1.2.3",
            "v1.2.3"
        )
        .is_ok());
        for url in [
            "https://github.com:444/ItzGlace/vaxa-vm/releases/tag/v1.2.3",
            "https://github.com/ItzGlace/vaxa-vm/releases/tag/v1.2.3?download=1",
            "https://github.com/ItzGlace/vaxa-vm/releases/tag/v1.2.3#assets",
        ] {
            assert!(validate_release_page_url(url, "v1.2.3").is_err(), "accepted {url}");
        }
    }

    #[tokio::test]
    async fn staged_artifact_is_rehashed_and_confined() {
        let (_, _, trust) = signed_manifest();
        let directory = tempfile::tempdir().unwrap();
        let updater = ReleaseUpdater::new(directory.path(), trust, false).unwrap();
        let path = directory.path().join("vexa-vm-1.2.3-test.tar.gz");
        let bytes = b"verified release";
        tokio::fs::write(&path, bytes).await.unwrap();
        let artifact = StagedArtifact {
            component: UpdateComponent::VexaVm,
            version: "1.2.3".into(),
            release: "v1.2.3".into(),
            manifest_sha256: "a".repeat(64),
            signer_key_id: "test-2026".into(),
            path,
            size_bytes: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        };
        updater.verify_staged_artifact(&artifact).await.unwrap();
        tokio::fs::write(&artifact.path, b"tampered").await.unwrap();
        assert!(updater.verify_staged_artifact(&artifact).await.is_err());
    }

    #[tokio::test]
    async fn privileged_helper_reverifies_approval_manifest_and_artifact() {
        let (manifest, detached, trust) = signed_manifest();
        let verified = verify_release_manifest(&manifest, &detached, &trust, "v1.2.3").unwrap();
        let staging = tempfile::tempdir().unwrap();
        let rollback = tempfile::tempdir().unwrap();
        let updater = ReleaseUpdater::new(staging.path(), trust.clone(), false).unwrap();
        let bytes = b"release archive";
        let path = staging.path().join("vexa-vm-1.2.3-test.tar.gz");
        tokio::fs::write(&path, bytes).await.unwrap();
        let artifact = StagedArtifact {
            component: UpdateComponent::VexaVm,
            version: "1.2.3".into(),
            release: "v1.2.3".into(),
            manifest_sha256: verified.manifest_sha256.clone(),
            signer_key_id: verified.signer_key_id.clone(),
            path: path.clone(),
            size_bytes: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        };
        let approved_at = 1_786_000_100;
        let activation = updater
            .build_activation_request(
                &verified,
                &[artifact],
                &UpdateApproval {
                    approved_by: "admin-1".into(),
                    release: "v1.2.3".into(),
                    manifest_sha256: verified.manifest_sha256.clone(),
                    components: BTreeSet::from([UpdateComponent::VexaVm]),
                    maintenance_impact_accepted: true,
                    approved_at,
                },
            )
            .await
            .unwrap();
        let request = verified
            .privileged_activation_request(activation)
            .unwrap();
        let mut request_with_command = serde_json::to_value(&request).unwrap();
        request_with_command
            .as_object_mut()
            .unwrap()
            .insert("command".into(), serde_json::json!("sh -c attacker"));
        assert!(serde_json::from_value::<PrivilegedUpdateRequest>(request_with_command).is_err());
        let plan = validate_privileged_request(
            &request,
            &trust,
            staging.path(),
            rollback.path(),
            None,
            approved_at + 1,
        )
        .await
        .unwrap();
        assert!(matches!(plan, ValidatedHelperPlan::Activate { .. }));

        let spool_directory = tempfile::tempdir().unwrap();
        let spool = PrivilegedRequestSpool::for_test(spool_directory.path()).unwrap();
        let stored_id = spool.store(&request).await.unwrap();
        let stored_path = spool_directory.path().join(format!("{stored_id}.json"));
        let stored: PrivilegedUpdateRequest =
            serde_json::from_slice(&tokio::fs::read(&stored_path).await.unwrap()).unwrap();
        assert!(matches!(stored, PrivilegedUpdateRequest::Activate { .. }));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                tokio::fs::metadata(&stored_path)
                    .await
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(spool.store(&request).await.is_err());

        let mut invalid_id = request.clone();
        let PrivilegedUpdateRequest::Activate { activation, .. } = &mut invalid_id else {
            unreachable!();
        };
        activation.id = "../../unsafe".into();
        assert!(validate_privileged_request(
            &invalid_id,
            &trust,
            staging.path(),
            rollback.path(),
            None,
            approved_at + 1,
        )
        .await
        .is_err());

        tokio::fs::write(&path, b"tampered after approval")
            .await
            .unwrap();
        assert!(validate_privileged_request(
            &request,
            &trust,
            staging.path(),
            rollback.path(),
            None,
            approved_at + 1,
        )
        .await
        .is_err());
        assert!(validate_privileged_request(
            &request,
            &trust,
            staging.path(),
            rollback.path(),
            None,
            approved_at + UPDATE_APPROVAL_TTL_SECONDS + 1,
        )
        .await
        .is_err());
    }

    #[test]
    fn trust_store_is_versioned_and_bounded() {
        let (_, _, trust) = signed_manifest();
        assert!(trust.get("test-2026").is_some());
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[9_u8; 32]).unwrap();
        let store = TrustedReleaseKeyStore {
            schema_version: 1,
            keys: vec![TrustedReleaseKey {
                key_id: "release-2026".into(),
                public_key_base64: BASE64.encode(key_pair.public_key().as_ref()),
            }],
        };
        assert!(store.into_trusted_keys().is_ok());
        assert!(TrustedReleaseKeyStore {
            schema_version: 99,
            keys: vec![],
        }
        .into_trusted_keys()
        .is_err());
    }

    #[test]
    fn activation_and_rollback_require_matching_explicit_approval() {
        let (_, _, trust) = signed_manifest();
        let updater = ReleaseUpdater::new("/var/lib/vexa-vm/updates", trust, false).unwrap();
        let point = RollbackPoint {
            activation_id: "633f5ca4-2306-4056-8aba-047b06d01e5b".into(),
            release: "v1.2.3".into(),
            previous_release: "v1.2.2".into(),
            manifest_sha256: "a".repeat(64),
            snapshot_path: PathBuf::from("/var/lib/vexa-vm/updates/rollback-1.tar.gz"),
            snapshot_sha256: "b".repeat(64),
            snapshot_size_bytes: 1024,
            components: BTreeSet::from([UpdateComponent::VexaVm]),
        };
        let mut approval = RollbackApproval {
            approved_by: "admin-1".into(),
            activation_id: "wrong".into(),
            previous_release: "v1.2.2".into(),
            maintenance_impact_accepted: true,
            approved_at: 1_786_000_001,
        };
        assert!(updater.build_rollback_request(&point, &approval).is_err());
        approval.activation_id = point.activation_id.clone();
        assert!(updater.build_rollback_request(&point, &approval).is_ok());
    }

    #[test]
    fn recovered_activation_rollback_point_requires_a_committed_activation_state() {
        let request_id = Uuid::new_v4().to_string();
        let mut status = DurableUpdateStatus {
            schema_version: 1,
            request_id: request_id.clone(),
            operation: Some("activate".into()),
            release: Some("1.2.3".into()),
            phase: "recovered_committed".into(),
            progress_percent: 100,
            outcome: DurableUpdateOutcome::Succeeded,
            message: "Recovered committed activation".into(),
            started_at: 100,
            updated_at: 110,
            completed_at: Some(110),
            package_changes: Vec::new(),
            rollback: DurableRollbackStatus {
                available: true,
                attempted: false,
                succeeded: false,
                previous_release: Some("1.2.2".into()),
                snapshot_sha256: Some("b".repeat(64)),
            },
            rollback_point: Some(PublicRollbackPoint {
                activation_id: request_id.clone(),
                release: "1.2.3".into(),
                previous_release: "1.2.2".into(),
                manifest_sha256: "a".repeat(64),
                snapshot_sha256: "b".repeat(64),
                snapshot_size_bytes: 4096,
                components: vec!["vexa-vm".into()],
            }),
        };
        assert!(validate_durable_update_status(&status, &request_id).is_ok());

        status.operation = Some("recover".into());
        assert!(validate_durable_update_status(&status, &request_id).is_err());
        status.operation = Some("activate".into());
        status.rollback.available = false;
        assert!(validate_durable_update_status(&status, &request_id).is_err());
    }
}
