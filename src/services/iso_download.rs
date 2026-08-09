//! Secure, bounded remote image acquisition.
//!
//! Remote images are never published directly into the managed image store.
//! Every URL and redirect is constrained to HTTPS and pinned to DNS answers
//! that are globally routable. Bytes are streamed into a unique partial file,
//! bounded, hashed, and atomically renamed only after the administrator's
//! expected SHA-256 (and optional size) matches.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime},
};

use futures_util::StreamExt;
use reqwest::{
    header::{ACCEPT_ENCODING, CONTENT_LENGTH, LOCATION},
    redirect::Policy,
    Response, StatusCode,
};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, net::lookup_host};
use url::{Host, Url};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

pub const MAX_REMOTE_IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const STALE_PARTIAL_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const MIN_FREE_AFTER_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SIMULTANEOUS_IMAGE_TRANSFERS: usize = 1;

static ACTIVE_OPERATIONS: OnceLock<Mutex<ActiveOperations>> = OnceLock::new();

#[derive(Default)]
struct ActiveOperations {
    records: HashSet<String>,
    image_transfers: usize,
}

#[derive(Debug)]
pub struct DownloadedImage {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    cleanup_on_drop: bool,
}

impl DownloadedImage {
    /// Keep the verified file after its catalog transaction commits.
    pub fn retain(&mut self) {
        self.cleanup_on_drop = false;
    }
}

impl Drop for DownloadedImage {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Validate and normalize a remote image URL without performing DNS I/O.
pub fn validate_source_url(value: &str) -> AppResult<Url> {
    let value = value.trim();
    let Some((raw_scheme, raw_authority)) = value.split_once("://") else {
        return Err(AppError::Validation("remote image URL is invalid".into()));
    };
    if !raw_scheme.eq_ignore_ascii_case("https") || raw_authority.is_empty() || raw_authority.starts_with('/')
    {
        return Err(AppError::Validation("remote image URL is invalid".into()));
    }
    let mut url =
        Url::parse(value).map_err(|_| AppError::Validation("remote image URL is invalid".into()))?;
    if url.scheme() != "https" {
        return Err(AppError::Validation("remote image sources must use HTTPS".into()));
    }
    if url.host().is_none() {
        return Err(AppError::Validation(
            "remote image URL must include a host".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::Validation(
            "remote image URLs must not contain credentials".into(),
        ));
    }
    if url.port_or_known_default() != Some(443) {
        return Err(AppError::Validation(
            "remote image URLs must use the default HTTPS port 443".into(),
        ));
    }
    url.set_fragment(None);
    Ok(url)
}

/// Validate the trusted digest supplied before a remote download begins.
pub fn validate_sha256(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::Validation(
            "image SHA-256 must contain exactly 64 hexadecimal characters".into(),
        ));
    }
    Ok(value.to_ascii_lowercase())
}

/// Fetch a remote image and publish it only when all verification succeeds.
pub async fn download_and_verify(
    operation: &mut ImageOperationGuard,
    source_url: &str,
    expected_sha256: &str,
    expected_size: Option<u64>,
    storage_root: &Path,
) -> AppResult<DownloadedImage> {
    let original_url = validate_source_url(source_url)?;
    let expected_sha256 = validate_sha256(expected_sha256)?;
    if expected_size.is_some_and(|size| size > MAX_REMOTE_IMAGE_BYTES) {
        return Err(AppError::Validation(
            "remote image exceeds the 16 GiB limit".into(),
        ));
    }
    operation.begin_image_transfer()?;

    tokio::fs::create_dir_all(storage_root).await?;
    let storage_root = tokio::fs::canonicalize(storage_root)
        .await
        .map_err(|_| AppError::Internal("managed image storage could not be resolved".into()))?;
    if !tokio::fs::metadata(&storage_root).await?.is_dir() {
        return Err(AppError::Configuration(
            "VEXA_ISO_STORAGE must be a directory".into(),
        ));
    }

    let (response, final_url) = fetch_with_safe_redirects(original_url.clone()).await?;
    let declared_size = response_length(&response);
    validate_declared_length(declared_size, expected_size)?;
    ensure_storage_capacity(&storage_root, transfer_capacity_reservation(declared_size)).await?;
    let extension = image_extension(&final_url)
        .or_else(|| image_extension(&original_url))
        .ok_or_else(|| {
            AppError::Validation("remote image URL must end in .iso, .qcow, .qcow2, .raw, or .img".into())
        })?;

    let final_path = storage_root.join(format!("{}.{}", Uuid::new_v4(), extension));
    let partial_path = final_path.with_extension(format!("{extension}.part"));
    let result = stream_and_verify(
        response.bytes_stream(),
        &partial_path,
        &final_path,
        &expected_sha256,
        expected_size,
        MAX_REMOTE_IMAGE_BYTES,
    )
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&partial_path).await;
    }
    result
}

/// Remove incomplete files created by interrupted Vexa-VM image transfers.
///
/// Cleanup is deliberately non-recursive and only touches regular files whose
/// basename begins with a UUID and ends with `.part`. User-managed partial
/// files and directories are left untouched.
pub async fn cleanup_stale_partial_files(storage_root: &Path) -> AppResult<usize> {
    let cutoff = SystemTime::now()
        .checked_sub(STALE_PARTIAL_AGE)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    cleanup_partial_files_before(storage_root, cutoff).await
}

async fn cleanup_partial_files_before(storage_root: &Path, cutoff: SystemTime) -> AppResult<usize> {
    let mut entries = tokio::fs::read_dir(storage_root).await?;
    let mut removed = 0;
    while let Some(entry) = entries.next_entry().await? {
        let Some(filename) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_generated_partial_name(&filename) {
            continue;
        }
        let metadata = tokio::fs::symlink_metadata(entry.path()).await?;
        let stale = metadata
            .modified()
            .ok()
            .is_some_and(|modified| modified <= cutoff);
        if metadata.file_type().is_file() && stale {
            tokio::fs::remove_file(entry.path()).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn is_generated_partial_name(filename: &str) -> bool {
    filename.len() > 41
        && filename.ends_with(".part")
        && matches!(filename.as_bytes().get(36), Some(b'.') | Some(b'-'))
        && Uuid::parse_str(&filename[..36]).is_ok()
}

async fn fetch_with_safe_redirects(mut url: Url) -> AppResult<(Response, Url)> {
    for redirect_count in 0..=MAX_REDIRECTS {
        let targets = resolve_public_targets(&url).await?;
        let host = url
            .host_str()
            .ok_or_else(|| AppError::Validation("remote image URL has no host".into()))?;
        let mut builder = reqwest::Client::builder()
            .redirect(Policy::none())
            .https_only(true)
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_IDLE_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("vexa-vm/", env!("CARGO_PKG_VERSION")));
        if matches!(url.host(), Some(Host::Domain(_))) {
            builder = builder.resolve_to_addrs(host, &targets);
        }
        let client = builder
            .build()
            .map_err(|_| AppError::Internal("remote image client could not be built".into()))?;
        let response = client
            .get(url.clone())
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    AppError::Conflict("remote image request timed out".into())
                } else {
                    AppError::Conflict("remote image request failed".into())
                }
            })?;

        let peer = response
            .remote_addr()
            .ok_or_else(|| AppError::Conflict("remote image server address could not be verified".into()))?;
        if !is_public_ip(peer.ip())
            || !targets
                .iter()
                .any(|target| target.ip() == peer.ip() && target.port() == peer.port())
        {
            return Err(AppError::Validation(
                "remote image connection resolved to a non-public or unexpected address".into(),
            ));
        }

        if is_followable_redirect(response.status()) {
            if redirect_count == MAX_REDIRECTS {
                return Err(AppError::Conflict(
                    "remote image URL exceeded five redirects".into(),
                ));
            }
            let location = response
                .headers()
                .get(LOCATION)
                .ok_or_else(|| AppError::Conflict("remote image redirect has no location".into()))?
                .to_str()
                .map_err(|_| AppError::Conflict("remote image redirect is invalid".into()))?;
            url = redirect_target(&url, location)?;
            continue;
        }

        if !response.status().is_success() {
            return Err(AppError::Conflict(format!(
                "remote image server returned HTTP {}",
                response.status().as_u16()
            )));
        }
        return Ok((response, url));
    }
    Err(AppError::Internal("remote image redirect handling failed".into()))
}

async fn resolve_public_targets(url: &Url) -> AppResult<Vec<SocketAddr>> {
    let port = url
        .port_or_known_default()
        .ok_or_else(|| AppError::Validation("remote image URL has no usable port".into()))?;
    let addresses = match url.host() {
        Some(Host::Ipv4(address)) => vec![SocketAddr::new(IpAddr::V4(address), port)],
        Some(Host::Ipv6(address)) => vec![SocketAddr::new(IpAddr::V6(address), port)],
        Some(Host::Domain(host)) => tokio::time::timeout(CONNECT_TIMEOUT, lookup_host((host, port)))
            .await
            .map_err(|_| AppError::Conflict("remote image DNS lookup timed out".into()))?
            .map_err(|_| AppError::Conflict("remote image host could not be resolved".into()))?
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    if addresses.is_empty() {
        return Err(AppError::Conflict(
            "remote image host did not resolve to an address".into(),
        ));
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(AppError::Validation(
            "remote image hosts must resolve only to globally routable addresses".into(),
        ));
    }
    let mut unique = Vec::with_capacity(addresses.len());
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    Ok(unique)
}

fn redirect_target(current: &Url, location: &str) -> AppResult<Url> {
    let target = current
        .join(location)
        .map_err(|_| AppError::Conflict("remote image redirect is invalid".into()))?;
    validate_source_url(target.as_str())
}

fn is_followable_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn response_length(response: &Response) -> Option<u64> {
    response.content_length().or_else(|| {
        response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    })
}

fn transfer_capacity_reservation(declared_size: Option<u64>) -> u64 {
    // A caller-provided expected size is an integrity assertion, not a safe
    // allocation bound. Chunked responses without Content-Length must reserve
    // the full stream limit so a false small expectation cannot fill the node.
    declared_size.unwrap_or(MAX_REMOTE_IMAGE_BYTES)
}

pub async fn ensure_storage_capacity(storage_root: &Path, image_bytes: u64) -> AppResult<()> {
    let available = crate::host::filesystem_available_bytes(storage_root).await?;
    let required = image_bytes
        .checked_add(MIN_FREE_AFTER_DOWNLOAD_BYTES)
        .ok_or_else(|| AppError::Validation("remote image is too large".into()))?;
    if available < required {
        return Err(AppError::Conflict(format!(
            "image storage needs at least {required} free bytes for this download and safety reserve"
        )));
    }
    Ok(())
}

fn validate_declared_length(length: Option<u64>, expected_size: Option<u64>) -> AppResult<()> {
    let Some(length) = length else {
        return Ok(());
    };
    if length > MAX_REMOTE_IMAGE_BYTES {
        return Err(AppError::Validation(
            "remote image exceeds the 16 GiB limit".into(),
        ));
    }
    if expected_size.is_some_and(|expected| expected != length) {
        return Err(AppError::Conflict(
            "remote image Content-Length does not match the expected size".into(),
        ));
    }
    Ok(())
}

async fn stream_and_verify<S, B, E>(
    stream: S,
    partial_path: &Path,
    final_path: &Path,
    expected_sha256: &str,
    expected_size: Option<u64>,
    maximum_size: u64,
) -> AppResult<DownloadedImage>
where
    S: futures_util::Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
{
    let result = stream_and_verify_inner(
        stream,
        partial_path,
        final_path,
        expected_sha256,
        expected_size,
        maximum_size,
    )
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(partial_path).await;
    }
    result
}

async fn stream_and_verify_inner<S, B, E>(
    stream: S,
    partial_path: &Path,
    final_path: &Path,
    expected_sha256: &str,
    expected_size: Option<u64>,
    maximum_size: u64,
) -> AppResult<DownloadedImage>
where
    S: futures_util::Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
{
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(partial_path)?;
    // Synchronous removal in Drop is intentional: it also runs if the HTTP
    // request future is cancelled by a timeout or service shutdown.
    let mut file_cleanup = TransferFileCleanup::new(partial_path, final_path);
    let mut file = tokio::fs::File::from_std(file);
    futures_util::pin_mut!(stream);
    let mut digest = Sha256::new();
    let mut size_bytes = 0_u64;

    loop {
        let next = tokio::time::timeout(READ_IDLE_TIMEOUT, stream.next())
            .await
            .map_err(|_| AppError::Conflict("remote image download stalled".into()))?;
        let Some(chunk) = next else { break };
        let chunk = chunk.map_err(|_| AppError::Conflict("remote image download stream failed".into()))?;
        let chunk = chunk.as_ref();
        size_bytes = size_bytes
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| AppError::Validation("remote image is too large".into()))?;
        if size_bytes > maximum_size {
            return Err(AppError::Validation(
                "remote image exceeds the 16 GiB limit".into(),
            ));
        }
        if expected_size.is_some_and(|expected| size_bytes > expected) {
            return Err(AppError::Conflict(
                "downloaded image exceeds the expected size".into(),
            ));
        }
        digest.update(chunk);
        file.write_all(chunk).await?;
    }
    file.sync_all().await?;
    drop(file);

    if expected_size.is_some_and(|expected| expected != size_bytes) {
        return Err(AppError::Conflict(
            "downloaded image size does not match the expected size".into(),
        ));
    }
    let sha256 = format!("{:x}", digest.finalize());
    if sha256 != expected_sha256 {
        return Err(AppError::Conflict(
            "downloaded image SHA-256 does not match; the file was discarded".into(),
        ));
    }

    tokio::fs::rename(partial_path, final_path).await?;
    // No await may occur between the rename completing and transferring final
    // ownership to DownloadedImage. If cancellation lands at the rename await
    // boundary, the armed guard removes both possible paths.
    file_cleanup.retain();
    Ok(DownloadedImage {
        path: final_path.to_path_buf(),
        size_bytes,
        sha256,
        cleanup_on_drop: true,
    })
}

fn image_extension(url: &Url) -> Option<String> {
    let filename = url.path_segments()?.next_back()?;
    let extension = Path::new(filename).extension()?.to_str()?.to_ascii_lowercase();
    matches!(extension.as_str(), "iso" | "qcow" | "qcow2" | "raw" | "img").then_some(extension)
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = address.segments();
    // Only currently allocated global-unicast space is accepted. Exclude the
    // documentation range and transition mechanisms whose embedded address
    // can otherwise undermine destination checks.
    (segments[0] & 0xe000) == 0x2000
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && !(segments[0] == 0x2001 && segments[1] == 0)
        && (segments[0] != 0x2002
            || is_public_ipv4(Ipv4Addr::new(
                (segments[1] >> 8) as u8,
                segments[1] as u8,
                (segments[2] >> 8) as u8,
                segments[2] as u8,
            )))
}

pub struct ImageOperationGuard {
    key: String,
    image_transfer: bool,
}

struct TransferFileCleanup {
    partial_path: PathBuf,
    final_path: PathBuf,
    retain_final: bool,
}

impl TransferFileCleanup {
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

impl Drop for TransferFileCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.partial_path);
        if !self.retain_final {
            let _ = std::fs::remove_file(&self.final_path);
        }
    }
}

impl ImageOperationGuard {
    pub fn acquire(key: &str) -> AppResult<Self> {
        let operations = ACTIVE_OPERATIONS.get_or_init(|| Mutex::new(ActiveOperations::default()));
        let mut operations = operations
            .lock()
            .map_err(|_| AppError::Internal("image operation lock was poisoned".into()))?;
        if !operations.records.insert(key.to_owned()) {
            return Err(AppError::Conflict(
                "an image operation is already active for this catalog entry".into(),
            ));
        }
        Ok(Self {
            key: key.to_owned(),
            image_transfer: false,
        })
    }

    pub fn begin_image_transfer(&mut self) -> AppResult<()> {
        if self.image_transfer {
            return Ok(());
        }
        let operations = ACTIVE_OPERATIONS.get_or_init(|| Mutex::new(ActiveOperations::default()));
        let mut operations = operations
            .lock()
            .map_err(|_| AppError::Internal("image operation lock was poisoned".into()))?;
        if operations.image_transfers >= MAX_SIMULTANEOUS_IMAGE_TRANSFERS {
            return Err(AppError::Conflict(
                "the node is already transferring an image".into(),
            ));
        }
        operations.image_transfers += 1;
        self.image_transfer = true;
        Ok(())
    }
}

impl Drop for ImageOperationGuard {
    fn drop(&mut self) {
        if let Some(operations) = ACTIVE_OPERATIONS.get() {
            if let Ok(mut operations) = operations.lock() {
                operations.records.remove(&self.key);
                if self.image_transfer {
                    operations.image_transfers = operations.image_transfers.saturating_sub(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_normalizes_https_source() {
        let url = validate_source_url(" https://images.example.test/os/image.qcow2#ignored ").unwrap();
        assert_eq!(url.as_str(), "https://images.example.test/os/image.qcow2");
    }

    #[test]
    fn rejects_unsafe_source_urls() {
        for value in [
            "http://example.com/image.iso",
            "file:///etc/passwd",
            "https://user:secret@example.com/image.iso",
            "https://example.com:8443/image.iso",
            "https:///image.iso",
            "not a URL",
        ] {
            assert!(validate_source_url(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn validates_expected_sha256_strictly() {
        let uppercase = "A".repeat(64);
        assert_eq!(validate_sha256(&uppercase).unwrap(), "a".repeat(64));
        for value in ["", "abc"] {
            assert!(validate_sha256(value).is_err());
        }
        for value in ["g".repeat(64), "a".repeat(63), "a".repeat(65)] {
            assert!(validate_sha256(&value).is_err());
        }
    }

    #[test]
    fn blocks_non_public_ipv4_destinations() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.0.1",
            "192.0.2.10",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "accepted {address}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn blocks_non_public_and_transition_ipv6_destinations() {
        for address in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2001::1",
            "2002:7f00:0001::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "accepted {address}");
        }
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn every_redirect_is_revalidated() {
        let current = Url::parse("https://downloads.example/os/image.iso").unwrap();
        assert_eq!(
            redirect_target(&current, "/releases/image.iso").unwrap().as_str(),
            "https://downloads.example/releases/image.iso"
        );
        assert!(redirect_target(&current, "http://other.example/image.iso").is_err());
        assert!(redirect_target(&current, "https://user:pass@other.example/image.iso").is_err());
        assert!(redirect_target(&current, "https://other.example:8443/image.iso").is_err());
    }

    #[tokio::test]
    async fn literal_ssrf_targets_are_rejected_before_a_request() {
        for value in [
            "https://127.0.0.1/image.iso",
            "https://169.254.169.254/latest/image.iso",
            "https://[::1]/image.iso",
            "https://[fe80::1]/image.iso",
        ] {
            let url = validate_source_url(value).unwrap();
            assert!(resolve_public_targets(&url).await.is_err(), "accepted {value}");
        }
    }

    #[test]
    fn declared_length_is_bounded_and_must_match() {
        assert!(validate_declared_length(None, None).is_ok());
        assert!(validate_declared_length(Some(1024), Some(1024)).is_ok());
        assert!(validate_declared_length(Some(1024), Some(2048)).is_err());
        assert!(validate_declared_length(Some(MAX_REMOTE_IMAGE_BYTES + 1), None).is_err());
    }

    #[test]
    fn only_supported_image_extensions_are_published() {
        for value in ["image.iso", "disk.qcow", "disk.qcow2", "disk.raw", "disk.img"] {
            let url = Url::parse(&format!("https://example.test/{value}?token=redacted")).unwrap();
            assert!(image_extension(&url).is_some());
        }
        let url = Url::parse("https://example.test/archive.tar.gz").unwrap();
        assert!(image_extension(&url).is_none());
    }

    #[test]
    fn duplicate_operations_and_excess_downloads_are_rejected() {
        let mut first = ImageOperationGuard::acquire("same-record").unwrap();
        assert!(ImageOperationGuard::acquire("same-record").is_err());
        first.begin_image_transfer().unwrap();
        let mut second = ImageOperationGuard::acquire("second-record").unwrap();
        assert!(second.begin_image_transfer().is_err());
        drop(first);
        second.begin_image_transfer().unwrap();
        assert!(ImageOperationGuard::acquire("same-record").is_ok());
    }

    #[test]
    fn chunked_transfers_reserve_the_full_stream_limit() {
        assert_eq!(transfer_capacity_reservation(None), MAX_REMOTE_IMAGE_BYTES);
        assert_eq!(transfer_capacity_reservation(Some(1024)), 1024);
    }

    #[tokio::test]
    async fn startup_cleanup_only_removes_generated_regular_partial_files() {
        let directory = tempfile::tempdir().unwrap();
        let generated = directory.path().join(format!("{}.iso.part", Uuid::new_v4()));
        let uploaded = directory.path().join(format!("{}-ubuntu.part", Uuid::new_v4()));
        let user_file = directory.path().join("my-image.part");
        let complete = directory.path().join(format!("{}.iso", Uuid::new_v4()));
        tokio::fs::write(&generated, b"partial").await.unwrap();
        tokio::fs::write(&uploaded, b"partial").await.unwrap();
        tokio::fs::write(&user_file, b"keep").await.unwrap();
        tokio::fs::write(&complete, b"keep").await.unwrap();

        assert_eq!(cleanup_stale_partial_files(directory.path()).await.unwrap(), 0);
        assert!(generated.exists());
        assert!(uploaded.exists());

        assert_eq!(
            cleanup_partial_files_before(directory.path(), SystemTime::now() + Duration::from_secs(1),)
                .await
                .unwrap(),
            2
        );
        assert!(!generated.exists());
        assert!(!uploaded.exists());
        assert!(user_file.exists());
        assert!(complete.exists());
    }

    #[tokio::test]
    async fn verified_stream_is_published_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let partial = directory.path().join("image.iso.part");
        let final_path = directory.path().join("image.iso");
        let body = b"verified image bytes";
        let expected = format!("{:x}", Sha256::digest(body));
        let stream = futures_util::stream::iter([Ok::<_, ()>(&body[..8]), Ok::<_, ()>(&body[8..])]);

        let image = stream_and_verify(
            stream,
            &partial,
            &final_path,
            &expected,
            Some(body.len() as u64),
            1024,
        )
        .await
        .unwrap();

        assert_eq!(image.size_bytes, body.len() as u64);
        assert_eq!(image.sha256, expected);
        assert_eq!(tokio::fs::read(&final_path).await.unwrap(), body);
        assert!(!partial.exists());
        drop(image);
        assert!(!final_path.exists());
    }

    #[tokio::test]
    async fn checksum_mismatch_or_size_limit_never_publishes() {
        let directory = tempfile::tempdir().unwrap();
        let partial = directory.path().join("bad.iso.part");
        let final_path = directory.path().join("bad.iso");
        let stream = futures_util::stream::iter([Ok::<_, ()>(b"untrusted".as_slice())]);
        let result = stream_and_verify(stream, &partial, &final_path, &"0".repeat(64), None, 1024).await;
        assert!(result.is_err());
        assert!(!partial.exists());
        assert!(!final_path.exists());

        let stream = futures_util::stream::iter([Ok::<_, ()>(b"larger than expected".as_slice())]);
        let result = stream_and_verify(
            stream,
            &partial,
            &final_path,
            &format!("{:x}", Sha256::digest(b"larger than expected")),
            Some(3),
            1024,
        )
        .await;
        assert!(result.is_err());
        assert!(!partial.exists());
        assert!(!final_path.exists());

        let stream = futures_util::stream::iter([Ok::<_, ()>(b"too large".as_slice())]);
        let result = stream_and_verify(
            stream,
            &partial,
            &final_path,
            &format!("{:x}", Sha256::digest(b"too large")),
            None,
            3,
        )
        .await;
        assert!(result.is_err());
        assert!(!partial.exists());
        assert!(!final_path.exists());
    }
}
