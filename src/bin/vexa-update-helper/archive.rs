//! Constrained extraction for signed Vexa-VM release archives.
//!
//! Release archives are treated as hostile even after signature verification.
//! This module manually materializes the small set of paths a Vexa release may
//! contain; it never delegates path handling, links, ownership, timestamps, or
//! permissions to `tar`.

use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};

const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRY_COUNT: usize = 32_768;
const MAX_PATH_BYTES: usize = 1024;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const MAX_PATH_COMPONENTS: usize = 48;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_VERSION_BYTES: u64 = 128;
const MAX_TAR_PADDING_BYTES: u64 = 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 128 * 1024;

const ALLOWED_DIRECTORIES: &[&str] = &[
    "bin",
    "templates",
    "static",
    "migrations",
    "deploy",
    "docs",
    "guest-tools",
];
const ALLOWED_ROOT_FILES: &[&str] = &["VERSION", "README.md", "LICENSE"];
pub(crate) const REQUIRED_RELEASE_FILES: &[&str] = &[
    "bin/vexa-vm",
    "bin/vexa-update-helper",
    "VERSION",
    "README.md",
    "LICENSE",
    "templates/base.html",
    "templates/docs.html",
    "templates/error.html",
    "templates/isos.html",
    "templates/login.html",
    "templates/logs.html",
    "templates/network.html",
    "templates/overall.html",
    "templates/public_base.html",
    "templates/settings.html",
    "templates/status.html",
    "templates/vm_create.html",
    "templates/vm_detail.html",
    "templates/vms.html",
    "templates/vnc.html",
    "static/css/app.css",
    "static/images/vexa-vm-emblem.png",
    "static/js/app.js",
    "static/vendor/novnc/LICENSE.txt",
    "static/vendor/novnc/core/rfb.js",
    "guest-tools/vexa-guest-tools-linux-x86_64",
    "guest-tools/vexa-guest-tools-windows-x86_64.exe",
    "deploy/vexa-vm.service",
    "deploy/vexa-update-executor-ready.service",
    "deploy/vexa-update-dispatch.service",
    "deploy/vexa-update-dispatch.path",
];

/// The small amount of trusted metadata produced by a successful extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedRelease {
    pub destination: PathBuf,
    pub version: String,
    pub entry_count: usize,
    pub unpacked_bytes: u64,
}

/// Extract a signed release archive into a new, private destination directory.
///
/// `expected_size_bytes` and `expected_sha256` must come from the verified
/// release manifest. The archive is opened once with `O_NOFOLLOW`; that same
/// descriptor is hashed, rewound, decompressed, and hashed again. The caller
/// must provide an absolute destination whose existing parent is trusted and
/// not group/world writable. `destination` itself must not already exist.
pub fn extract_release(
    archive: &Path,
    destination: &Path,
    expected_size_bytes: u64,
    expected_sha256: &str,
) -> Result<ExtractedRelease> {
    validate_expected_archive(expected_size_bytes, expected_sha256)?;
    let mut archive_file = open_archive_nofollow(archive)?;
    verify_open_archive(
        &mut archive_file,
        expected_size_bytes,
        expected_sha256,
    )?;

    validate_destination(destination)?;
    std::fs::create_dir(destination)
        .context("release extraction destination could not be created")?;
    let mut cleanup = PartialExtraction::new(destination.to_path_buf());
    secure_created_directory(destination)
        .context("release extraction destination could not be secured")?;

    let reader = BufReader::with_capacity(COPY_BUFFER_BYTES, archive_file);
    let decoder = GzDecoder::new(reader);
    let mut tar_archive = tar::Archive::new(decoder);
    let mut seen_entries = HashSet::new();
    let mut regular_files = HashSet::new();
    let mut created_directories = HashSet::new();
    created_directories.insert(destination.to_path_buf());
    let mut entry_count = 0usize;
    let mut unpacked_bytes = 0u64;
    let mut version_bytes = None;

    let entries = tar_archive
        .entries()
        .context("release archive is not a readable tar stream")?
        // Surface GNU/PAX metadata records instead of letting `tar` allocate
        // and apply them before our per-entry/type/path limits run. Release
        // archives use normalized ustar-compatible paths and need no extended
        // metadata.
        .raw(true);
    for entry in entries {
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("release archive entry count overflowed"))?;
        if entry_count > MAX_ENTRY_COUNT {
            bail!("release archive contains too many entries");
        }

        let mut entry = entry.context("release archive contains an invalid tar entry")?;
        let entry_type = entry.header().entry_type();
        let is_directory = entry_type.is_dir();
        if !is_directory && !entry_type.is_file() {
            bail!("release archive contains a non-regular entry");
        }

        let relative = validate_archive_path(entry.path_bytes().as_ref(), is_directory)?;
        let relative_key = relative_to_key(&relative)?;
        if !seen_entries.insert(relative_key.clone()) {
            bail!("release archive contains duplicate path {relative_key:?}");
        }

        let declared_size = entry
            .header()
            .size()
            .context("release archive entry has an invalid size")?;
        if is_directory {
            if declared_size != 0 {
                bail!("release archive directory {relative_key:?} has file data");
            }
            ensure_release_directory(
                destination,
                &relative,
                &mut created_directories,
            )?;
            continue;
        }

        if declared_size > MAX_FILE_BYTES {
            bail!("release archive file {relative_key:?} exceeds its size limit");
        }
        if declared_size == 0 && REQUIRED_RELEASE_FILES.contains(&relative_key.as_str()) {
            bail!("required release file {relative_key:?} is empty");
        }
        if relative_key == "VERSION" && declared_size > MAX_VERSION_BYTES {
            bail!("release VERSION file exceeds its size limit");
        }
        unpacked_bytes = unpacked_bytes
            .checked_add(declared_size)
            .ok_or_else(|| anyhow!("release archive total size overflowed"))?;
        if unpacked_bytes > MAX_TOTAL_FILE_BYTES {
            bail!("release archive exceeds its total unpacked size limit");
        }

        ensure_parent_directories(destination, &relative, &mut created_directories)?;
        let output_path = destination.join(&relative);
        let captured = write_regular_file(
            &mut entry,
            &output_path,
            declared_size,
            is_executable_payload(&relative),
            relative_key == "VERSION",
        )?;
        if relative_key == "VERSION" {
            version_bytes = captured;
        }
        regular_files.insert(relative_key);
    }

    let decoder = tar_archive.into_inner();
    let mut decoder = drain_and_validate_gzip(decoder)?;
    let buffered = u64::try_from(decoder.get_ref().buffer().len())
        .context("gzip buffer size is not representable")?;
    let physical_position = decoder
        .get_mut()
        .get_mut()
        .stream_position()
        .context("release archive position could not be read")?;
    let gzip_end = physical_position
        .checked_sub(buffered)
        .ok_or_else(|| anyhow!("release archive gzip position is invalid"))?;
    if gzip_end != expected_size_bytes {
        bail!("release archive contains data after its gzip member");
    }
    let mut archive_file = decoder.into_inner().into_inner();
    verify_open_archive(
        &mut archive_file,
        expected_size_bytes,
        expected_sha256,
    )
    .context("release archive changed while it was being extracted")?;

    for required in REQUIRED_RELEASE_FILES {
        if !regular_files.contains(*required) {
            bail!("release archive is missing required file {required:?}");
        }
    }
    let version = parse_version_file(
        version_bytes
            .as_deref()
            .ok_or_else(|| anyhow!("release archive VERSION file was not captured"))?,
    )?;

    finalize_directory_permissions(&created_directories, destination)?;
    sync_directory(destination)?;
    if let Some(parent) = destination.parent() {
        sync_directory(parent)?;
    }
    cleanup.commit();

    Ok(ExtractedRelease {
        destination: destination.to_path_buf(),
        version,
        entry_count,
        unpacked_bytes,
    })
}

fn validate_expected_archive(expected_size_bytes: u64, expected_sha256: &str) -> Result<()> {
    if expected_size_bytes == 0 || expected_size_bytes > MAX_ARCHIVE_BYTES {
        bail!("signed release archive size is outside its allowed range");
    }
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("signed release archive SHA-256 must be lowercase hexadecimal");
    }
    Ok(())
}

fn open_archive_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux O_NOFOLLOW; the update helper is a Linux-only root helper.
        options.custom_flags(0x0002_0000);
    }
    let file = options
        .open(path)
        .context("release archive could not be opened")?;
    let metadata = file
        .metadata()
        .context("release archive metadata could not be read")?;
    if !metadata.file_type().is_file() {
        bail!("release archive is not a regular file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_ARCHIVE_BYTES {
        bail!("release archive size is outside its allowed range");
    }
    Ok(file)
}

fn verify_open_archive(file: &mut File, expected_size: u64, expected_sha256: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .context("release archive metadata could not be read")?;
    if !metadata.file_type().is_file() || metadata.len() != expected_size {
        bail!("release archive does not match its signed size");
    }

    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut observed_size = 0u64;
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(u64::try_from(read).context("archive read size is not representable")?)
            .ok_or_else(|| anyhow!("release archive read size overflowed"))?;
        if observed_size > expected_size {
            bail!("release archive grew while it was being verified");
        }
        hasher.update(&buffer[..read]);
    }
    if observed_size != expected_size {
        bail!("release archive does not match its signed size");
    }
    let observed_sha256 = lowercase_hex(&hasher.finalize());
    if observed_sha256 != expected_sha256 {
        bail!("release archive does not match its signed SHA-256");
    }
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 3];
    file.read_exact(&mut magic)
        .context("release archive gzip header could not be read")?;
    if magic != [0x1f, 0x8b, 0x08] {
        bail!("release archive is not gzip-compressed");
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn validate_destination(destination: &Path) -> Result<()> {
    if !destination.is_absolute()
        || destination.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        bail!("release destination must be an absolute normalized path");
    }
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("release destination has no parent"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .context("release destination parent metadata could not be read")?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        bail!("release destination parent is not a real directory");
    }
    let canonical_parent = std::fs::canonicalize(parent)
        .context("release destination parent could not be resolved")?;
    if canonical_parent != parent {
        bail!("release destination parent must not traverse symbolic links");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if parent_metadata.mode() & 0o022 != 0 {
            bail!("release destination parent must not be group/world writable");
        }
    }
    match std::fs::symlink_metadata(destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("release destination metadata could not be read"),
        Ok(_) => bail!("release destination already exists"),
    }
}

fn validate_archive_path(raw_path: &[u8], is_directory: bool) -> Result<PathBuf> {
    if raw_path.is_empty() || raw_path.len() > MAX_PATH_BYTES {
        bail!("release archive path is outside its length limit");
    }
    let raw_path = std::str::from_utf8(raw_path)
        .context("release archive path is not valid UTF-8")?;
    if raw_path.starts_with('/')
        || raw_path.contains('\0')
        || raw_path.contains('\\')
        || raw_path.chars().any(char::is_control)
    {
        bail!("release archive path is not a safe relative path");
    }

    let normalized = if is_directory {
        raw_path.strip_suffix('/').unwrap_or(raw_path)
    } else {
        raw_path
    };
    if normalized.is_empty()
        || normalized.ends_with('/')
        || normalized.split('/').any(|component| component.is_empty())
    {
        bail!("release archive path is not normalized");
    }
    let components = normalized.split('/').collect::<Vec<_>>();
    if components.len() > MAX_PATH_COMPONENTS {
        bail!("release archive path contains too many components");
    }
    for component in &components {
        if *component == "." || *component == ".." {
            bail!("release archive path contains a traversal component");
        }
        if component.as_bytes().len() > MAX_PATH_COMPONENT_BYTES {
            bail!("release archive path component exceeds its length limit");
        }
    }

    let top = components[0];
    if ALLOWED_ROOT_FILES.contains(&top) {
        if components.len() != 1 || is_directory {
            bail!("release archive root file path is invalid");
        }
    } else if ALLOWED_DIRECTORIES.contains(&top) {
        if components.len() == 1 && !is_directory {
            bail!("release archive top-level directory is a file");
        }
    } else {
        bail!("release archive path is outside the release allowlist");
    }

    let path = PathBuf::from(normalized);
    if path.components().any(|component| {
        !matches!(component, Component::Normal(_))
    }) {
        bail!("release archive path is not normalized");
    }
    Ok(path)
}

fn relative_to_key(relative: &Path) -> Result<String> {
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("release archive path is not valid UTF-8"))
}

fn ensure_parent_directories(
    root: &Path,
    relative: &Path,
    created: &mut HashSet<PathBuf>,
) -> Result<()> {
    if let Some(parent) = relative.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_release_directory(root, parent, created)?;
        }
    }
    Ok(())
}

fn ensure_release_directory(
    root: &Path,
    relative: &Path,
    created: &mut HashSet<PathBuf>,
) -> Result<()> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("release directory path is not normalized");
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    bail!("release path conflicts with a non-directory");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_directory(&current)
                    .with_context(|| format!("release directory {current:?} could not be created"))?;
            }
            Err(error) => return Err(error).context("release directory metadata could not be read"),
        }
        created.insert(current.clone());
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    std::fs::create_dir(path)?;
    secure_created_directory(path)
}

fn secure_created_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("created release path is not a real directory");
    }
    Ok(())
}

fn write_regular_file<R: Read>(
    entry: &mut R,
    output_path: &Path,
    expected_size: u64,
    executable: bool,
    capture: bool,
) -> Result<Option<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(0x0002_0000);
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(output_path)
        .with_context(|| format!("release file {output_path:?} could not be created"))?;
    let mut captured = capture.then(Vec::new);
    let mut copied = 0u64;
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let remaining = expected_size
            .checked_sub(copied)
            .ok_or_else(|| anyhow!("release entry exceeded its declared size"))?;
        if remaining == 0 {
            break;
        }
        let maximum = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
            .context("release entry remaining size is not representable")?;
        let read = entry
            .read(&mut buffer[..maximum])
            .context("release entry could not be read")?;
        if read == 0 {
            bail!("release entry ended before its declared size");
        }
        output.write_all(&buffer[..read])?;
        if let Some(bytes) = captured.as_mut() {
            bytes.extend_from_slice(&buffer[..read]);
        }
        copied = copied
            .checked_add(u64::try_from(read).context("release entry size is not representable")?)
            .ok_or_else(|| anyhow!("release entry size overflowed"))?;
    }
    let mut overrun = [0u8; 1];
    if entry.read(&mut overrun)? != 0 {
        bail!("release entry exceeds its declared size");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        output.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    output.sync_all()?;
    drop(output);
    let metadata = std::fs::symlink_metadata(output_path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("created release path is not a regular file");
    }
    Ok(captured)
}

fn drain_and_validate_gzip<R: io::BufRead>(mut decoder: GzDecoder<R>) -> Result<GzDecoder<R>> {
    let mut trailing = 0u64;
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .context("release archive gzip trailer is invalid")?;
        if read == 0 {
            break;
        }
        trailing = trailing
            .checked_add(u64::try_from(read).context("tar padding size is not representable")?)
            .ok_or_else(|| anyhow!("tar padding size overflowed"))?;
        if trailing > MAX_TAR_PADDING_BYTES || buffer[..read].iter().any(|byte| *byte != 0) {
            bail!("release tar contains unexpected trailing data");
        }
    }
    Ok(decoder)
}

fn is_executable_payload(relative: &Path) -> bool {
    matches!(relative.components().next(), Some(Component::Normal(value)) if value == "bin")
        || relative == Path::new("guest-tools/vexa-guest-tools-linux-x86_64")
}

fn parse_version_file(bytes: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(bytes).context("release VERSION is not valid UTF-8")?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    if value.is_empty()
        || value.len() > MAX_VERSION_BYTES as usize
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        bail!("release VERSION is not a strict semantic version");
    }
    validate_semver(value)?;
    Ok(value.to_owned())
}

fn validate_semver(value: &str) -> Result<()> {
    if !value.is_ascii() {
        bail!("release VERSION is not a strict semantic version");
    }
    let (without_build, build) = match value.split_once('+') {
        Some((base, build)) => (base, Some(build)),
        None => (value, None),
    };
    if let Some(build) = build {
        validate_semver_identifiers(build, false)?;
    }
    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (without_build, None),
    };
    if let Some(prerelease) = prerelease {
        validate_semver_identifiers(prerelease, true)?;
    }
    let core = core.split('.').collect::<Vec<_>>();
    if core.len() != 3 || core.iter().any(|part| !valid_numeric_identifier(part)) {
        bail!("release VERSION is not a strict semantic version");
    }
    Ok(())
}

fn validate_semver_identifiers(value: &str, reject_numeric_leading_zero: bool) -> Result<()> {
    if value.is_empty() {
        bail!("release VERSION is not a strict semantic version");
    }
    for identifier in value.split('.') {
        if identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || (reject_numeric_leading_zero
                && identifier.bytes().all(|byte| byte.is_ascii_digit())
                && !valid_numeric_identifier(identifier))
        {
            bail!("release VERSION is not a strict semantic version");
        }
    }
    Ok(())
}

fn valid_numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn finalize_directory_permissions(created: &HashSet<PathBuf>, root: &Path) -> Result<()> {
    let mut directories = created.iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            bail!("release directory changed during extraction");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
        }
        sync_directory(path)?;
    }
    let root_metadata = std::fs::symlink_metadata(root)?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        bail!("release extraction root changed during extraction");
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

struct PartialExtraction {
    path: PathBuf,
    committed: bool,
}

impl PartialExtraction {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PartialExtraction {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::os::unix::fs::PermissionsExt;
    use tar::{Builder, EntryType, Header};
    use tempfile::TempDir;

    fn append_file(builder: &mut Builder<GzEncoder<File>>, path: &str, bytes: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o777);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }

    fn archive_with(
        mut extra: impl FnMut(&mut Builder<GzEncoder<File>>),
        version: &[u8],
    ) -> (TempDir, PathBuf) {
        let temporary = TempDir::new().unwrap();
        let archive_path = temporary.path().join("release.tar.gz");
        let encoder = GzEncoder::new(File::create(&archive_path).unwrap(), Compression::default());
        let mut builder = Builder::new(encoder);
        append_file(&mut builder, "bin/vexa-vm", b"server");
        append_file(&mut builder, "bin/vexa-update-helper", b"helper");
        append_file(&mut builder, "VERSION", version);
        for path in REQUIRED_RELEASE_FILES {
            if matches!(*path, "bin/vexa-vm" | "bin/vexa-update-helper" | "VERSION") {
                continue;
            }
            append_file(&mut builder, path, b"required release payload");
        }
        extra(&mut builder);
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
        (temporary, archive_path)
    }

    fn signed_properties(path: &Path) -> (u64, String) {
        let bytes = std::fs::read(path).unwrap();
        let digest = Sha256::digest(&bytes);
        (bytes.len() as u64, lowercase_hex(&digest))
    }

    #[test]
    fn extracts_valid_release_with_sanitized_permissions() {
        let (temporary, archive_path) = archive_with(
            |builder| append_file(builder, "docs/UPDATES.md", b"documentation"),
            b"1.2.3-rc.1+build.9\n",
        );
        let destination = temporary.path().join("partial-release");
        let (size, sha256) = signed_properties(&archive_path);

        let extracted = extract_release(&archive_path, &destination, size, &sha256).unwrap();

        assert_eq!(extracted.version, "1.2.3-rc.1+build.9");
        assert_eq!(std::fs::read(destination.join("bin/vexa-vm")).unwrap(), b"server");
        assert_eq!(
            std::fs::metadata(destination.join("bin/vexa-vm"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(destination.join("templates/base.html"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(
                destination.join("guest-tools/vexa-guest-tools-linux-x86_64")
            )
            .unwrap()
            .permissions()
            .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(destination.join("static/css"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    fn rejects_links_and_removes_partial_destination() {
        let (temporary, archive_path) = archive_with(
            |builder| {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Symlink);
                header.set_mode(0o777);
                header.set_size(0);
                header.set_link_name("/etc/passwd").unwrap();
                header.set_cksum();
                builder
                    .append_data(&mut header, "static/escape", io::empty())
                    .unwrap();
            },
            b"1.2.3\n",
        );
        let destination = temporary.path().join("partial-release");
        let (size, sha256) = signed_properties(&archive_path);

        let error = extract_release(&archive_path, &destination, size, &sha256).unwrap_err();

        assert!(error.to_string().contains("non-regular"));
        assert!(!destination.exists());
    }

    #[test]
    fn rejects_an_invalid_version() {
        let (temporary, archive_path) = archive_with(|_| {}, b"01.2.3\n");
        let destination = temporary.path().join("partial-release");
        let (size, sha256) = signed_properties(&archive_path);

        let error = extract_release(&archive_path, &destination, size, &sha256).unwrap_err();

        assert!(error.to_string().contains("semantic version"));
        assert!(!destination.exists());
    }

    #[test]
    fn rejects_a_digest_mismatch_before_creating_destination() {
        let (temporary, archive_path) = archive_with(|_| {}, b"1.2.3\n");
        let destination = temporary.path().join("partial-release");
        let size = std::fs::metadata(&archive_path).unwrap().len();

        let error =
            extract_release(&archive_path, &destination, size, &"0".repeat(64)).unwrap_err();

        assert!(error.to_string().contains("signed SHA-256"));
        assert!(!destination.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn does_not_follow_an_archive_symlink() {
        use std::os::unix::fs::symlink;

        let (temporary, archive_path) = archive_with(|_| {}, b"1.2.3\n");
        let linked_archive = temporary.path().join("linked-release.tar.gz");
        symlink(&archive_path, &linked_archive).unwrap();
        let destination = temporary.path().join("partial-release");
        let (size, sha256) = signed_properties(&archive_path);

        assert!(extract_release(&linked_archive, &destination, size, &sha256).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn path_validator_rejects_traversal_and_non_allowlisted_roots() {
        for path in [
            b"../etc/passwd".as_slice(),
            b"/etc/passwd".as_slice(),
            b"static//app.css".as_slice(),
            b"static/./app.css".as_slice(),
            b"static\\app.css".as_slice(),
            b"Cargo.toml".as_slice(),
        ] {
            assert!(validate_archive_path(path, false).is_err(), "{path:?}");
        }
    }

    #[test]
    fn strict_semver_accepts_and_rejects_expected_forms() {
        for valid in ["0.1.0", "1.2.3-alpha.1", "1.2.3+001", "1.2.3-a-b+c-d"] {
            assert!(validate_semver(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "v1.2.3",
            "1.2",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-01",
            "1.2.3-",
            "1.2.3+",
            "1.2.3+a..b",
            "1.2.3+build+other",
        ] {
            assert!(validate_semver(invalid).is_err(), "{invalid}");
        }
    }
}
