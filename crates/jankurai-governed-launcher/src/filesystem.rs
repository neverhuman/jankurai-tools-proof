use super::{BoundaryError, Identity, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) fn ensure_contained(root: &Path, path: &Path) -> Result<()> {
    if !root.is_absolute() || !path.is_absolute() || path == root || !path.starts_with(root) {
        return Err(BoundaryError("governed path is outside the trusted root"));
    }
    Ok(())
}

pub(super) fn ensure_directory_chain(root: &Path, path: &Path, effective_uid: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(BoundaryError("governed path has no parent"))?;
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| BoundaryError("governed path escaped the trusted root"))?;
    let mut current = root.to_path_buf();
    validate_directory(&current, effective_uid)?;
    for component in relative.components() {
        current.push(component.as_os_str());
        validate_directory(&current, effective_uid)?;
    }
    Ok(())
}

fn validate_directory(path: &Path, effective_uid: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| BoundaryError("trusted directory is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BoundaryError(
            "trusted directory is not a physical directory",
        ));
    }
    if metadata.uid() != effective_uid {
        return Err(BoundaryError("trusted directory has the wrong owner"));
    }
    if metadata.mode() & 0o002 != 0 {
        return Err(BoundaryError("trusted directory is world writable"));
    }
    Ok(())
}

pub(super) fn open_regular(
    path: &Path,
    effective_uid: u32,
    exact_mode: u32,
    maximum_size: u64,
) -> Result<(File, Identity)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| BoundaryError("governed file could not be opened safely"))?;
    let metadata = file
        .metadata()
        .map_err(|_| BoundaryError("governed file metadata is unavailable"))?;
    let identity = Identity::from(&metadata);
    validate_regular_identity(
        identity,
        metadata.is_file(),
        effective_uid,
        exact_mode,
        maximum_size,
    )?;
    require_stable_path(path, identity)?;
    Ok((file, identity))
}

pub(super) fn validate_regular_identity(
    identity: Identity,
    is_regular: bool,
    effective_uid: u32,
    exact_mode: u32,
    maximum_size: u64,
) -> Result<()> {
    if !is_regular {
        return Err(BoundaryError("governed file is not regular"));
    }
    if identity.uid != effective_uid {
        return Err(BoundaryError("governed file has the wrong owner"));
    }
    if identity.mode != exact_mode {
        return Err(BoundaryError("governed file has the wrong mode"));
    }
    if identity.links != 1 {
        return Err(BoundaryError("governed file has an unsafe link count"));
    }
    if identity.length == 0 || identity.length > maximum_size {
        return Err(BoundaryError("governed file has an invalid size"));
    }
    Ok(())
}

pub(super) fn require_stable_path(path: &Path, expected: Identity) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| BoundaryError("governed path disappeared during validation"))?;
    if metadata.file_type().is_symlink() || Identity::from(&metadata) != expected {
        return Err(BoundaryError("governed path changed during validation"));
    }
    Ok(())
}

pub(super) fn require_stable_fd(file: &File, expected: Identity) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|_| BoundaryError("governed descriptor changed during validation"))?;
    if Identity::from(&metadata) != expected {
        return Err(BoundaryError(
            "governed descriptor changed during validation",
        ));
    }
    Ok(())
}

pub(super) fn read_bounded(file: &mut File, maximum_size: u64) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BoundaryError("governed file seek failed"))?;
    let mut bytes = Vec::new();
    file.take(maximum_size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BoundaryError("governed file read failed"))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_size {
        return Err(BoundaryError("governed file exceeded its size bound"));
    }
    Ok(bytes)
}
