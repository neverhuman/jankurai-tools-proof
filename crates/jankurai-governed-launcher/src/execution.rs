use super::{BoundaryError, Result, VerifiedExecutable};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(super) fn sealed_copy(bytes: &[u8]) -> Result<File> {
    let name = CString::new("jankurai-governed-executable")
        .map_err(|_| BoundaryError("sealed executable name is invalid"))?;
    // SAFETY: name is a live NUL-terminated CString and flags are valid for memfd_create.
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(BoundaryError("sealed executable allocation failed"));
    }
    // SAFETY: descriptor is newly created and ownership is transferred exactly once.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(bytes)
        .map_err(|_| BoundaryError("sealed executable write failed"))?;
    file.flush()
        .map_err(|_| BoundaryError("sealed executable flush failed"))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o500))
        .map_err(|_| BoundaryError("sealed executable mode could not be set"))?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: file owns a valid memfd and F_ADD_SEALS consumes only the integer mask.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(BoundaryError("sealed executable could not be sealed"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BoundaryError("sealed executable seek failed"))?;
    Ok(file)
}

pub(super) fn exec_sealed(
    verified: VerifiedExecutable,
    display_path: &Path,
    arguments: Vec<OsString>,
) -> Result<()> {
    let mut argv = Vec::with_capacity(arguments.len() + 1);
    argv.push(os_to_cstring(display_path.as_os_str())?);
    for argument in arguments {
        argv.push(os_to_cstring(&argument)?);
    }
    let mut argv_pointers = argv.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    argv_pointers.push(std::ptr::null());

    let mut environment = std::env::vars_os()
        .filter(|(name, _)| name != "JANKURAI_BIN" && name != "JANKURAI_NO_UPDATE_CHECK")
        .map(|(name, value)| {
            let mut pair = name;
            pair.push("=");
            pair.push(value);
            os_to_cstring(&pair)
        })
        .collect::<Result<Vec<_>>>()?;
    environment.push(
        CString::new("JANKURAI_NO_UPDATE_CHECK=1")
            .map_err(|_| BoundaryError("governed environment is invalid"))?,
    );
    let mut environment_pointers = environment
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null());

    // SAFETY: the fd owns a sealed executable image; argv/envp are live NUL-terminated
    // CString arrays with trailing null pointers for the duration of fexecve.
    let result = unsafe {
        libc::fexecve(
            verified.sealed_file.as_raw_fd(),
            argv_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    };
    debug_assert_eq!(result, -1);
    Err(BoundaryError("verified executable launch failed"))
}

fn os_to_cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| BoundaryError("argument contains a NUL byte"))
}
