use serde_json::Value;
use std::ffi::{CString, OsStr, OsString};
use std::fmt::{Display, Formatter};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const BINARY_PATH: &str = "/home/ubuntu/.jeryu/bin/jankurai";
const BINARY_SHA256: &str = "fdb42e5fa7d9851c0729e59bf1e582c895aa9cfc03a7175b420c6025d2fd014e";
const RECEIPT_PATH: &str = "/home/ubuntu/.jeryu/receipts/jankurai/sha256/494ea02af28e6aa7fb2f817831dc8f00df102398677779f7decfce55b3b20b98.json";
const RECEIPT_SHA256: &str = "494ea02af28e6aa7fb2f817831dc8f00df102398677779f7decfce55b3b20b98";
const TRUSTED_ROOT: &str = "/home/ubuntu/.jeryu";
const MAX_BINARY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryError(&'static str);

impl Display for BoundaryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for BoundaryError {}

type Result<T> = std::result::Result<T, BoundaryError>;

#[derive(Clone)]
struct Policy {
    trusted_root: PathBuf,
    binary_path: PathBuf,
    binary_sha256: String,
    receipt_path: PathBuf,
    receipt_sha256: String,
}

impl Policy {
    fn production() -> Self {
        Self {
            trusted_root: PathBuf::from(TRUSTED_ROOT),
            binary_path: PathBuf::from(BINARY_PATH),
            binary_sha256: BINARY_SHA256.to_owned(),
            receipt_path: PathBuf::from(RECEIPT_PATH),
            receipt_sha256: RECEIPT_SHA256.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    length: u64,
}

impl Identity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            links: metadata.nlink(),
            length: metadata.len(),
        }
    }
}

#[derive(Debug)]
struct VerifiedExecutable {
    sealed_file: File,
}

pub fn verify_and_exec(arguments: Vec<OsString>) -> Result<()> {
    let policy = Policy::production();
    let verified = verify_with_hook(&policy, || {})?;
    exec_sealed(verified, &policy.binary_path, arguments)
}

fn verify_with_hook<F>(policy: &Policy, hook: F) -> Result<VerifiedExecutable>
where
    F: FnOnce(),
{
    // SAFETY: geteuid has no arguments, does not dereference memory, and cannot violate Rust aliases.
    let effective_uid = unsafe { libc::geteuid() };
    ensure_contained(&policy.trusted_root, &policy.binary_path)?;
    ensure_contained(&policy.trusted_root, &policy.receipt_path)?;
    ensure_directory_chain(&policy.trusted_root, &policy.binary_path, effective_uid)?;
    ensure_directory_chain(&policy.trusted_root, &policy.receipt_path, effective_uid)?;

    let (mut binary, binary_identity) =
        open_regular(&policy.binary_path, effective_uid, 0o755, MAX_BINARY_BYTES)?;
    let (mut receipt, receipt_identity) = open_regular(
        &policy.receipt_path,
        effective_uid,
        0o600,
        MAX_RECEIPT_BYTES,
    )?;

    let receipt_bytes = read_bounded(&mut receipt, MAX_RECEIPT_BYTES)?;
    require_digest(
        &receipt_bytes,
        &policy.receipt_sha256,
        "receipt digest mismatch",
    )?;
    validate_receipt(&receipt_bytes, policy)?;

    let binary_bytes = read_bounded(&mut binary, MAX_BINARY_BYTES)?;
    require_digest(
        &binary_bytes,
        &policy.binary_sha256,
        "binary digest mismatch",
    )?;
    let sealed_file = sealed_copy(&binary_bytes)?;
    require_file_digest(&sealed_file, &policy.binary_sha256)?;

    hook();
    require_stable_path(&policy.binary_path, binary_identity)?;
    require_stable_path(&policy.receipt_path, receipt_identity)?;
    require_stable_fd(&binary, binary_identity)?;
    require_stable_fd(&receipt, receipt_identity)?;

    Ok(VerifiedExecutable { sealed_file })
}

fn ensure_contained(root: &Path, path: &Path) -> Result<()> {
    if !root.is_absolute() || !path.is_absolute() || path == root || !path.starts_with(root) {
        return Err(BoundaryError("governed path is outside the trusted root"));
    }
    Ok(())
}

fn ensure_directory_chain(root: &Path, path: &Path, effective_uid: u32) -> Result<()> {
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

fn open_regular(
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

fn validate_regular_identity(
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

fn require_stable_path(path: &Path, expected: Identity) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| BoundaryError("governed path disappeared during validation"))?;
    if metadata.file_type().is_symlink() || Identity::from(&metadata) != expected {
        return Err(BoundaryError("governed path changed during validation"));
    }
    Ok(())
}

fn require_stable_fd(file: &File, expected: Identity) -> Result<()> {
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

fn read_bounded(file: &mut File, maximum_size: u64) -> Result<Vec<u8>> {
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

fn digest_hex(bytes: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_length = (bytes.len() as u64).wrapping_mul(8);
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let upper_e = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let first = h
                .wrapping_add(upper_e)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let upper_a = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = upper_a.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    state
        .iter()
        .map(|word| format!("{word:08x}"))
        .collect::<String>()
}

fn require_digest(bytes: &[u8], expected: &str, message: &'static str) -> Result<()> {
    if digest_hex(bytes) != expected {
        return Err(BoundaryError(message));
    }
    Ok(())
}

fn require_file_digest(file: &File, expected: &str) -> Result<()> {
    let mut copy = file
        .try_clone()
        .map_err(|_| BoundaryError("sealed executable could not be duplicated"))?;
    let bytes = read_bounded(&mut copy, MAX_BINARY_BYTES)?;
    require_digest(&bytes, expected, "sealed executable digest mismatch")
}

fn sealed_copy(bytes: &[u8]) -> Result<File> {
    let name = CString::new("jankurai-governed-executable")
        .map_err(|_| BoundaryError("sealed executable name is invalid"))?;
    // SAFETY: name is a live NUL-terminated CString and both flags are valid for memfd_create.
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(BoundaryError("sealed executable allocation failed"));
    }
    // SAFETY: descriptor is a newly created positive fd and ownership is transferred exactly once.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(bytes)
        .map_err(|_| BoundaryError("sealed executable write failed"))?;
    file.flush()
        .map_err(|_| BoundaryError("sealed executable flush failed"))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o500))
        .map_err(|_| BoundaryError("sealed executable mode could not be set"))?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: file owns a valid memfd and F_ADD_SEALS consumes only the integer seal mask.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(BoundaryError("sealed executable could not be sealed"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BoundaryError("sealed executable seek failed"))?;
    Ok(file)
}

fn validate_receipt(bytes: &[u8], policy: &Policy) -> Result<()> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| BoundaryError("governed receipt is not valid JSON"))?;
    expect_string(&value, "/schema", "jeryu.jankurai-installation/v1")?;
    expect_string(
        &value,
        "/source/remote",
        "http://127.0.0.1:8787/git/jeryu/jankurai.git",
    )?;
    expect_string(
        &value,
        "/source/commit",
        "dface7397fe24d46b0b1885ddd5782c34edbff49",
    )?;
    expect_string(&value, "/source/tag", "v1.6.11-deadlang-precision-split.1")?;
    expect_string(
        &value,
        "/source/tree",
        "34a8a1fb59bc4ebfadf12c45d95f169d06acc781",
    )?;
    expect_string(
        &value,
        "/source/archive_sha256",
        "2fbca5d04083e3c8d32f383d5b6b4520b8911690b26968c6fbcb210e1202b938",
    )?;
    expect_string(
        &value,
        "/source/cargo_lock_sha256",
        "b9acb981c326226a687d0b6703e4f7ee303148e9e1a6dda1aa03d77988820f6a",
    )?;
    expect_string(&value, "/source/verification", "release-authoritative")?;
    expect_string(
        &value,
        "/build/rustc",
        "rustc 1.95.0 (59807616e 2026-04-14)",
    )?;
    expect_string(
        &value,
        "/build/cargo",
        "cargo 1.95.0 (f2d3ce0bd 2026-03-21)",
    )?;
    expect_string(&value, "/build/target_triple", "x86_64-unknown-linux-gnu")?;
    expect_string(
        &value,
        "/build/mode",
        "cargo-install-locked-offline-path-v1",
    )?;
    for pointer in [
        "/build/cargo_net_offline",
        "/build/dedicated_cargo_home",
        "/build/git_global_config_disabled",
        "/build/git_system_config_disabled",
        "/build/git_http_follow_redirects",
        "/build/git_terminal_prompt",
        "/build/jankurai_update_check",
    ] {
        let expected = !matches!(
            pointer,
            "/build/git_http_follow_redirects"
                | "/build/git_terminal_prompt"
                | "/build/jankurai_update_check"
        );
        expect_bool(&value, pointer, expected)?;
    }
    expect_string(
        &value,
        "/build/network_scope",
        "local-forge-source-plus-offline-cargo",
    )?;
    expect_string(&value, "/build/no_proxy", "127.0.0.1,localhost,::1")?;
    expect_string(&value, "/binary/sha256", &policy.binary_sha256)?;
    expect_string(&value, "/binary/version_output", "jankurai 1.6.11")?;
    expect_string(
        &value,
        "/installation/path",
        &policy.binary_path.to_string_lossy(),
    )?;
    expect_bool(&value, "/installation/atomic", true)?;
    expect_string(&value, "/governance/status", "governed")?;
    expect_string(
        &value,
        "/governance/manifest_repo",
        "http://127.0.0.1:8787/git/jeryu/jeryu-tool.git",
    )?;
    expect_string(
        &value,
        "/governance/manifest_commit",
        "de80b657e1be5580289dfecdc0cd3c71348261e0",
    )?;
    expect_string(
        &value,
        "/governance/manifest_tree",
        "8dd6f773dce3ec2e5a82c8f0b606c240760489f9",
    )?;
    expect_string(
        &value,
        "/governance/manifest_sha256",
        "707f57b7f60b65025303315b050cc1c138c7fb2e2080e775ef97a971f286e9b5",
    )?;
    expect_bool(&value, "/governance/protected_main", true)?;
    expect_string(&value, "/governance/protection_policy", "immutable-main-v1")?;
    expect_bool(&value, "/test_mode", false)?;
    expect_string(&value, "/conclusion", "success")?;
    Ok(())
}

fn expect_string(value: &Value, pointer: &str, expected: &str) -> Result<()> {
    if value.pointer(pointer).and_then(Value::as_str) != Some(expected) {
        return Err(BoundaryError("governed receipt semantic mismatch"));
    }
    Ok(())
}

fn expect_bool(value: &Value, pointer: &str, expected: bool) -> Result<()> {
    if value.pointer(pointer).and_then(Value::as_bool) != Some(expected) {
        return Err(BoundaryError("governed receipt semantic mismatch"));
    }
    Ok(())
}

fn exec_sealed(
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

    struct Fixture {
        _temp: TempDir,
        policy: Policy,
    }

    impl Fixture {
        fn new(binary_bytes: &[u8]) -> Self {
            let temp = tempfile::tempdir().unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let binary_dir = temp.path().join("bin");
            let receipt_dir = temp.path().join("receipts");
            fs::create_dir(&binary_dir).unwrap();
            fs::create_dir(&receipt_dir).unwrap();
            fs::set_permissions(&binary_dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&receipt_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let binary_path = binary_dir.join("jankurai");
            fs::write(&binary_path, binary_bytes).unwrap();
            fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o755)).unwrap();
            let binary_sha256 = digest_hex(binary_bytes);
            let receipt_path = receipt_dir.join("receipt.json");
            let receipt = valid_receipt(&binary_path, &binary_sha256);
            let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
            fs::write(&receipt_path, &receipt_bytes).unwrap();
            fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
            let receipt_sha256 = digest_hex(&receipt_bytes);
            Self {
                _temp: temp,
                policy: Policy {
                    trusted_root: binary_dir.parent().unwrap().to_path_buf(),
                    binary_path,
                    binary_sha256,
                    receipt_path,
                    receipt_sha256,
                },
            }
        }
    }

    fn valid_receipt(binary_path: &Path, binary_sha256: &str) -> Value {
        json!({
            "schema": "jeryu.jankurai-installation/v1",
            "source": {
                "remote": "http://127.0.0.1:8787/git/jeryu/jankurai.git",
                "commit": "dface7397fe24d46b0b1885ddd5782c34edbff49",
                "tag": "v1.6.11-deadlang-precision-split.1",
                "tree": "34a8a1fb59bc4ebfadf12c45d95f169d06acc781",
                "archive_sha256": "2fbca5d04083e3c8d32f383d5b6b4520b8911690b26968c6fbcb210e1202b938",
                "cargo_lock_sha256": "b9acb981c326226a687d0b6703e4f7ee303148e9e1a6dda1aa03d77988820f6a",
                "verification": "release-authoritative"
            },
            "build": {
                "rustc": "rustc 1.95.0 (59807616e 2026-04-14)",
                "cargo": "cargo 1.95.0 (f2d3ce0bd 2026-03-21)",
                "target_triple": "x86_64-unknown-linux-gnu",
                "mode": "cargo-install-locked-offline-path-v1",
                "cargo_net_offline": true,
                "dedicated_cargo_home": true,
                "git_global_config_disabled": true,
                "git_system_config_disabled": true,
                "git_http_follow_redirects": false,
                "git_terminal_prompt": false,
                "jankurai_update_check": false,
                "network_scope": "local-forge-source-plus-offline-cargo",
                "no_proxy": "127.0.0.1,localhost,::1"
            },
            "binary": {"sha256": binary_sha256, "version_output": "jankurai 1.6.11"},
            "installation": {"path": binary_path, "atomic": true},
            "governance": {
                "status": "governed",
                "manifest_repo": "http://127.0.0.1:8787/git/jeryu/jeryu-tool.git",
                "manifest_commit": "de80b657e1be5580289dfecdc0cd3c71348261e0",
                "manifest_tree": "8dd6f773dce3ec2e5a82c8f0b606c240760489f9",
                "manifest_sha256": "707f57b7f60b65025303315b050cc1c138c7fb2e2080e775ef97a971f286e9b5",
                "protected_main": true,
                "protection_policy": "immutable-main-v1"
            },
            "test_mode": false,
            "conclusion": "success"
        })
    }

    #[test]
    fn valid_files_produce_a_write_sealed_exact_copy() {
        let fixture = Fixture::new(b"governed executable bytes");
        let verified = verify_with_hook(&fixture.policy, || {}).unwrap();
        assert_eq!(
            // SAFETY: the verified object owns a valid memfd and F_GET_SEALS has no pointer argument.
            unsafe { libc::fcntl(verified.sealed_file.as_raw_fd(), libc::F_GET_SEALS,) },
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE
        );
        assert_eq!(
            require_file_digest(&verified.sealed_file, &fixture.policy.binary_sha256),
            Ok(())
        );
    }

    #[test]
    fn in_process_sha256_matches_standard_vectors() {
        assert_eq!(
            digest_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            digest_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejects_symlink_component() {
        let fixture = Fixture::new(b"governed executable bytes");
        let link = fixture._temp.path().join("linked-bin");
        symlink(fixture._temp.path().join("bin"), &link).unwrap();
        let mut policy = fixture.policy.clone();
        policy.binary_path = link.join("jankurai");
        assert!(verify_with_hook(&policy, || {}).is_err());
    }

    #[test]
    fn rejects_hardlinked_binary() {
        let fixture = Fixture::new(b"governed executable bytes");
        fs::hard_link(
            &fixture.policy.binary_path,
            fixture._temp.path().join("alias"),
        )
        .unwrap();
        assert_eq!(
            verify_with_hook(&fixture.policy, || {}).unwrap_err(),
            BoundaryError("governed file has an unsafe link count")
        );
    }

    #[test]
    fn rejects_wrong_file_mode() {
        let fixture = Fixture::new(b"governed executable bytes");
        fs::set_permissions(
            &fixture.policy.binary_path,
            fs::Permissions::from_mode(0o775),
        )
        .unwrap();
        assert_eq!(
            verify_with_hook(&fixture.policy, || {}).unwrap_err(),
            BoundaryError("governed file has the wrong mode")
        );
    }

    #[test]
    fn rejects_wrong_effective_owner() {
        let identity = Identity {
            device: 1,
            inode: 2,
            uid: 2000,
            mode: 0o755,
            links: 1,
            length: 1,
        };
        assert_eq!(
            validate_regular_identity(identity, true, 1000, 0o755, 64).unwrap_err(),
            BoundaryError("governed file has the wrong owner")
        );
    }

    #[test]
    fn rejects_oversized_receipt_before_parsing() {
        let fixture = Fixture::new(b"governed executable bytes");
        fs::write(
            &fixture.policy.receipt_path,
            vec![b'x'; (MAX_RECEIPT_BYTES + 1) as usize],
        )
        .unwrap();
        assert_eq!(
            verify_with_hook(&fixture.policy, || {}).unwrap_err(),
            BoundaryError("governed file has an invalid size")
        );
    }

    #[test]
    fn rejects_atomic_path_replacement_after_open() {
        let fixture = Fixture::new(b"governed executable bytes");
        let original = fixture.policy.binary_path.with_extension("original");
        let replacement = fixture.policy.binary_path.clone();
        let result = verify_with_hook(&fixture.policy, || {
            fs::rename(&replacement, &original).unwrap();
            fs::write(&replacement, b"governed executable bytes").unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
        });
        assert_eq!(
            result.unwrap_err(),
            BoundaryError("governed path changed during validation")
        );
    }

    #[test]
    fn rejects_same_version_fake_by_digest() {
        let fixture = Fixture::new(b"governed executable bytes");
        fs::write(
            &fixture.policy.binary_path,
            b"#!/bin/sh\nprintf 'jankurai 1.6.11\\n'\n",
        )
        .unwrap();
        assert_eq!(
            verify_with_hook(&fixture.policy, || {}).unwrap_err(),
            BoundaryError("binary digest mismatch")
        );
    }

    #[test]
    fn ambient_path_and_shell_function_markers_are_not_consulted() {
        let _guard = ENVIRONMENT_LOCK.lock().unwrap();
        let fixture = Fixture::new(b"governed executable bytes");
        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", "/definitely/hostile");
        std::env::set_var("BASH_FUNC_sha256sum%%", "() { return 0; }");
        let result = verify_with_hook(&fixture.policy, || {});
        std::env::remove_var("BASH_FUNC_sha256sum%%");
        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        } else {
            std::env::remove_var("PATH");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn production_policy_verifies_current_governed_installation() {
        verify_with_hook(&Policy::production(), || {}).unwrap();
    }
}
