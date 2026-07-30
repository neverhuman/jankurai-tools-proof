use super::*;
use digest::digest_hex;
use filesystem::validate_regular_identity;
use serde_json::{json, Value};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
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
            "commit": "4dfbdfa3585f1928d5f996d7b5e14608dff14a03",
            "tag": "v1.6.11-deadlang-precision-split.2",
            "tree": "7e5d501aa6f0ee6ced9a48c6288a9943d0b9573c",
            "archive_sha256": "1aa3d178dec0fbb8d0657dd465ea6fda830ffc4ec1f65560b7b7d1682fd87e69",
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
            "manifest_commit": "aac9336ac369f4d3046a1e0acc9d98c48ce164d1",
            "manifest_tree": "7049feda28cfd95c8657f562b92e8246ceb1cc26",
            "manifest_sha256": "7aaac7f1b8c1543eba5215ec7cd2bf35e0c2411339ed9af1d1a6ace68d2807d8",
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
        // SAFETY: verified owns a valid memfd and F_GET_SEALS has no pointer argument.
        unsafe { libc::fcntl(verified.sealed_file.as_raw_fd(), libc::F_GET_SEALS) },
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
