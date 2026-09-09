mod digest;
mod execution;
mod filesystem;
mod receipt;

use digest::{require_digest, require_file_digest};
use execution::{exec_sealed, sealed_copy};
use filesystem::{
    ensure_contained, ensure_directory_chain, open_regular, read_bounded, require_stable_fd,
    require_stable_path,
};
use receipt::validate_receipt;
use std::ffi::OsString;
use std::fmt::{Display, Formatter};
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const BINARY_PATH: &str = "/home/ubuntu/.jeryu/bin/jankurai";
const BINARY_SHA256: &str = "96d99e6e7d8dc9cf23df1081edd1f975231456592f81d9405385219a2c7298aa";
const RECEIPT_PATH: &str = "/home/ubuntu/.jeryu/receipts/jankurai/sha256/4b66c7b3d2ce4102b2302a7e73533cdbc2ae48ac02ec76cb6b1ff395ddc91d6a.json";
const RECEIPT_SHA256: &str = "4b66c7b3d2ce4102b2302a7e73533cdbc2ae48ac02ec76cb6b1ff395ddc91d6a";
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
    // SAFETY: geteuid has no arguments, does not dereference memory, and cannot violate aliases.
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

#[cfg(test)]
mod tests;
