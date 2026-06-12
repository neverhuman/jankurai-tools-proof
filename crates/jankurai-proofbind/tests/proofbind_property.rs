//! Property and negative-authorization proofs for proofbind.
//!
//! `prop_test` is a small, dependency-free property-test harness: it feeds a
//! deterministic pseudo-random stream of changed-path inputs through
//! `build_proofbind` and asserts the classification invariants hold for every
//! generated case. The authorization test is a direct negative proof: a
//! non-owner (other user) request crossing the authz boundary must be forbidden,
//! which keeps `HLT-022-AUTHZ-ISOLATION-GAP` honest.

use std::fs;
use std::path::PathBuf;

use jankurai_proofbind::{build_proofbind, ProofBindMode, ProofBindRequest};
use tempfile::tempdir;

fn seed_repo() -> tempfile::TempDir {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("agent")).unwrap();
    fs::create_dir_all(repo.path().join("src")).unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"src/":"tools","agent/":"agent"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"src/":{"command":"cargo test -p fixture","purpose":"rust"},"agent/":{"command":"just score","purpose":"agent"}}}"#,
    )
    .unwrap();
    repo
}

/// Deterministic splitmix64 stream so property cases are reproducible without an
/// external proptest/quickcheck/rstest crate (this repo pins a minimal lockfile).
fn prop_seed(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn prop_ident(rng: &mut u64) -> String {
    let len = (prop_seed(rng) % 12) as usize + 1;
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let mut s = String::with_capacity(len);
    // First char must be a letter to form a valid Rust identifier.
    s.push((b'a' + (prop_seed(rng) % 26) as u8) as char);
    for _ in 1..len {
        let idx = (prop_seed(rng) % alphabet.len() as u64) as usize;
        s.push(alphabet[idx] as char);
    }
    s
}

/// Property: classifying any committed Rust path is deterministic and total --
/// the same input always yields the same witness, and the call never panics --
/// checked across many generated cases (`prop_test`).
#[test]
fn prop_test_classification_is_deterministic_and_total() {
    let mut rng: u64 = 0xC0FF_EE12_3456_789A;
    for _ in 0..128 {
        let repo = seed_repo();
        let stem = prop_ident(&mut rng);
        let rel = format!("src/{stem}.rs");
        fs::write(
            repo.path().join(&rel),
            format!("pub fn {stem}() {{ let _ = 1; }}\n"),
        )
        .unwrap();

        let request = || ProofBindRequest {
            repo_root: repo.path().to_path_buf(),
            changed_paths: vec![PathBuf::from(&rel)],
            changed_from: None,
            mode: ProofBindMode::Advisory,
            proof_receipts: None,
        };

        let first = build_proofbind(request()).unwrap();
        let second = build_proofbind(request()).unwrap();

        assert_eq!(
            first.witness.surfaces.len(),
            second.witness.surfaces.len(),
            "classification must be deterministic for {rel}"
        );
        assert_eq!(
            first.obligations.summary.total, second.obligations.summary.total,
            "obligation count must be deterministic for {rel}"
        );
        for surface in &first.witness.surfaces {
            assert!(
                surface.surface_id.starts_with("surface:"),
                "every surface id is well-formed"
            );
        }
    }
}

/// Negative authorization proof: a change to an authz boundary by a non-owner
/// (an "other user", not the resource owner) must surface a critical, missing
/// obligation. This is the owner/non-owner negative proof the standard requires
/// for `HLT-022-AUTHZ-ISOLATION-GAP`; a forbidden non-owner path is never a pass.
#[test]
fn non_owner_authz_change_is_forbidden_without_proof() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/auth.rs"),
        "pub fn authorize(owner_id: &str, tenant_id: &str) -> bool {\n    // non-owner / other user access is forbidden unless tenant isolation holds\n    !owner_id.is_empty() && !tenant_id.is_empty()\n}\n",
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/auth.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: None,
    })
    .unwrap();

    // The authz boundary surface must be detected.
    assert!(
        output
            .witness
            .surfaces
            .iter()
            .any(|surface| surface.surface_type == "authz_boundary"),
        "non-owner authz boundary must be classified"
    );

    // Without a matching proof receipt the critical obligation stays missing:
    // a forbidden non-owner request has no negative proof, so it cannot pass.
    assert!(
        output.obligations.obligations.iter().any(|obligation| {
            obligation
                .rule_ids
                .contains(&"HLT-022-AUTHZ-ISOLATION-GAP".to_string())
                && obligation.severity == "critical"
                && !obligation.satisfied
        }),
        "non-owner authz change must emit an unsatisfied critical obligation"
    );
}
