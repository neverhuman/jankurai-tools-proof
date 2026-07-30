use std::fs;
use std::path::PathBuf;

use jankurai_proofmark::{build_proofmark, ProofMarkMode, ProofMarkRequest};
use tempfile::tempdir;

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .current_dir(repo)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn seed_two_commit_rust_change(repo: &std::path::Path) {
    fs::create_dir_all(repo.join("src")).unwrap();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.name", "ProofMark Test"]);
    git(repo, &["config", "user.email", "proofmark@example.invalid"]);
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn existing() -> bool { true }\n",
    )
    .unwrap();
    git(repo, &["add", "src/lib.rs"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn existing() -> bool { true }\n\npub fn added() -> bool {\n    true\n}\n",
    )
    .unwrap();
    git(repo, &["add", "src/lib.rs"]);
    git(repo, &["commit", "-q", "-m", "change"]);
}

fn write_obligation(repo: &std::path::Path, path: &str, required_lanes: &[&str]) {
    fs::create_dir_all(repo.join("target/jankurai/proofbind")).unwrap();
    fs::write(
        repo.join("target/jankurai/proofbind/obligations.json"),
        serde_json::json!({
            "obligations": [{
                "obligation_id": format!("obligation:test:{path}"),
                "path": path,
                "rule_ids": ["HLT-008-FALSE-GREEN-RISK"],
                "required_lanes": required_lanes,
                "required_receipt_kinds": ["proof-receipt"]
            }]
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn lcov_covered_change_satisfies_non_boundary_obligation() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("src")).unwrap();
    fs::create_dir_all(repo.path().join("target/jankurai/proofbind")).unwrap();
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("target/jankurai/proofbind/obligations.json"),
        serde_json::json!({
            "schema_version": "1.0.0",
            "standard_version": "0.7.0",
            "generated_at": "0",
            "repo_root": repo.path().display().to_string(),
            "git_head": "unknown",
            "mode": "advisory",
            "obligations": [{
                "obligation_id": "obligation:HLT-007-HANDWRITTEN-CONTRACT:surface:rust_public_api:src:lib:api",
                "surface_id": "surface:rust_public_api:src:lib:api",
                "path": "src/lib.rs",
                "symbol": "api",
                "surface_type": "rust_public_api",
                "severity": "medium",
                "risk_tags": ["public_api"],
                "rule_ids": ["HLT-007-HANDWRITTEN-CONTRACT"],
                "required_lanes": ["contract", "proofmark-rust"],
                "required_receipt_kinds": ["proof-receipt", "proofmark"],
                "repair_task": "prove public API",
                "satisfied": false,
                "status": "missing",
                "receipt_paths": []
            }],
            "summary": {
                "total": 1,
                "satisfied": 0,
                "missing": 1,
                "high_or_critical_missing": 0,
                "changed_surface_count": 1,
                "verdict": "review"
            }
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        repo.path().join("coverage.lcov"),
        "TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n",
    )
    .unwrap();
    let output = build_proofmark(ProofMarkRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        obligations_path: Some(PathBuf::from("target/jankurai/proofbind/obligations.json")),
        coverage_path: Some(PathBuf::from("coverage.lcov")),
        mutation_path: None,
        negative_proofs: vec![],
        mode: ProofMarkMode::Advisory,
    })
    .unwrap();
    assert_eq!(output.receipt.summary.satisfied_obligations, 1);
    assert_eq!(output.receipt.coverage.status, "pass");
    assert_eq!(output.proof_receipt.lane, "proofmark-rust");
    assert_eq!(
        output.proof_receipt.extensions["proofmark"]["satisfied_obligations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn boundary_obligation_requires_negative_proof_marker() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("src")).unwrap();
    fs::create_dir_all(repo.path().join("target/jankurai/proofbind")).unwrap();
    fs::write(
        repo.path().join("src/auth.rs"),
        "pub fn authorize() -> bool { true }\n",
    )
    .unwrap();
    let obligation_id =
        "obligation:HLT-022-AUTHZ-ISOLATION-GAP:surface:authz_boundary:src:auth:authz";
    fs::write(
        repo.path()
            .join("target/jankurai/proofbind/obligations.json"),
        serde_json::json!({
            "obligations": [{
                "obligation_id": obligation_id,
                "path": "src/auth.rs",
                "rule_ids": ["HLT-022-AUTHZ-ISOLATION-GAP"],
                "required_lanes": ["security", "proofmark-rust"],
                "required_receipt_kinds": ["proof-receipt", "proofmark", "negative-behavior-proof"],
                "severity": "critical"
            }]
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        repo.path().join("coverage.lcov"),
        "SF:src/auth.rs\nDA:1,1\nend_of_record\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("mutation.json"),
        r#"{"survived":0,"timeout":0}"#,
    )
    .unwrap();
    let review = build_proofmark(ProofMarkRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/auth.rs")],
        changed_from: None,
        obligations_path: Some(PathBuf::from("target/jankurai/proofbind/obligations.json")),
        coverage_path: Some(PathBuf::from("coverage.lcov")),
        mutation_path: Some(PathBuf::from("mutation.json")),
        negative_proofs: vec![],
        mode: ProofMarkMode::Advisory,
    })
    .unwrap();
    assert_eq!(review.receipt.obligation_results[0].status, "review");
    let pass = build_proofmark(ProofMarkRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/auth.rs")],
        changed_from: None,
        obligations_path: Some(PathBuf::from("target/jankurai/proofbind/obligations.json")),
        coverage_path: Some(PathBuf::from("coverage.lcov")),
        mutation_path: Some(PathBuf::from("mutation.json")),
        negative_proofs: vec![obligation_id.into()],
        mode: ProofMarkMode::Advisory,
    })
    .unwrap();
    assert_eq!(pass.receipt.obligation_results[0].status, "pass");
}

#[test]
fn legacy_json_coverage_cannot_shrink_the_coverable_universe_to_hits() {
    let repo = tempdir().unwrap();
    seed_two_commit_rust_change(repo.path());
    write_obligation(repo.path(), "src/lib.rs", &["proofmark-rust"]);
    fs::write(
        repo.path().join("coverage.json"),
        serde_json::json!({
            "files": [{
                "filename": "src/lib.rs",
                "covered_lines": [4]
            }]
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofmark(ProofMarkRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![],
        changed_from: Some("HEAD^".into()),
        obligations_path: Some(PathBuf::from("target/jankurai/proofbind/obligations.json")),
        coverage_path: Some(PathBuf::from("coverage.json")),
        mutation_path: None,
        negative_proofs: vec![],
        mode: ProofMarkMode::Required,
    })
    .unwrap();

    assert_eq!(output.receipt.changed_units[0].coverage_status, "review");
    assert_eq!(output.receipt.summary.verdict, "block");
}

#[test]
fn changed_declarations_are_not_invented_as_executable_coverage_lines() {
    let repo = tempdir().unwrap();
    seed_two_commit_rust_change(repo.path());
    write_obligation(repo.path(), "src/lib.rs", &["proofmark-rust"]);
    fs::write(
        repo.path().join("coverage.lcov"),
        "TN:\nSF:src/lib.rs\nDA:4,1\nend_of_record\n",
    )
    .unwrap();

    let output = build_proofmark(ProofMarkRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![],
        changed_from: Some("HEAD^".into()),
        obligations_path: Some(PathBuf::from("target/jankurai/proofbind/obligations.json")),
        coverage_path: Some(PathBuf::from("coverage.lcov")),
        mutation_path: None,
        negative_proofs: vec![],
        mode: ProofMarkMode::Required,
    })
    .unwrap();

    assert_eq!(output.receipt.changed_units[0].changed_lines, vec![4]);
    assert_eq!(
        output.receipt.changed_units[0].covered_changed_lines,
        vec![4]
    );
    assert!(output.receipt.changed_units[0]
        .uncovered_changed_lines
        .is_empty());
    assert_eq!(output.receipt.summary.verdict, "pass");
}

#[test]
fn zero_hit_lcov_lines_remain_coverable_and_uncovered() {
    let repo = tempdir().unwrap();
    seed_two_commit_rust_change(repo.path());
    write_obligation(repo.path(), "src/lib.rs", &["proofmark-rust"]);
    fs::write(
        repo.path().join("coverage.lcov"),
        "TN:\nSF:src/lib.rs\nDA:4,0\nend_of_record\n",
    )
    .unwrap();

    let output = build_proofmark(ProofMarkRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![],
        changed_from: Some("HEAD^".into()),
        obligations_path: Some(PathBuf::from("target/jankurai/proofbind/obligations.json")),
        coverage_path: Some(PathBuf::from("coverage.lcov")),
        mutation_path: None,
        negative_proofs: vec![],
        mode: ProofMarkMode::Required,
    })
    .unwrap();

    assert_eq!(output.receipt.changed_units[0].changed_lines, vec![4]);
    assert_eq!(
        output.receipt.changed_units[0].uncovered_changed_lines,
        vec![4]
    );
    assert_eq!(output.receipt.summary.verdict, "block");
}

#[test]
fn changed_production_file_missing_from_coverage_inventory_blocks() {
    let repo = tempdir().unwrap();
    seed_two_commit_rust_change(repo.path());
    write_obligation(repo.path(), "src/lib.rs", &["proofmark-rust"]);
    fs::write(
        repo.path().join("coverage.lcov"),
        "TN:\nSF:src/other.rs\nDA:1,1\nend_of_record\n",
    )
    .unwrap();

    let output = build_proofmark(ProofMarkRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![],
        changed_from: Some("HEAD^".into()),
        obligations_path: Some(PathBuf::from("target/jankurai/proofbind/obligations.json")),
        coverage_path: Some(PathBuf::from("coverage.lcov")),
        mutation_path: None,
        negative_proofs: vec![],
        mode: ProofMarkMode::Required,
    })
    .unwrap();

    assert_eq!(output.receipt.coverage.status, "review");
    assert_eq!(output.receipt.changed_units[0].coverage_status, "review");
    assert_eq!(output.receipt.summary.verdict, "block");
}

#[test]
fn integration_test_source_is_not_treated_as_production_lcov() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("tests")).unwrap();
    fs::write(
        repo.path().join("tests/integration.rs"),
        "#[test]\nfn exercises_api() {}\n",
    )
    .unwrap();
    write_obligation(repo.path(), "tests/integration.rs", &["test-map"]);
    fs::write(
        repo.path().join("coverage.lcov"),
        "TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n",
    )
    .unwrap();

    let output = build_proofmark(ProofMarkRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("tests/integration.rs")],
        changed_from: None,
        obligations_path: Some(PathBuf::from("target/jankurai/proofbind/obligations.json")),
        coverage_path: Some(PathBuf::from("coverage.lcov")),
        mutation_path: None,
        negative_proofs: vec![],
        mode: ProofMarkMode::Required,
    })
    .unwrap();

    assert!(output.receipt.changed_units.is_empty());
    assert!(output.receipt.obligation_results.is_empty());
}
