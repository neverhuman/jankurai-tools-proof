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
        r#"{"workspace":"fixture","owners":{"src/":"tools","db/":"standard","agent/":"agent"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"src/":{"command":"cargo test -p fixture","purpose":"rust"},"db/":{"command":"cargo run -p jankurai -- migrate . --analyze --json target/jankurai/migration-report.json","purpose":"db"},"agent/":{"command":"just score","purpose":"agent"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "proofmark-rust"
command = "cargo test -p fixture"
purpose = "proofmark"

[[lane]]
name = "db-migration-analyze"
command = "cargo run -p jankurai -- migrate . --analyze --json target/jankurai/migration-report.json"
purpose = "migration"

[[lane]]
name = "audit"
command = "just score"
purpose = "audit"
"#,
    )
    .unwrap();
    repo
}

#[test]
fn authz_rust_change_emits_critical_obligation() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/auth.rs"),
        "pub fn authorize(tenant_id: &str) -> bool { !tenant_id.is_empty() }\n",
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
    assert!(output
        .witness
        .surfaces
        .iter()
        .any(|surface| surface.surface_type == "authz_boundary"));
    assert!(output.obligations.obligations.iter().any(|obligation| {
        obligation
            .rule_ids
            .contains(&"HLT-022-AUTHZ-ISOLATION-GAP".to_string())
            && obligation.severity == "critical"
    }));
    assert_eq!(output.obligations.summary.high_or_critical_missing, 1);
}

#[test]
fn exact_proofmark_id_does_not_bypass_other_required_lanes() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    let initial = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: None,
    })
    .unwrap();
    let obligation_id = initial.obligations.obligations[0].obligation_id.clone();
    let receipt_dir = repo.path().join("target/jankurai/proofmark");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("proof-receipt.json"),
        serde_json::json!({
            "lane": "proofmark-rust",
            "command": "jankurai proofmark rust",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/lib.rs"],
            "rules_covered": [{"rule_id":"HLT-007-HANDWRITTEN-CONTRACT","status":"covered"}],
            "extensions": {
                "proofmark": {
                    "satisfied_obligations": [obligation_id],
                    "obligation_results": [{
                        "obligation_id": obligation_id,
                        "status": "pass",
                        "negative_proof_status": "not_required"
                    }]
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: Some(PathBuf::from("target/jankurai/proofmark")),
    })
    .unwrap();
    assert_eq!(output.obligations.summary.satisfied, 0);
    assert_eq!(output.obligations.summary.missing, 1);
}

#[test]
fn every_required_lane_and_receipt_kind_must_be_present() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    let initial = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: None,
    })
    .unwrap();
    let obligation_id = initial.obligations.obligations[0].obligation_id.clone();
    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("contract.json"),
        serde_json::json!({
            "lane": "contract",
            "command": "cargo public-api diff",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/lib.rs"],
            "rules_covered": [{"rule_id":"HLT-007-HANDWRITTEN-CONTRACT","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        receipt_dir.join("proofmark.json"),
        serde_json::json!({
            "lane": "proofmark-rust",
            "command": "jankurai proofmark rust",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/lib.rs"],
            "rules_covered": [{"rule_id":"HLT-007-HANDWRITTEN-CONTRACT","status":"covered"}],
            "extensions": {
                "proofmark": {
                    "satisfied_obligations": [obligation_id],
                    "obligation_results": [{
                        "obligation_id": obligation_id,
                        "status": "pass",
                        "negative_proof_status": "not_required"
                    }]
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();

    assert_eq!(output.obligations.summary.satisfied, 1);
    assert_eq!(output.obligations.summary.missing, 0);
}

#[test]
fn changed_test_requires_typed_execution_receipt() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("tests")).unwrap();
    fs::write(
        repo.path().join("tests/integration.rs"),
        "#[test]\nfn exercises_api() {}\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"src/":"tools","tests/":"tools","agent/":"agent"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"src/":{"command":"cargo test -p fixture","purpose":"rust"},"tests/":{"command":"cargo test --test integration","purpose":"integration"},"agent/":{"command":"just score","purpose":"agent"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "proofmark-rust"
command = "cargo test -p fixture"
purpose = "proofmark"

[[lane]]
name = "integration-test"
command = "cargo test --test integration"
purpose = "test execution"
"#,
    )
    .unwrap();

    let initial = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("tests/integration.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();
    assert_eq!(
        initial.obligations.obligations[0].surface_type,
        "test_execution"
    );
    assert!(initial.obligations.obligations[0]
        .required_receipt_kinds
        .contains(&"test-execution".to_string()));
    assert_eq!(initial.obligations.summary.missing, 1);

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("test.json"),
        serde_json::json!({
            "lane": "integration-test",
            "command": "cargo test --test integration",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["tests/integration.rs"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        receipt_dir.join("unrelated-typed.json"),
        serde_json::json!({
            "lane": "unrelated",
            "command": "cargo test --test integration",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["tests/integration.rs"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}],
            "extensions": {
                "test_execution": {
                    "kind": "test",
                    "status": "pass"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let unrelated_typed = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("tests/integration.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();
    assert_eq!(unrelated_typed.obligations.summary.satisfied, 0);
    assert_eq!(unrelated_typed.obligations.summary.missing, 1);

    fs::write(
        receipt_dir.join("test.json"),
        serde_json::json!({
            "lane": "integration-test",
            "command": "cargo test --test integration",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["tests/integration.rs"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}],
            "extensions": {
                "test_execution": {
                    "kind": "test",
                    "status": "pass"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("tests/integration.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();
    assert_eq!(output.obligations.summary.satisfied, 1);
    assert_eq!(output.obligations.summary.missing, 0);
}

#[test]
fn boundary_obligation_requires_every_receipt_kind() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/auth.rs"),
        "pub fn authorize(tenant_id: &str) -> bool { !tenant_id.is_empty() }\n",
    )
    .unwrap();
    let initial = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/auth.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();
    let obligation = initial
        .obligations
        .obligations
        .iter()
        .find(|obligation| {
            obligation
                .rule_ids
                .contains(&"HLT-022-AUTHZ-ISOLATION-GAP".to_string())
        })
        .unwrap();
    let obligation_id = obligation.obligation_id.clone();
    assert!(obligation
        .required_receipt_kinds
        .contains(&"negative-behavior-proof".to_string()));

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("security.json"),
        serde_json::json!({
            "lane": "security",
            "command": "cargo test authz",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/auth.rs"],
            "rules_covered": [{"rule_id":"HLT-022-AUTHZ-ISOLATION-GAP","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        receipt_dir.join("proofmark.json"),
        serde_json::json!({
            "lane": "proofmark-rust",
            "command": "jankurai proofmark rust",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/auth.rs"],
            "rules_covered": [{"rule_id":"HLT-022-AUTHZ-ISOLATION-GAP","status":"covered"}],
            "extensions": {
                "proofmark": {
                    "obligation_results": [{
                        "obligation_id": obligation_id,
                        "status": "pass",
                        "negative_proof_status": "missing"
                    }]
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/auth.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();
    let authz = output
        .obligations
        .obligations
        .iter()
        .find(|obligation| obligation.obligation_id == obligation_id)
        .unwrap();
    assert!(!authz.satisfied);
}
