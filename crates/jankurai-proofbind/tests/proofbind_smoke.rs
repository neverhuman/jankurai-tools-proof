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
fn proofmark_receipt_alone_does_not_satisfy_matching_obligation() {
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
                    "satisfied_obligations": [obligation_id]
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
fn typed_test_receipt_must_be_bound_to_the_declared_test_command() {
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
        r#"{"workspace":"fixture","tests":{"tests/":{"command":"cargo test --test integration","purpose":"integration"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "integration-test"
command = "cargo test --test integration"
purpose = "test execution"
"#,
    )
    .unwrap();

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("self-asserted.json"),
        serde_json::json!({
            "lane": "integration-test",
            "command": "true",
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

    assert_eq!(output.obligations.summary.satisfied, 0);
    assert_eq!(output.obligations.summary.missing, 1);
}

#[test]
fn changed_example_accepts_a_typed_example_receipt_on_its_declared_lane() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("examples")).unwrap();
    fs::write(
        repo.path().join("examples/demo.rs"),
        "fn main() { println!(\"demo\"); }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"examples/":"tools"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"examples/":{"command":"cargo run --example demo","purpose":"example"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "example-demo"
command = "cargo run --example demo"
purpose = "example execution"
"#,
    )
    .unwrap();

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("example.json"),
        serde_json::json!({
            "lane": "example-demo",
            "command": "cargo run --example demo",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["examples/demo.rs"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}],
            "extensions": {
                "test_execution": {
                    "kind": "example",
                    "status": "pass"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("examples/demo.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();

    assert_eq!(output.obligations.summary.satisfied, 1);
    assert_eq!(output.obligations.summary.missing, 0);
}

#[test]
fn non_rust_fallback_requires_the_declared_test_map_command() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("docs")).unwrap();
    fs::write(repo.path().join("docs/release.md"), "release evidence\n").unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"docs/":"docs"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"docs/":{"command":"just docs-check","purpose":"docs"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "docs-check"
command = "just docs-check"
purpose = "documentation verification"
"#,
    )
    .unwrap();

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("docs.json"),
        serde_json::json!({
            "lane": "docs-check",
            "command": "true",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["docs/release.md"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();

    let false_green = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("docs/release.md")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();
    assert_eq!(
        false_green.obligations.obligations[0].required_lanes,
        ["docs-check"]
    );
    assert_eq!(false_green.obligations.summary.satisfied, 0);

    fs::write(
        receipt_dir.join("docs.json"),
        serde_json::json!({
            "lane": "docs-check",
            "command": "just docs-check",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["docs/release.md"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();
    let bound = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("docs/release.md")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();
    assert_eq!(bound.obligations.summary.satisfied, 1);
    assert_eq!(bound.obligations.summary.missing, 0);
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
