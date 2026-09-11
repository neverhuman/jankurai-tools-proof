use jankurai_proofbind::{build_proofbind, ProofBindMode, ProofBindRequest};
use std::fs;
use std::path::PathBuf;

#[test]
fn classified_tests_have_a_published_witness_type_and_keep_missing_obligations() {
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir(repo.path().join("tests")).unwrap();
    fs::create_dir(repo.path().join("agent")).unwrap();
    fs::write(
        repo.path().join("tests/integration.rs"),
        "#[test]\nfn exercises_boundary() { assert_eq!(1 + 1, 2); }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"tests/":"tools"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"tests/":{"command":"cargo test --test integration","purpose":"integration"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        "[[lane]]\nname = \"integration\"\ncommand = \"cargo test --test integration\"\npurpose = \"test execution\"\n",
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("tests/integration.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();
    assert!(!output.witness.surfaces.is_empty());
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/proofbind-witness.schema.json"
    ))
    .unwrap();
    let published_types = schema["properties"]["surfaces"]["items"]["properties"]["surface_type"]
        ["enum"]
        .as_array()
        .unwrap();
    for surface in &output.witness.surfaces {
        assert_eq!(surface.surface_type, "test_execution");
        assert!(published_types
            .iter()
            .any(|value| value == &surface.surface_type));
    }
    assert_eq!(output.obligations.summary.satisfied, 0);
    assert!(output.obligations.summary.missing > 0);
}
