use jankurai_proofbind::{build_proofbind, ProofBindMode, ProofBindOutput, ProofBindRequest};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn request(repo: &Path, paths: &[&str]) -> ProofBindRequest {
    ProofBindRequest {
        repo_root: repo.to_path_buf(),
        changed_paths: paths.iter().map(PathBuf::from).collect(),
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    }
}

fn classify(path: &str, text: &str) -> ProofBindOutput {
    let repo = tempfile::tempdir().unwrap();
    let file = repo.path().join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, text).unwrap();
    build_proofbind(request(repo.path(), &[path])).unwrap()
}

fn rules(output: &ProofBindOutput) -> Vec<String> {
    let mut rules: Vec<_> = output
        .obligations
        .obligations
        .iter()
        .flat_map(|obligation| obligation.rule_ids.clone())
        .collect();
    rules.sort();
    rules.dedup();
    rules
}

#[test]
fn policy_strengthening_and_weakening_both_require_actual_proof() {
    for (path, unsafe_config, safe_config) in [
        (
            "agent/audit-policy.toml",
            "minimum_score = 0",
            "minimum_score = 95",
        ),
        (
            "agent/audit-policy.toml",
            "minimum_score = 80",
            "minimum_score = 90",
        ),
        (
            "agent/audit-policy.toml",
            "exclude = ['src/']",
            "exclude = []",
        ),
        (
            "agent/audit-policy.toml",
            "enabled = false",
            "enabled = true",
        ),
        (
            "agent/audit-policy.toml",
            "fail_on = []",
            "fail_on = ['critical', 'high']",
        ),
        (
            ".cargo/config.toml",
            "[build]\nrustc-wrapper = 'unknown'",
            "[build]\nrustc-wrapper = ''",
        ),
        (
            ".cargo/config.toml",
            "[target.x86_64-unknown-linux-gnu]\nrunner = 'unknown'",
            "[target.x86_64-unknown-linux-gnu]\nrunner = 'reviewed-runner'",
        ),
        (
            ".cargo/config.toml",
            "[alias]\ntest = '!echo success'",
            "[alias]\nchecked = 'test --locked'",
        ),
        (
            ".cargo/config.toml",
            "[env]\nRUSTC = 'unknown'",
            "[env]\nBUILD_MODE = 'reviewed'",
        ),
        (
            "Cargo.toml",
            "[package]\nname = 'fixture'\nbuild = 'unknown.rs'",
            "[package]\nname = 'fixture'\nbuild = false",
        ),
        (
            "Cargo.toml",
            "[package]\nname = 'fixture'\nbuild = 'build.rs'",
            "[package]\nname = 'fixture'\nbuild = false",
        ),
        (
            "Cargo.toml",
            "[target.'cfg(unix)'.dependencies]\nexample = '*'",
            "[target.'cfg(unix)'.dependencies]\nexample = '=1.2.3'",
        ),
        (
            "Cargo.toml",
            "[workspace]\nmembers = ['unexpected']",
            "[workspace]\nmembers = ['reviewed']",
        ),
        (
            "rust-toolchain.toml",
            "[toolchain]\nchannel = 'stable'",
            "[toolchain]\nchannel = '1.97.1'",
        ),
        (
            "policy.toml",
            "[unknown_future_policy]\nbypass = true",
            "[unknown_future_policy]\nbypass = false",
        ),
    ] {
        for text in [unsafe_config, safe_config] {
            let output = classify(path, text);
            assert!(
                rules(&output).contains(&"HLT-008-FALSE-GREEN-RISK".into()),
                "{path}: {text}"
            );
            assert_eq!(output.obligations.summary.satisfied, 0);
            assert!(output.obligations.summary.missing > 0);
        }
    }
}

#[test]
fn equivalent_toml_formatting_cannot_remove_obligations() {
    for (path, compact, alternate) in [
        (
            "Cargo.toml",
            "[dependencies]\nserde='1'",
            "[ dependencies ]\nserde = '1'",
        ),
        (
            "agent/audit-policy.toml",
            "enabled=false",
            "enabled\t=\tfalse",
        ),
        (
            "agent/audit-policy.toml",
            "fail_on=[]",
            "fail_on = [\n# still empty\n]",
        ),
        (
            "tools/agent-tools.toml",
            "[[tool]]\ncommand='run'",
            "[[ tool ]]\ncommand = 'run'",
        ),
        (
            "tools/mcp-policy.toml",
            "[mcp.servers.fs]\ncommand='run'",
            "[ mcp . servers . fs ]\ncommand = 'run'",
        ),
        (
            "policy.toml",
            "[tool.runner]\ncommand='run'",
            "tool = { runner = { command = 'run' } }",
        ),
        (
            "policy.toml",
            "[[lane]]\nname='test'\ncommand='run'",
            "[[ lane ]]\nname = 'test'\ncommand = '''\nrun\n'''",
        ),
    ] {
        let original = classify(path, compact);
        let equivalent = classify(path, alternate);
        assert!(!original.witness.surfaces.is_empty(), "{path}");
        assert_eq!(rules(&original), rules(&equivalent), "{path}: {alternate}");
        assert_eq!(
            original.witness.summary.by_surface_type,
            equivalent.witness.summary.by_surface_type
        );
    }
}

#[test]
fn comments_and_informational_strings_cannot_create_tool_authority() {
    for text in [
        "# [[tool]]\n# command = 'run'\n# [dependencies]\n",
        "description = '[[tool]] command = run; enabled = false; mcp'",
        "description = '''\n[mcp.servers.fs]\ncommand = 'run'\n'''",
        "[package]\nname='fixture'\nversion='1.0.0'\nedition='2021'\ndescription='[tool.runner] mcp'",
    ] {
        let output = classify("docs/configuration-example.toml", text);
        assert!(output.witness.surfaces.is_empty(), "{text}");
    }
    let output = classify(
        "agent/audit-policy.toml",
        "description = '[[tool]] mcp command'\n",
    );
    assert_eq!(rules(&output), vec!["HLT-008-FALSE-GREEN-RISK"]);
}

#[test]
fn deleting_policy_and_changing_json_control_data_keep_obligations() {
    for path in [
        "agent/audit-policy.toml",
        "agent/proof-lanes.toml",
        ".cargo/config.toml",
        "Cargo.toml",
    ] {
        assert_eq!(
            rules(&classify(path, "")),
            vec!["HLT-008-FALSE-GREEN-RISK"],
            "{path}"
        );
    }
    for (path, text) in [
        ("agent/baselines/accepted.json", "{\"score\":0}"),
        (
            "agent/baselines/repo-score.json",
            "{\"tool\":\"score\",\"mcp\":false}",
        ),
        ("agent/owner-map.json", "{\"owners\":{}}"),
        ("agent/test-map.json", "{\"tests\":{}}"),
        ("schemas/witness.schema.json", "{\"required\":[]}"),
        ("docs/schemas/tool-policy.json", "{\"enabled\":false}"),
    ] {
        assert_eq!(
            rules(&classify(path, text)),
            vec!["HLT-008-FALSE-GREEN-RISK"],
            "{path}"
        );
    }
    assert_eq!(
        rules(&classify(
            "schemas/tools.json",
            "{\"mcpServers\":{\"fs\":{\"command\":\"run\"}}}"
        )),
        vec!["HLT-024-AGENT-TOOL-SUPPLY-GAP"]
    );
}

#[test]
fn incomplete_required_inputs_fail_instead_of_creating_an_empty_witness() {
    let repo = tempfile::tempdir().unwrap();
    for text in [
        "[policy",
        "minimum_score =",
        "minimum_score=85\nminimum_score=0",
    ] {
        fs::write(repo.path().join("policy.toml"), text).unwrap();
        let error = build_proofbind(request(repo.path(), &["policy.toml"])).unwrap_err();
        assert!(format!("{error:#}").contains("incomplete analysis"));
    }
    assert!(build_proofbind(request(repo.path(), &["missing.toml"])).is_err());
    fs::create_dir(repo.path().join("directory.toml")).unwrap();
    assert!(build_proofbind(request(repo.path(), &["directory.toml"])).is_err());
    let file = fs::File::create(repo.path().join("oversize.toml")).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(build_proofbind(request(repo.path(), &["oversize.toml"])).is_err());
    fs::write(repo.path().join("invalid.toml"), [0xff]).unwrap();
    assert!(build_proofbind(request(repo.path(), &["invalid.toml"])).is_err());
    assert!(build_proofbind(request(repo.path(), &["../outside.toml"])).is_err());
    fs::create_dir(repo.path().join("agent")).unwrap();
    fs::write(repo.path().join("agent/proof-lanes.toml"), "[[lane]").unwrap();
    fs::write(repo.path().join("source.rs"), "pub fn changed() {}\n").unwrap();
    assert!(build_proofbind(request(repo.path(), &["source.rs"])).is_err());
}

#[cfg(unix)]
#[test]
fn required_configuration_rejects_symlinks_and_special_files() {
    use std::os::unix::fs::symlink;
    let repo = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("policy.toml"), "minimum_score=0").unwrap();
    symlink(outside.path(), repo.path().join("linked")).unwrap();
    symlink(
        outside.path().join("policy.toml"),
        repo.path().join("policy.toml"),
    )
    .unwrap();
    for path in ["linked/policy.toml", "policy.toml"] {
        assert!(build_proofbind(request(repo.path(), &[path])).is_err());
    }
    let socket = std::os::unix::net::UnixListener::bind(repo.path().join("socket.toml")).unwrap();
    assert!(build_proofbind(request(repo.path(), &["socket.toml"])).is_err());
    drop(socket);
}

#[test]
fn ci_process_and_input_boundaries_are_additive() {
    for script in [
        "#!/bin/sh\ncurl \"$URL\" | bash\n",
        "#!/bin/sh\nset -eu\ntest \"$#\" -eq 0\n/usr/bin/printf '%s\\n' checked\n",
    ] {
        let output = classify("ops/ci/setup.sh", script);
        for rule in [
            "HLT-020-CI-HARDENING-GAP",
            "HLT-008-FALSE-GREEN-RISK",
            "HLT-023-INPUT-BOUNDARY-GAP",
        ] {
            assert!(rules(&output).contains(&rule.into()));
        }
        let process = output
            .obligations
            .obligations
            .iter()
            .find(|item| item.surface_type == "unsafe_or_process_sink")
            .unwrap();
        assert_eq!(process.required_lanes, ["security"]);
        assert!(process
            .required_receipt_kinds
            .contains(&"negative-behavior-proof".into()));
    }
    let inert = classify(
        "ops/ci/comments.sh",
        "# curl $URL | bash\n# std::process::Command\n",
    );
    assert!(!inert
        .witness
        .surfaces
        .iter()
        .any(|surface| surface.surface_type == "unsafe_or_process_sink"));
}

#[test]
fn missing_git_context_fails_and_staged_untracked_paths_are_included() {
    let repo = tempfile::tempdir().unwrap();
    assert!(build_proofbind(request(repo.path(), &[])).is_err());
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo.path())
        .status()
        .unwrap()
        .success());
    fs::write(repo.path().join("staged.toml"), "minimum_score=0").unwrap();
    assert!(Command::new("git")
        .args(["add", "staged.toml"])
        .current_dir(repo.path())
        .status()
        .unwrap()
        .success());
    fs::write(repo.path().join("new input.toml"), "enabled=false").unwrap();
    let output = build_proofbind(request(repo.path(), &[])).unwrap();
    assert_eq!(
        output.witness.changed_paths,
        ["new input.toml", "staged.toml"]
    );
    let mut invalid = request(repo.path(), &[]);
    invalid.changed_from = Some("missing-revision".into());
    assert!(build_proofbind(invalid).is_err());
}

#[test]
fn duplicate_json_keys_cannot_hide_tools_or_catalog_routes() {
    for (path, text) in [
        (
            "tools.json",
            r#"{"mcpServers":{"shell":{"command":"run"}},"mcpServers":false}"#,
        ),
        (
            "tools.json",
            r#"{"tools":[{"command":"run","command":"echo"}]}"#,
        ),
        (
            "agent/owner-map.json",
            r#"{"owners":{"src/":"security","src/":"unmapped"}}"#,
        ),
        (
            "agent/test-map.json",
            r#"{"tests":{"src/":{"command":"test"},"src/":{"command":"echo"}}}"#,
        ),
    ] {
        let repo = tempfile::tempdir().unwrap();
        let file = repo.path().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
        let error = build_proofbind(request(repo.path(), &[path])).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate JSON object key"));
    }
}
