//! Bind classified surfaces to the required receipt kinds and their actual evidence.
use crate::{catalog::Catalog, ChangedSurface, ProofObligation};

pub(crate) fn repair_tasks(surface_type: &str, severity: &str) -> Vec<String> {
    let task = match surface_type {
        "authz_boundary" => {
            "add negative authorization or tenant-isolation proof and attach a proofmark receipt"
        }
        "input_boundary" => {
            "add malformed-input or unsafe-sink negative proof and attach a proofmark receipt"
        }
        "db_migration" => {
            "run migration analysis and document rollback/backfill/lock evidence for destructive SQL"
        }
        "sql_query" => "prove the SQL boundary with migration or adapter evidence",
        "cli_command" | "mcp_tool" => {
            "prove the tool surface with supply-chain review and changed-behavior receipt"
        }
        "ci_hardening" => {
            "prove CI script hardening with the security lane and attach a proof receipt"
        }
        "rust_public_api" => "prove public API compatibility and changed-line behavior",
        "unsafe_or_process_sink" => {
            "prove the process/filesystem sink with negative input evidence"
        }
        _ => "attach a focused proof receipt for the changed behavior",
    };
    let mut tasks = vec![task.to_string()];
    if matches!(severity, "high" | "critical") {
        tasks.push("do not merge as hard proof until the obligation is satisfied or waived".into());
    }
    tasks
}

pub(crate) fn required_receipt_kinds(surface: &ChangedSurface) -> Vec<String> {
    let mut kinds = vec!["proof-receipt".to_string()];
    if surface.surface_type == "test_execution" {
        kinds.push("test-execution".into());
    }
    if surface
        .required_lanes
        .iter()
        .any(|lane| lane == "proofmark-rust")
    {
        kinds.push("proofmark".into());
    }
    if surface
        .risk_tags
        .iter()
        .any(|tag| tag == "negative_proof_required")
    {
        kinds.push("negative-behavior-proof".into());
    }
    kinds
}

pub(crate) fn obligation_for_surface(
    surface: &ChangedSurface,
    receipts: &[crate::receipts::ReceiptEvidence],
    catalog: &Catalog,
) -> ProofObligation {
    let obligation_id = format!(
        "obligation:{}:{}",
        match surface.required_rules.first() {
            Some(rule) => rule.clone(),
            None => "HLT-008-FALSE-GREEN-RISK".into(),
        },
        surface.surface_id
    );
    let mut receipt_paths = Vec::new();
    receipt_paths.extend(crate::receipts::satisfying_receipt_paths(
        &obligation_id,
        surface,
        receipts,
        catalog,
        catalog.test_command_for_path(&surface.path),
    ));
    let satisfied = !receipt_paths.is_empty();
    ProofObligation {
        obligation_id,
        surface_id: surface.surface_id.clone(),
        path: surface.path.clone(),
        symbol: surface.symbol.clone(),
        surface_type: surface.surface_type.clone(),
        severity: surface.severity.clone(),
        risk_tags: surface.risk_tags.clone(),
        rule_ids: surface.required_rules.clone(),
        required_lanes: surface.required_lanes.clone(),
        required_receipt_kinds: required_receipt_kinds(surface),
        repair_task: match surface.repair_tasks.first() {
            Some(task) => task.clone(),
            None => "attach a focused proof receipt for the changed surface".into(),
        },
        satisfied,
        status: if satisfied { "satisfied" } else { "missing" }.into(),
        receipt_paths,
    }
}
