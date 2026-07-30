use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::ChangedSurface;

#[derive(Debug, Clone)]
pub(crate) struct ReceiptEvidence {
    pub lane: String,
    pub exit_code: i64,
    pub path: String,
    pub changed_paths: Vec<String>,
    pub rules_covered: Vec<String>,
    pub full_repository_scope: bool,
    pub proofmark_results: BTreeMap<String, String>,
    pub proofmark_negative_results: BTreeMap<String, String>,
    pub typed_test_execution: bool,
}

pub(crate) fn load_receipts(repo: &Path, path: Option<&Path>) -> Result<Vec<ReceiptEvidence>> {
    let Some(path) = path else {
        return Ok(vec![]);
    };
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.join(path)
    };
    if !path.exists() {
        return Ok(vec![]);
    }
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(&path).with_context(|| format!("read {}", path.display()))? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                entries.push(entry.path());
            }
        }
    } else {
        entries.push(path);
    }
    entries.sort();
    let mut receipts = Vec::new();
    for entry in entries {
        let text =
            fs::read_to_string(&entry).with_context(|| format!("read {}", entry.display()))?;
        let value: Value =
            serde_json::from_str(&text).with_context(|| format!("parse {}", entry.display()))?;
        receipts.push(receipt_from_value(repo, &entry, &value));
    }
    Ok(receipts)
}

fn receipt_matches_surface(
    obligation_id: &str,
    surface: &ChangedSurface,
    receipt: &ReceiptEvidence,
) -> bool {
    if receipt.exit_code != 0 {
        return false;
    }
    let path_matches = (receipt.changed_paths.is_empty() && receipt.full_repository_scope)
        || receipt
            .changed_paths
            .iter()
            .any(|path| path == &surface.path || surface.path.starts_with(&format!("{path}/")));
    if !path_matches {
        return false;
    }
    let rules_match = surface
        .required_rules
        .iter()
        .all(|rule| receipt.rules_covered.iter().any(|covered| covered == rule));
    if !rules_match {
        return false;
    }
    if receipt.lane == "proofmark-rust" {
        return receipt
            .proofmark_results
            .get(obligation_id)
            .is_some_and(|status| status == "pass");
    }
    true
}

fn receipt_kinds_for(
    obligation_id: &str,
    surface: &ChangedSurface,
    receipt: &ReceiptEvidence,
) -> BTreeSet<&'static str> {
    let mut kinds = BTreeSet::from(["proof-receipt"]);
    if receipt.lane == "proofmark-rust"
        && receipt
            .proofmark_results
            .get(obligation_id)
            .is_some_and(|status| status == "pass")
    {
        kinds.insert("proofmark");
        if receipt
            .proofmark_negative_results
            .get(obligation_id)
            .is_some_and(|status| status == "present")
        {
            kinds.insert("negative-behavior-proof");
        }
    }
    if receipt.typed_test_execution
        && surface
            .required_lanes
            .iter()
            .any(|lane| lane == &receipt.lane)
    {
        kinds.insert("test-execution");
    }
    kinds
}

pub(crate) fn satisfying_receipt_paths(
    obligation_id: &str,
    surface: &ChangedSurface,
    receipts: &[ReceiptEvidence],
) -> Vec<String> {
    let matching = receipts
        .iter()
        .filter(|receipt| receipt_matches_surface(obligation_id, surface, receipt))
        .collect::<Vec<_>>();
    let lanes = matching
        .iter()
        .map(|receipt| receipt.lane.as_str())
        .collect::<BTreeSet<_>>();
    let kinds = matching
        .iter()
        .flat_map(|receipt| receipt_kinds_for(obligation_id, surface, receipt))
        .collect::<BTreeSet<_>>();
    if !surface
        .required_lanes
        .iter()
        .all(|lane| lanes.contains(lane.as_str()))
        || !crate::classify::required_receipt_kinds(surface)
            .iter()
            .all(|kind| kinds.contains(kind.as_str()))
    {
        return Vec::new();
    }
    let mut paths = matching
        .iter()
        .map(|receipt| receipt.path.clone())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

fn receipt_from_value(repo: &Path, entry: &Path, value: &Value) -> ReceiptEvidence {
    let lane = if let Some(lane) = value.get("lane").and_then(Value::as_str) {
        lane.to_string()
    } else {
        "unknown".into()
    };
    let exit_code = value.get("exit_code").and_then(Value::as_i64).unwrap_or(1);
    let changed_paths = if let Some(items) = value.get("changed_paths").and_then(Value::as_array) {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut rules_covered = Vec::new();
    if let Some(items) = value.get("rules_covered").and_then(Value::as_array) {
        for item in items {
            if let Some(rule) = item.as_str() {
                rules_covered.push(rule.to_string());
            } else if let Some(rule) = item.get("rule_id").and_then(Value::as_str) {
                let status = item
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("covered");
                if !matches!(status, "covered" | "pass" | "satisfied") {
                    continue;
                }
                rules_covered.push(rule.to_string());
            }
        }
    }
    let null_value = Value::Null;
    let proofmark =
        if let Some(proofmark) = value.get("extensions").and_then(|v| v.get("proofmark")) {
            proofmark
        } else {
            &null_value
        };
    let mut proofmark_results = BTreeMap::new();
    let mut proofmark_negative_results = BTreeMap::new();
    if let Some(items) = proofmark
        .get("obligation_results")
        .and_then(Value::as_array)
    {
        for item in items {
            let Some(id) = item.get("obligation_id").and_then(Value::as_str) else {
                continue;
            };
            let status = item
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            proofmark_results.insert(id.to_string(), status.to_string());
            let negative_status = item
                .get("negative_proof_status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            proofmark_negative_results.insert(id.to_string(), negative_status.to_string());
        }
    }
    let full_repository_scope = value
        .get("extensions")
        .and_then(|extensions| extensions.get("full_repository_scope"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || value
            .get("extensions")
            .and_then(|extensions| extensions.get("scope"))
            .and_then(Value::as_str)
            .is_some_and(|scope| scope == "full-repository" || scope == "full_repository");
    let typed_test_execution = value
        .get("extensions")
        .and_then(|extensions| extensions.get("test_execution"))
        .is_some_and(|execution| {
            execution
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "test" | "example"))
                && execution.get("status").and_then(Value::as_str) == Some("pass")
        });
    ReceiptEvidence {
        lane,
        exit_code,
        path: display_rel(repo, entry),
        changed_paths,
        rules_covered,
        full_repository_scope,
        proofmark_results,
        proofmark_negative_results,
        typed_test_execution,
    }
}

fn display_rel(repo: &Path, path: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(repo) {
        rel.to_string_lossy().replace('\\', "/")
    } else {
        path.to_string_lossy().replace('\\', "/")
    }
}
