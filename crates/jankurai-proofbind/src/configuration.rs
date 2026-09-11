use crate::{catalog::Catalog, classify::surface, ChangedSurface};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(crate) enum Configuration {
    Inert,
    Authority,
    Tool { mcp: bool },
}

/// Parse configuration before looking for authority. Values and comments that
/// quote a command or table header are data, not declarations of that table.
pub(crate) fn classify(path: &str, text: &str) -> Result<Option<Configuration>> {
    let value = if path.ends_with(".toml") {
        let parsed: toml::Value = toml::from_str(text)
            .with_context(|| format!("incomplete analysis: parse TOML {path}"))?;
        serde_json::to_value(parsed)?
    } else if path.ends_with(".json") {
        crate::strict_json::from_slice(text.as_bytes())
            .with_context(|| format!("incomplete analysis: parse JSON {path}"))?
    } else {
        return Ok(None);
    };
    let Some(table) = value.as_object() else {
        return Ok(Some(Configuration::Authority));
    };
    let mcp = table.iter().any(|(key, value)| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "mcp" | "mcpservers" | "mcp_servers" | "mcp-tools" | "mcp_tools"
        ) && tool_collection(value)
    });
    if mcp
        || ["tool", "tools"]
            .iter()
            .any(|key| table.get(*key).is_some_and(tool_collection))
    {
        return Ok(Some(Configuration::Tool { mcp }));
    }
    // Known execution and policy roles remain authoritative even when emptied:
    // removing a setting can select a different default or disable a check.
    let name = Path::new(path).file_name().and_then(|name| name.to_str());
    if matches!(name, Some("cargo.toml" | "rust-toolchain.toml"))
        || path.starts_with(".cargo/")
        || path.contains("/.cargo/")
        || path.starts_with("agent/")
        || path.starts_with(".agents/")
        || path.starts_with(".cursor/")
        || path.ends_with(".json")
    {
        return Ok(Some(Configuration::Authority));
    }
    // Only a small, explicit informational shape is inert. Unknown structured
    // settings retain changed-behavior obligations rather than gaining a new
    // exemption whenever a tool introduces another configuration key.
    let inert = table.iter().all(|(key, value)| {
        (matches!(key.as_str(), "title" | "description" | "documentation") && value.is_string())
            || (key == "package" && informational_package(value))
    });
    Ok(Some(if inert {
        Configuration::Inert
    } else {
        Configuration::Authority
    }))
}

fn tool_collection(value: &Value) -> bool {
    value.is_object()
        || value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_object))
}

fn informational_package(value: &Value) -> bool {
    value.as_object().is_some_and(|table| {
        table.iter().all(|(key, value)| {
            matches!(
                key.as_str(),
                "name"
                    | "version"
                    | "edition"
                    | "description"
                    | "license"
                    | "repository"
                    | "homepage"
                    | "documentation"
            ) && value.is_string()
        })
    })
}

pub(crate) fn surfaces(
    catalog: &Catalog,
    path: &str,
    text: &str,
) -> Result<Option<Vec<ChangedSurface>>> {
    let Some(configuration) = classify(&path.to_ascii_lowercase(), text)? else {
        return Ok(None);
    };
    if matches!(configuration, Configuration::Inert) {
        return Ok(Some(Vec::new()));
    }
    let (_, lane) = catalog.test_for_path(path);
    let (kind, rule, severity, symbol, tags, lane) = match configuration {
        Configuration::Tool { mcp } => (
            if mcp { "mcp_tool" } else { "cli_command" },
            "HLT-024-AGENT-TOOL-SUPPLY-GAP",
            "high",
            "tool",
            vec!["changed_behavior", "agent_tool_supply", "tool_authority"],
            if lane == "unmapped" {
                "security"
            } else {
                lane.as_str()
            },
        ),
        _ => (
            "business_invariant",
            "HLT-008-FALSE-GREEN-RISK",
            "medium",
            "configuration",
            vec!["changed_behavior", "configuration_authority"],
            lane.as_str(),
        ),
    };
    Ok(Some(vec![surface(
        catalog,
        path,
        symbol,
        kind,
        severity,
        tags,
        vec![rule],
        vec![lane],
    )]))
}
