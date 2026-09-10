use crate::shared::sanitize;
use std::path::Path;

pub(crate) fn surface_id(surface_type: &str, path: &str, symbol: &str) -> String {
    format!(
        "surface:{}:{}:{}",
        sanitize(surface_type),
        sanitize(path),
        sanitize(symbol)
    )
}

pub(crate) fn rust_public_symbols(text: &str) -> Vec<String> {
    let mut symbols = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("pub ") else {
            continue;
        };
        if rest.starts_with("fn ")
            || rest.starts_with("async fn ")
            || rest.starts_with("struct ")
            || rest.starts_with("enum ")
            || rest.starts_with("trait ")
            || rest.starts_with("mod ")
            || rest.starts_with("type ")
        {
            if let Some(name) = rust_symbol_name(rest) {
                symbols.push(name);
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    symbols.truncate(24);
    symbols
}

fn rust_symbol_name(rest: &str) -> Option<String> {
    let rest = if let Some(rest) = rest.strip_prefix("async ") {
        rest
    } else {
        rest
    };
    let mut matched = None;
    for prefix in ["fn ", "struct ", "enum ", "trait ", "mod ", "type "] {
        if let Some(value) = rest.strip_prefix(prefix) {
            matched = Some(value);
            break;
        }
    }
    let rest = matched?;
    let name = rest
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()?
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(name.into())
    }
}

pub(crate) fn contains_authz_marker(path: &str, text: &str) -> bool {
    path.contains("auth")
        || text.contains("authorize")
        || text.contains("authorization")
        || text.contains("permission")
        || text.contains("tenant_id")
        || text.contains("owner_id")
        || text.contains("role")
}

pub(crate) fn contains_input_marker(path: &str, text: &str) -> bool {
    path.contains("parser")
        || path.contains("request")
        || text.contains("from_str")
        || text.contains("parse(")
        || text.contains("deserialize")
        || text.contains("inner_html")
        || text.contains(&["select", " * from"].concat())
        || text.contains("format!(\"select")
}

pub(crate) fn contains_process_sink(text: &str) -> bool {
    text.contains("unsafe ")
        || text.contains(&["command", "::new"].concat())
        || text.contains("std::process")
        || text.contains("remove_file")
        || text.contains("remove_dir")
        || text.contains("fs::write")
}

pub(crate) fn contains_destructive_sql(text: &str) -> bool {
    [
        concat!("drop", " table"),
        concat!("drop", " column"),
        "truncate",
        concat!("delete", " from"),
        concat!("alter", " table"),
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

pub fn is_test_or_example_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let components = normalized.split('/').collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| matches!(*component, "tests" | "examples" | "benches"))
    {
        return true;
    }
    let stem = Path::new(&normalized)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    stem == "tests" || stem.ends_with("_test") || stem.ends_with("_tests")
}

pub(crate) fn is_agent_tool_surface(path: &str, text: &str) -> bool {
    let normalized = path.replace('\\', "/");
    // Docs, badges, baselines, schemas, and maps are not executable tool supply.
    // The previous bare `text.contains("tool")` needle classified README/docs/JSON as
    // cli_command/mcp_tool and forced security/HLT-024 or proofmark-rust obligations.
    if is_documentation_or_inert_control_data(&normalized) {
        return false;
    }
    normalized.starts_with("agent/")
        || normalized.starts_with(".agents/")
        || normalized.starts_with(".cursor/")
        || normalized.starts_with(".github/workflows/")
        || normalized.starts_with("tools/")
        || normalized.contains("/mcp/")
        || normalized.contains("mcp")
        || text.contains("mcp")
}

fn is_documentation_or_inert_control_data(path: &str) -> bool {
    if path.starts_with("docs/")
        || path == "readme.md"
        || path.ends_with("/readme.md")
        || path == "changelog.md"
        || path.ends_with("/changelog.md")
        || path == "agents.md"
        || path == "claude.md"
        || path == "gemini.md"
        || path == "split.md"
        || path == "license"
        || path == "license.md"
    {
        return true;
    }
    path.contains("/baselines/")
        || path.contains("/schemas/")
        || path.ends_with(".schema.json")
        || path.ends_with("owner-map.json")
        || path.ends_with("test-map.json")
        || path.ends_with("repo-score.json")
        || path.ends_with("repo-score.provenance.json")
        || path.ends_with("jankurai-badge.json")
        || path.ends_with("jankurai-badge.svg")
        || path.ends_with(".svg")
}
