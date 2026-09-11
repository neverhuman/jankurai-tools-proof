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
    // Classify by extension/format, not directory name: docs/tool.rs and
    // schemas/handler.mjs remain executable tool surfaces; README.md / docs/*.md /
    // structured configuration is classified separately before this predicate.
    if is_documentation_or_inert_control_data(&normalized) {
        return false;
    }
    let docs_or_schema_executable = (normalized.starts_with("docs/")
        || normalized.starts_with("schemas/"))
        && (normalized.ends_with(".mjs")
            || normalized.ends_with(".js")
            || normalized.ends_with(".sh"));
    normalized.starts_with("agent/")
        || normalized.starts_with(".agents/")
        || normalized.starts_with(".cursor/")
        || normalized.starts_with(".github/workflows/")
        || normalized.starts_with("tools/")
        || docs_or_schema_executable
        || normalized.contains("/mcp/")
        || normalized.contains("mcp")
        || text.contains("mcp")
}

pub(crate) fn is_documentation_or_inert_control_data(path: &str) -> bool {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let lower_name = file_name.to_ascii_lowercase();

    // Markdown / prose control docs (any directory, including docs/).
    if lower_name.ends_with(".md")
        || lower_name == "license"
        || lower_name == "copying"
        || lower_name == "notice"
    {
        return true;
    }

    // Badge / image artifacts.
    if lower_name.ends_with(".svg")
        || lower_name.ends_with(".png")
        || lower_name.ends_with(".jpg")
        || lower_name.ends_with(".jpeg")
        || lower_name.ends_with(".gif")
        || lower_name.ends_with(".webp")
    {
        return true;
    }

    false
}

pub(crate) fn is_inert_changed_path(path: &str, _text: &str) -> bool {
    is_documentation_or_inert_control_data(path)
}

/// CI scripts under `ops/ci/*.sh` — additive HLT-020 hardening. HLT-008
/// changed-behavior stays; `tools/*.sh` stays agent-tool / HLT-024.
pub(crate) fn is_ops_ci_shell_script(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with("ops/ci/") && normalized.ends_with(".sh")
}
