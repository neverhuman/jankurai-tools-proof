#!/usr/bin/env bash
# CI audits use an exact published source build. The governed deployment
# launcher remains available separately and keeps its production policy.
run_public_jankurai() {
  local tool_root="$REPO_ROOT/target/ci-tools"
  [[ -f "$tool_root/auditor.sha256" && ! -L "$tool_root/auditor.sha256" ]]
  [[ -f "$tool_root/bin/jankurai" && ! -L "$tool_root/bin/jankurai" ]]
  [[ "$(cat "$tool_root/auditor-source-revision")" == af340cf595fc4c3e1d822adcddc5092eb5ea3400 ]]
  (cd "$REPO_ROOT" && sha256sum --check target/ci-tools/auditor.sha256 >/dev/null)
  "$tool_root/bin/jankurai" "$@"
}
