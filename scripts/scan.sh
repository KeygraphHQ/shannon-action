#!/usr/bin/env bash
#
# Runs a Shannon scan and decides the job outcome from the produced report.
#
# Inputs arrive as IN_* environment variables (mapped by action.yml); outputs are
# written to $GITHUB_OUTPUT and a findings summary to $GITHUB_STEP_SUMMARY. Exits 0
# only on a complete assessment - a failed scan (no report) or a partial one (some
# vulnerability classes not assessed) exits non-zero.

# No -e: the scan's exit code is captured and classified, so a failed scan must not abort the script.
set -uo pipefail

# In npx mode the workspace lives under ~/.shannon/workspaces/<name>.
WS_DIR="$HOME/.shannon/workspaces/$IN_WORKSPACE"
REPORT_JSON="$WS_DIR/.shannon/deliverables/report.json"

# Export only the provider settings that were supplied.
export_credentials() {
  [ -n "$IN_API_KEY" ]                  && export SHANNON_AI_API_KEY="$IN_API_KEY"
  [ -n "$IN_MODEL" ]                    && export SHANNON_AI_MODEL="$IN_MODEL"
  [ -n "$IN_BASE_URL" ]                 && export SHANNON_AI_BASE_URL="$IN_BASE_URL"
  [ -n "$IN_OPENAI_FORMAT" ]            && export SHANNON_AI_OPENAI_FORMAT="$IN_OPENAI_FORMAT"
  [ -n "$IN_AWS_BEARER_TOKEN_BEDROCK" ] && export AWS_BEARER_TOKEN_BEDROCK="$IN_AWS_BEARER_TOKEN_BEDROCK"
  [ -n "$IN_AWS_REGION" ]               && export AWS_REGION="$IN_AWS_REGION"
  return 0
}

run_scan() {
  # -w is always passed so the workspace path is deterministic.
  local args=(start -u "$IN_URL" -r "$IN_REPO" -w "$IN_WORKSPACE" --follow)
  [ -n "$IN_CONFIG" ] && args+=(-c "$IN_CONFIG")
  [ "$IN_PIPELINE_TESTING" = "true" ] && args+=(--pipeline-testing)

  echo "Running: shannon ${args[*]}"
  npx --yes "@keygraph/shannon@${IN_VERSION}" "${args[@]}"
}

publish_report_outputs() {
  {
    [ -f "$WS_DIR/Security-Assessment-Report.pdf" ] && echo "report-pdf=$WS_DIR/Security-Assessment-Report.pdf"
    [ -f "$WS_DIR/Security-Assessment-Report.md" ]  && echo "report-md=$WS_DIR/Security-Assessment-Report.md"
    [ -f "$WS_DIR/report.sarif" ]                   && echo "sarif=$WS_DIR/report.sarif"
  } >> "$GITHUB_OUTPUT"
}

# The classes report.json marks not assessed, comma-separated (empty if none).
not_assessed_classes() {
  node -e 'try{const d=require(process.argv[1]);process.stdout.write((d.not_assessed||[]).join(", "))}catch(e){process.exit(3)}' "$REPORT_JSON"
}

# Fail if any exploited finding meets the fail-on-severity threshold. Only findings with
# status "exploited" count - a demonstrated vulnerability - so analysis-only scans (which
# have no exploited findings) never trip this gate.
severity_gate() {
  case "$IN_FAIL_ON_SEVERITY" in
    ''|none) return 0 ;;
    low|medium|high|critical) ;;
    *) echo "::error title=Shannon config error::Invalid fail-on-severity '$IN_FAIL_ON_SEVERITY' (expected none, low, medium, high, or critical)."; exit 1 ;;
  esac

  local count
  count="$(node -e '
    const d = require(process.argv[1]);
    const rank = { critical: 4, high: 3, medium: 2, low: 1 };
    const threshold = rank[process.argv[2]];
    const n = (d.findings || []).filter((f) => f.status === "exploited" && (rank[f.severity] || 0) >= threshold).length;
    process.stdout.write(String(n));
  ' "$REPORT_JSON" "$IN_FAIL_ON_SEVERITY")"

  if [ "${count:-0}" -gt 0 ] 2>/dev/null; then
    echo "::error title=Shannon severity gate::${count} exploited finding(s) at or above '$IN_FAIL_ON_SEVERITY' severity. See the job summary or the shannon-report artifact."
    exit 1
  fi
}

# Write the job summary. In exploit mode it counts exploited findings per severity;
# an analysis-only scan (report_meta.exploit false) has no exploited findings, so it
# counts all findings instead.
write_summary() {
  local outcome="$1" not_assessed="$2"
  {
    echo "## Shannon scan - $outcome"
    echo ""
    echo "Target: \`$IN_URL\`"
    echo ""
    if [ -f "$REPORT_JSON" ]; then
      node -e '
        const d = require(process.argv[1]);
        const f = Array.isArray(d.findings) ? d.findings : [];
        const exploitMode = !(d.report_meta && d.report_meta.exploit === false);
        const label = exploitMode ? "Exploited" : "Findings";
        const counts = (s) => f.filter((x) => x.severity === s && (!exploitMode || x.status === "exploited")).length;
        const total = f.filter((x) => !exploitMode || x.status === "exploited").length;
        const sevs = ["critical", "high", "medium", "low"];
        const rows = sevs.map((s) => `| ${s[0].toUpperCase() + s.slice(1)} | ${counts(s)} |`).join("\n");
        process.stdout.write(`| Severity | ${label} |\n| --- | --- |\n${rows}\n| Total | ${total} |\n`);
      ' "$REPORT_JSON"
    else
      echo "The scan did not produce a report."
    fi
    if [ -n "$not_assessed" ]; then
      echo ""
      echo "Not assessed: $not_assessed"
    fi
    echo ""
    echo "<sub>Shannon - AI Pentester by Keygraph</sub>"
  } >> "$GITHUB_STEP_SUMMARY"
}

# A plain-text findings block for the log footer, one severity per line, mirroring the
# summary table's counts. Exploit mode counts exploited findings; an analysis-only scan
# counts all findings. Each line is indented to sit under the footer's headline.
findings_line() {
  [ -f "$REPORT_JSON" ] || return 0
  node -e '
    const d = require(process.argv[1]);
    const f = Array.isArray(d.findings) ? d.findings : [];
    const exploitMode = !(d.report_meta && d.report_meta.exploit === false);
    const label = exploitMode ? "Exploited findings" : "Findings";
    const counts = (s) => f.filter((x) => x.severity === s && (!exploitMode || x.status === "exploited")).length;
    const total = f.filter((x) => !exploitMode || x.status === "exploited").length;
    const sevs = ["critical", "high", "medium", "low"];
    const rows = sevs.map((s) => `   ${s.padEnd(8)}  ${counts(s)}`).join("\n");
    process.stdout.write(` ${label}:\n${rows}\n   ─────────────\n   ${"total".padEnd(8)}  ${total}`);
  ' "$REPORT_JSON"
}

main() {
  export_credentials

  # Published up front so the workspace upload works even when the scan fails.
  echo "workspace-dir=$WS_DIR" >> "$GITHUB_OUTPUT"

  run_scan
  local rc=$?

  publish_report_outputs

  # report.json exists only when the pipeline produced an assessment; its not_assessed
  # array lists the classes that could not be assessed. Pass only on a complete one.
  local has_report="no"
  { [ "$rc" -eq 0 ] && [ -f "$REPORT_JSON" ]; } && has_report="yes"

  local not_assessed="" outcome="failed"
  if [ "$has_report" = "yes" ]; then
    not_assessed="$(not_assessed_classes)"
    [ -n "$not_assessed" ] && outcome="partial" || outcome="completed"
  fi

  write_summary "$outcome" "$not_assessed"

  # Hand the outcome and the findings line to the post-upload step, which prints them to the log
  # next to the artifact download URLs (those exist only once actions/upload-artifact has run).
  {
    echo "outcome=$outcome"
    echo "not-assessed=$not_assessed"
  } >> "$GITHUB_OUTPUT"

  # findings-line is now multi-line, so it uses the heredoc form of $GITHUB_OUTPUT. The
  # trailing echo terminates the block's last line before the closing delimiter.
  if [ "$has_report" = "yes" ]; then
    {
      echo "findings-line<<SHANNON_FINDINGS_EOF"
      findings_line
      echo ""
      echo "SHANNON_FINDINGS_EOF"
    } >> "$GITHUB_OUTPUT"
  fi

  if [ "$has_report" = "no" ]; then
    echo "::error title=Shannon scan failed::The scan did not produce a report."
    exit 1
  fi
  if [ -n "$not_assessed" ]; then
    echo "::error title=Shannon partial scan::These vulnerability classes were not assessed: ${not_assessed}. Absence of findings for them does not mean they are clean."
    exit 1
  fi

  severity_gate

  echo "Shannon scan completed - all vulnerability classes were assessed."
}

main "$@"
