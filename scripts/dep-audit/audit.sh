#!/usr/bin/env bash
#
# scripts/dep-audit/audit.sh
#
# Runs cargo-audit, cargo-deny, and cargo-outdated against the current
# checkout and emits a structured Markdown report on stdout. Exit code:
#   0  — no findings worth blocking on
#   1  — at least one cargo-audit advisory or cargo-deny error
#
# The workflow at .github/workflows/dep-audit.yml expects the report on
# stdout and posts it as a PR comment.
#
# This is the basic dep-audit pass. The dep-checksum tripwire that
# detects same-version-different-bytes attacks (issue #6) is layered
# on later as a separate workflow.

set -uo pipefail

# Locate the repo root from this script's location, so the script can be
# run from any directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

# Output goes to stdout; tool stderr goes to stderr (captured separately
# in CI). The exit status is the union of the tool exit codes.
exit_status=0

emit() { printf '%s\n' "$*"; }

emit '## Dep audit'
emit ''
emit "Run against \`$(git rev-parse --short HEAD)\` on \`$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)\`."
emit ''

# ---------------------------------------------------------------------
# Direct deps inventory
# ---------------------------------------------------------------------
emit '### Direct deps'
emit ''
emit '```'
cargo tree --depth 1 --quiet 2>/dev/null || emit '(cargo tree failed)'
emit '```'
emit ''

# Count direct deps for the summary line.
direct_count="$(cargo tree --depth 1 --quiet 2>/dev/null | grep -c '^[└├]──' || echo 0)"
total_count="$(cargo tree --quiet 2>/dev/null | grep -c '^[│ ]*[├└]──' || echo 0)"
emit "Total: ${direct_count} direct, ${total_count} entries in resolved tree (transitive)."
emit ''

# ---------------------------------------------------------------------
# cargo-audit (rustsec advisory db)
# ---------------------------------------------------------------------
emit '### cargo-audit'
emit ''
emit '```'
audit_output="$(cargo audit --quiet 2>&1)"
audit_status=$?
emit "${audit_output}"
emit '```'
if [ ${audit_status} -ne 0 ]; then
  emit ''
  emit '**FAIL**: cargo-audit reported one or more advisories.'
  exit_status=1
else
  emit ''
  emit '✅ no advisories.'
fi
emit ''

# ---------------------------------------------------------------------
# cargo-deny (licenses, advisories, bans, sources)
# ---------------------------------------------------------------------
emit '### cargo-deny'
emit ''
DENY_CONFIG="${SCRIPT_DIR}/deny.toml"
if [ ! -f "${DENY_CONFIG}" ]; then
  emit "(no deny.toml at ${DENY_CONFIG}, skipping)"
else
  emit '```'
  deny_output="$(cargo deny --config "${DENY_CONFIG}" check 2>&1)"
  deny_status=$?
  emit "${deny_output}"
  emit '```'
  if [ ${deny_status} -ne 0 ]; then
    emit ''
    emit '**FAIL**: cargo-deny reported one or more issues.'
    exit_status=1
  else
    emit ''
    emit '✅ no issues.'
  fi
fi
emit ''

# ---------------------------------------------------------------------
# cargo-outdated (informational, never blocks)
# ---------------------------------------------------------------------
emit '### cargo-outdated'
emit ''
emit '```'
outdated_output="$(cargo outdated --depth 1 --root-deps-only 2>&1 || true)"
emit "${outdated_output}"
emit '```'
emit ''
emit '_cargo-outdated is informational only and does not affect the audit status._'
emit ''

# ---------------------------------------------------------------------
# Final status line (parsed by the workflow)
# ---------------------------------------------------------------------
if [ ${exit_status} -eq 0 ]; then
  emit 'STATUS: PASS'
else
  emit 'STATUS: FAIL'
fi

exit ${exit_status}
