#!/usr/bin/env bash
#
# scripts/dep-audit/audit.sh
#
# Thin backwards-compatible wrapper that runs all three dep-audit tools
# in sequence by invoking scripts/dep-audit/run-one.sh once per tool,
# and emits a single combined Markdown report on stdout. The CI workflow
# uses run-one.sh directly via a matrix strategy; this wrapper exists
# for local invocation.
#
# Exit codes:
#   0  — all tools clean
#   1  — at least one cargo-audit advisory or cargo-deny error

set -uo pipefail

# Mirror run-one.sh's color suppression so a direct local invocation of
# this wrapper emits an ANSI-free report even when the caller's shell
# defaults differ.
export CARGO_TERM_COLOR=never
export NO_COLOR=1
export CLICOLOR=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

emit() { printf '%s\n' "$*"; }

RUN_ONE="${SCRIPT_DIR}/run-one.sh"
if [ ! -x "${RUN_ONE}" ]; then
  # Fall back to bash invocation if the executable bit is not set.
  RUN_ONE=(bash "${SCRIPT_DIR}/run-one.sh")
else
  RUN_ONE=("${RUN_ONE}")
fi

emit '## Dep audit'
emit ''
emit "Run against \`$(git rev-parse --short HEAD)\` on \`$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)\`."
emit ''

exit_status=0

for tool in cargo-audit cargo-deny cargo-outdated; do
  "${RUN_ONE[@]}" "${tool}"
  tool_status=$?
  if [ ${tool_status} -ne 0 ]; then
    exit_status=1
  fi
  emit ''
done

if [ ${exit_status} -eq 0 ]; then
  emit 'STATUS: PASS'
else
  emit 'STATUS: FAIL'
fi

exit ${exit_status}
