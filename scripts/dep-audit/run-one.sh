#!/usr/bin/env bash
#
# scripts/dep-audit/run-one.sh <tool>
#
# Runs ONE of cargo-audit, cargo-deny, or cargo-outdated against the
# current checkout and emits that tool's Markdown section on stdout.
# Exits 0 on clean, 1 if the tool reports a blocking finding (cargo-audit
# advisory or cargo-deny error). cargo-outdated is informational and
# always exits 0.
#
# The matrix dep-audit workflow invokes this once per matrix cell so the
# three tools run in parallel. The legacy audit.sh wrapper chains all
# three for local use.

set -uo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <cargo-audit|cargo-deny|cargo-outdated>" >&2
  exit 2
fi

TOOL="$1"

# Force cargo and downstream tools to never emit ANSI color codes. Without
# this, cargo tree / cargo audit emit \x1b[...m sequences that survive into
# the Markdown report, break the grep parsing of cargo tree output, and
# render as garbage in the PR comment body.
export CARGO_TERM_COLOR=never
export NO_COLOR=1
export CLICOLOR=0

# Locate the repo root from this script's location, so the script can be
# run from any directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

emit() { printf '%s\n' "$*"; }

# Audit ignores: known advisories tracked separately. Each entry has a
# comment naming the tracking issue. Lifted as the underlying upgrades
# land. See ErgodicLabs/btt#11 for the wasmtime/subxt upgrade tracker.
AUDIT_IGNORES=(
  # wasmtime 8.0.1 vulnerabilities (transitive via subxt 0.38.1 -> sp-core);
  # btt does not execute wasm at runtime; tracked in #11
  RUSTSEC-2023-0091
  RUSTSEC-2024-0438
  RUSTSEC-2025-0118
  RUSTSEC-2026-0020
  RUSTSEC-2026-0021
  RUSTSEC-2026-0085
  RUSTSEC-2026-0086
  RUSTSEC-2026-0087
  RUSTSEC-2026-0088
  RUSTSEC-2026-0089
  RUSTSEC-2026-0091
  RUSTSEC-2026-0092
  RUSTSEC-2026-0093
  RUSTSEC-2026-0094
  RUSTSEC-2026-0095
  RUSTSEC-2026-0096
  # bincode 1.x EOL / wasmtime-jit transitive — #11
  RUSTSEC-2024-0388
  RUSTSEC-2025-0141
  # Unmaintained crates pulled in transitively — #11
  RUSTSEC-2020-0168  # mach
  RUSTSEC-2022-0061  # parity-wasm
  RUSTSEC-2022-0080  # proc-macro-error
  RUSTSEC-2023-0037  # bigdecimal
  RUSTSEC-2024-0370  # proc-macro-error variant
  RUSTSEC-2024-0436  # paste
  RUSTSEC-2024-0442  # backoff
  RUSTSEC-2025-0057  # fxhash
  RUSTSEC-2026-0002  # derivative
  RUSTSEC-2026-0097  # instant
)

run_audit() {
  # cargo-audit section, prefixed by a direct-deps inventory so the
  # audited surface is visible alongside the advisory output.
  emit '### Direct deps'
  emit ''
  emit '```'
  cargo tree --depth 1 --quiet 2>/dev/null || emit '(cargo tree failed)'
  emit '```'
  emit ''

  # Count direct deps for the summary line. cargo tree's tree-drawing
  # characters are emitted with leading whitespace; match anything that
  # starts with a tree-corner glyph anywhere on the line.
  local direct_count total_count
  direct_count="$(cargo tree --depth 1 --quiet 2>/dev/null | grep -cE '[├└]──' || true)"
  total_count="$(cargo tree --quiet 2>/dev/null | grep -cE '[├└]──' || true)"
  emit "Total: ${direct_count:-0} direct, ${total_count:-0} entries in resolved tree (transitive)."
  emit ''

  emit '### cargo-audit'
  emit ''
  emit '```'
  local audit_ignore_args=()
  local id
  for id in "${AUDIT_IGNORES[@]}"; do
    audit_ignore_args+=("--ignore" "${id}")
  done
  local audit_output audit_status
  audit_output="$(cargo audit --quiet "${audit_ignore_args[@]}" 2>&1)"
  audit_status=$?
  emit "${audit_output}"
  emit '```'
  if [ ${audit_status} -ne 0 ]; then
    emit ''
    emit '**FAIL**: cargo-audit reported one or more advisories.'
    return 1
  fi
  emit ''
  emit 'no advisories.'
  return 0
}

run_deny() {
  emit '### cargo-deny'
  emit ''
  local deny_config="${SCRIPT_DIR}/deny.toml"
  if [ ! -f "${deny_config}" ]; then
    emit "(no deny.toml at ${deny_config}, skipping)"
    return 0
  fi
  emit '```'
  # cargo-deny argument order: subcommand first, options after.
  local deny_output deny_status
  deny_output="$(cargo deny check --config "${deny_config}" 2>&1)"
  deny_status=$?
  emit "${deny_output}"
  emit '```'
  if [ ${deny_status} -ne 0 ]; then
    emit ''
    emit '**FAIL**: cargo-deny reported one or more issues.'
    return 1
  fi
  emit ''
  emit 'no issues.'
  return 0
}

run_outdated() {
  emit '### cargo-outdated'
  emit ''
  emit '```'
  local outdated_output
  outdated_output="$(cargo outdated --depth 1 --root-deps-only 2>&1 || true)"
  emit "${outdated_output}"
  emit '```'
  emit ''
  emit '_cargo-outdated is informational only and does not affect the audit status._'
  return 0
}

case "${TOOL}" in
  cargo-audit)
    run_audit
    exit $?
    ;;
  cargo-deny)
    run_deny
    exit $?
    ;;
  cargo-outdated)
    run_outdated
    exit $?
    ;;
  *)
    echo "unknown tool: ${TOOL}" >&2
    echo "usage: $0 <cargo-audit|cargo-deny|cargo-outdated>" >&2
    exit 2
    ;;
esac
