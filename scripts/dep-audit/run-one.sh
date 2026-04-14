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

# Emit a collapsible <details> block. First arg is the summary label,
# second arg is "open" (0 = collapsed by default, 1 = expanded because
# the section is a failure the reader should see without clicking), and
# the body is read from stdin.
#
# The blank lines around the body are load-bearing: GitHub Flavored
# Markdown only parses nested markdown inside a <details> block when
# there is a blank line after <summary> and before </details>. Without
# the blanks the body renders as raw HTML and the code fences show up
# as literal backticks.
emit_details() {
  local summary="$1" open_flag="$2" open_attr=""
  if [ "${open_flag}" = "1" ]; then
    open_attr=" open"
  fi
  printf '<details%s>\n' "${open_attr}"
  printf '<summary><strong>%s</strong></summary>\n' "${summary}"
  printf '\n'
  cat
  printf '\n</details>\n'
}

# Audit ignores: see issue #52. The single source of truth is
# `scripts/dep-audit/rustsec-ignores.jsonl`; `render-ignores.sh --audit`
# emits the `--ignore RUSTSEC-xxxx` pairs for cargo-audit and
# `render-deny-toml.sh` emits the fully rendered deny.toml for
# cargo-deny. This file no longer hardcodes the list.
#
# See ErgodicLabs/btt#11 for the wasmtime/subxt upgrade tracker.
RENDER_IGNORES="${SCRIPT_DIR}/render-ignores.sh"
RENDER_DENY_TOML="${SCRIPT_DIR}/render-deny-toml.sh"

run_audit() {
  # cargo-audit section, prefixed by a direct-deps inventory so the
  # audited surface is visible alongside the advisory output. Both
  # sub-sections are wrapped in collapsible <details> blocks so the
  # combined PR comment can be scanned in a single screen; cargo-audit
  # auto-expands if it reports an advisory.

  # --- Direct deps --------------------------------------------------
  local direct_tree direct_count total_count
  direct_tree="$(cargo tree --depth 1 --quiet 2>/dev/null || printf '(cargo tree failed)\n')"
  # Count direct deps for the summary line. cargo tree's tree-drawing
  # characters are emitted with leading whitespace; match anything that
  # starts with a tree-corner glyph anywhere on the line.
  direct_count="$(cargo tree --depth 1 --quiet 2>/dev/null | grep -cE '[├└]──' || true)"
  total_count="$(cargo tree --quiet 2>/dev/null | grep -cE '[├└]──' || true)"

  emit_details 'Direct deps' 0 <<EOF
\`\`\`
${direct_tree}
\`\`\`

Total: ${direct_count:-0} direct, ${total_count:-0} entries in resolved tree (transitive).
EOF
  emit ''

  # --- cargo-audit --------------------------------------------------
  # Pull the ignore list out of rustsec-ignores.jsonl at run time so
  # this script never drifts from deny.toml. Capture the renderer to a
  # tempfile first and check its exit status explicitly: a process
  # substitution (`< <(...)`) would swallow the subshell's exit status
  # and silently feed a partial `--ignore` list to cargo-audit if the
  # renderer ever mutated to emit-then-fail. That is the PR #51 drift
  # class this whole jsonl pipeline was introduced to prevent (#54
  # barbarian NIT 56.1).
  local audit_tmp
  audit_tmp="$(mktemp -t btt-audit-ignores.XXXXXX)"
  if ! bash "${RENDER_IGNORES}" --audit > "${audit_tmp}"; then
    rm -f "${audit_tmp}"
    emit_details 'cargo-audit' 1 <<'EOF'
```
(render-ignores.sh --audit failed; cannot run cargo-audit)
```
EOF
    return 1
  fi
  # Each non-empty line of render output is a single CLI token (either
  # `--ignore` or an id); word-splitting turns the pair into the two
  # array elements cargo-audit expects.
  local audit_ignore_args=()
  local line
  while IFS= read -r line; do
    [ -z "${line}" ] && continue
    # shellcheck disable=SC2206
    audit_ignore_args+=( ${line} )
  done < "${audit_tmp}"
  rm -f "${audit_tmp}"
  local audit_output audit_status
  audit_output="$(cargo audit --quiet "${audit_ignore_args[@]}" 2>&1)"
  audit_status=$?
  if [ ${audit_status} -ne 0 ]; then
    emit_details 'cargo-audit' 1 <<EOF
\`\`\`
${audit_output}
\`\`\`

**FAIL**: cargo-audit reported one or more advisories.
EOF
    return 1
  fi
  emit_details 'cargo-audit' 0 <<EOF
\`\`\`
${audit_output}
\`\`\`

no advisories.
EOF
  return 0
}

run_deny() {
  # Render deny.toml from the template + jsonl into a tempfile; the
  # committed tree never holds a generated deny.toml (see issue #52).
  local deny_config
  deny_config="$(mktemp -t btt-deny.XXXXXX.toml)"
  if ! bash "${RENDER_DENY_TOML}" "${deny_config}"; then
    rm -f "${deny_config}"
    emit_details 'cargo-deny' 1 <<'EOF'
```
(render-deny-toml.sh failed; cannot run cargo-deny)
```
EOF
    return 1
  fi
  # cargo-deny argument order: subcommand first, options after.
  local deny_output deny_status
  deny_output="$(cargo deny check --config "${deny_config}" 2>&1)"
  deny_status=$?
  rm -f "${deny_config}"
  if [ ${deny_status} -ne 0 ]; then
    emit_details 'cargo-deny' 1 <<EOF
\`\`\`
${deny_output}
\`\`\`

**FAIL**: cargo-deny reported one or more issues.
EOF
    return 1
  fi
  emit_details 'cargo-deny' 0 <<EOF
\`\`\`
${deny_output}
\`\`\`

no issues.
EOF
  return 0
}

run_outdated() {
  local outdated_output
  outdated_output="$(cargo outdated --depth 1 --root-deps-only 2>&1 || true)"
  # cargo-outdated never fails the audit, so it stays collapsed.
  emit_details 'cargo-outdated' 0 <<EOF
\`\`\`
${outdated_output}
\`\`\`

_cargo-outdated is informational only and does not affect the audit status._
EOF
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
