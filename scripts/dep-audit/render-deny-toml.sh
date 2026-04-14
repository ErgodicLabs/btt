#!/usr/bin/env bash
#
# scripts/dep-audit/render-deny-toml.sh [output-path]
#
# Renders `deny.toml.in` with the `@@RUSTSEC_IGNORES@@` placeholder
# replaced by the body of the rustsec ignore list (see issue #52 and
# `rustsec-ignores.jsonl`). Writes to stdout by default, or to
# `output-path` if provided.
#
# This decouples the cargo-deny config from the hand-edited ignore list
# so the same jsonl drives both cargo-audit (via the `--audit` mode of
# render-ignores.sh) and cargo-deny. Adding a new advisory to ignore is
# a single-line append to rustsec-ignores.jsonl.
#
# Local usage:
#
#   scripts/dep-audit/render-deny-toml.sh > /tmp/deny.toml
#   cargo deny --config /tmp/deny.toml check
#
# run-one.sh's run_deny() calls this with a mktemp target and feeds the
# temp file to cargo-deny, so the rendered config never pollutes the
# tree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/deny.toml.in"
RENDER_IGNORES="${SCRIPT_DIR}/render-ignores.sh"

if [ ! -f "${TEMPLATE}" ]; then
  echo "render-deny-toml: template not found: ${TEMPLATE}" >&2
  exit 1
fi
if [ ! -x "${RENDER_IGNORES}" ] && [ ! -f "${RENDER_IGNORES}" ]; then
  echo "render-deny-toml: render-ignores.sh not found: ${RENDER_IGNORES}" >&2
  exit 1
fi

OUTPUT_PATH="${1:-}"

# Render the ignore block into a temp file so we can inject it with a
# single awk pass without worrying about escaping backslashes, ampersands,
# or slashes in the substituted content.
IGNORE_FRAGMENT="$(mktemp)"
trap 'rm -f "${IGNORE_FRAGMENT}"' EXIT

bash "${RENDER_IGNORES}" --deny > "${IGNORE_FRAGMENT}"

# awk replaces the single `@@RUSTSEC_IGNORES@@` line with the contents of
# the fragment file. The placeholder must be the only non-whitespace on
# its line in the template (we put it on its own line between the `[` and
# `]` of the `ignore = [ ... ]` block).
render() {
  awk -v frag="${IGNORE_FRAGMENT}" '
    /^[[:space:]]*@@RUSTSEC_IGNORES@@[[:space:]]*$/ {
      while ((getline line < frag) > 0) print line
      close(frag)
      next
    }
    { print }
  ' "${TEMPLATE}"
}

if [ -n "${OUTPUT_PATH}" ]; then
  render > "${OUTPUT_PATH}"
else
  render
fi
