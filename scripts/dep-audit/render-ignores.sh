#!/usr/bin/env bash
#
# scripts/dep-audit/render-ignores.sh <--audit|--deny> [jsonl-path]
#
# Single source of truth for the rustsec ignore list (see issue #52).
# Reads scripts/dep-audit/rustsec-ignores.jsonl — one `{"id": "...",
# "reason": "..."}` entry per line — and emits the list in one of two
# shapes:
#
#   --audit  ->  one `--ignore RUSTSEC-xxxx` arg pair per line, on stdout.
#                Fed into cargo-audit's CLI via `xargs` or shell splitting
#                from run-one.sh's run_audit().
#
#   --deny   ->  the body of a TOML `ignore = [...]` array, one
#                `    "RUSTSEC-xxxx",` per line, on stdout. Substituted
#                by render-deny-toml.sh into deny.toml.in where the
#                `@@RUSTSEC_IGNORES@@` placeholder lives.
#
# Exit code: 0 on success, 2 on bad args, 1 on malformed jsonl.
#
# The script uses jq to parse jsonl so each line can carry arbitrary
# reason text without quoting hazards. jq is preinstalled on
# ubuntu-latest (the CI runner) and is a hard dep of the dep-audit
# workflow after this change; local developers need it installed to
# render the config by hand.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: render-ignores.sh <--audit|--deny> [jsonl-path]

  --audit    emit `--ignore RUSTSEC-xxxx` args for cargo-audit CLI
  --deny     emit TOML list body for deny.toml ignore = [...] substitution

  jsonl-path defaults to scripts/dep-audit/rustsec-ignores.jsonl relative
  to this script's own directory.
EOF
  exit 2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  usage
fi

MODE="$1"
case "${MODE}" in
  --audit|--deny) ;;
  -h|--help) usage ;;
  *) usage ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JSONL="${2:-${SCRIPT_DIR}/rustsec-ignores.jsonl}"

if [ ! -f "${JSONL}" ]; then
  echo "render-ignores: jsonl not found: ${JSONL}" >&2
  exit 1
fi

# Validate the jsonl up front so a malformed line fails loudly with a
# line number instead of silently producing a short ignore list.
# blank lines and lines parsing to null are tolerated; non-blank lines
# must parse as JSON with a non-empty "id" field (#56 NIT 56.3).
if ! jq -e 'has("id")' "${JSONL}" >/dev/null 2>&1; then
  # jq -e over a jsonl stream returns false only if the last value is
  # false/null; a parse error exits non-zero. Either way, re-run with a
  # per-line parse to pinpoint the offending line.
  lineno=0
  while IFS= read -r line; do
    lineno=$((lineno + 1))
    if ! printf '%s\n' "${line}" | jq -e 'type == "object" and has("id")' >/dev/null 2>&1; then
      echo "render-ignores: malformed jsonl at ${JSONL}:${lineno}: ${line}" >&2
      exit 1
    fi
  done < "${JSONL}"
fi

case "${MODE}" in
  --audit)
    # Emit one line per advisory: `--ignore RUSTSEC-xxxx`. run-one.sh
    # reads this with `mapfile` and passes it as an array to cargo-audit.
    jq -r '"--ignore " + .id' "${JSONL}"
    ;;
  --deny)
    # Emit the body of a TOML array literal — the `ignore = [` / `]`
    # braces live in deny.toml.in. Indentation matches the surrounding
    # TOML (4 spaces).
    jq -r '"    \"" + .id + "\","' "${JSONL}"
    ;;
esac
