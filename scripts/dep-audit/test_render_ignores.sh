#!/usr/bin/env bash
#
# scripts/dep-audit/test_render_ignores.sh
#
# Unit tests for render-ignores.sh and render-deny-toml.sh (issue #52).
# Plain bash, no pytest or external harness — it asserts expected
# output against a fixture jsonl and exits 0 on pass, 1 on fail.
#
# Invoked from the dep-audit CI workflow as a pre-check before the
# matrix runs, so regressions in the renderers fail fast and loud
# instead of bleeding into the audit jobs as "missing advisory" errors.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDER_IGNORES="${SCRIPT_DIR}/render-ignores.sh"
RENDER_DENY_TOML="${SCRIPT_DIR}/render-deny-toml.sh"

FAIL=0
TESTS=0

trap 'rm -rf "${TMPDIR_X:-}"' EXIT
TMPDIR_X="$(mktemp -d)"

pass() {
  TESTS=$((TESTS + 1))
  printf '  PASS  %s\n' "$1"
}

fail() {
  TESTS=$((TESTS + 1))
  FAIL=$((FAIL + 1))
  printf '  FAIL  %s\n' "$1" >&2
  if [ "$#" -ge 2 ]; then
    printf '        %s\n' "$2" >&2
  fi
}

assert_eq() {
  local name="$1" want="$2" got="$3"
  if [ "${want}" = "${got}" ]; then
    pass "${name}"
  else
    fail "${name}" "want: ${want}"
    printf '        got:  %s\n' "${got}" >&2
  fi
}

assert_contains() {
  local name="$1" needle="$2" haystack="$3"
  if printf '%s\n' "${haystack}" | grep -qF -- "${needle}"; then
    pass "${name}"
  else
    fail "${name}" "missing: ${needle}"
    printf '        in:   %s\n' "${haystack}" >&2
  fi
}

# ---------------------------------------------------------------------
# Fixture: three advisories, varied reason shapes (including one with
# embedded quotes and arrows to catch naive sed/printf escaping).
# ---------------------------------------------------------------------
FIXTURE="${TMPDIR_X}/fixture.jsonl"
cat > "${FIXTURE}" <<'EOF'
{"id": "RUSTSEC-2099-0001", "reason": "fixture: wasmtime transitive, see #11"}
{"id": "RUSTSEC-2099-0002", "reason": "fixture: bincode 1.x EOL / \"wasmtime-jit\""}
{"id": "RUSTSEC-2099-0003", "reason": "fixture: unmaintained: foo -> bar -> baz"}
EOF

echo "--- render-ignores.sh --audit ---"
AUDIT_OUT="$(bash "${RENDER_IGNORES}" --audit "${FIXTURE}")"
AUDIT_LINES="$(printf '%s\n' "${AUDIT_OUT}" | wc -l | tr -d ' ')"
assert_eq "audit: line count == 3" "3" "${AUDIT_LINES}"
assert_contains "audit: has --ignore RUSTSEC-2099-0001" "--ignore RUSTSEC-2099-0001" "${AUDIT_OUT}"
assert_contains "audit: has --ignore RUSTSEC-2099-0002" "--ignore RUSTSEC-2099-0002" "${AUDIT_OUT}"
assert_contains "audit: has --ignore RUSTSEC-2099-0003" "--ignore RUSTSEC-2099-0003" "${AUDIT_OUT}"

# Exact first line, to pin the output format (space-separated pair).
FIRST_AUDIT="$(printf '%s\n' "${AUDIT_OUT}" | head -1)"
assert_eq "audit: first line exact format" "--ignore RUSTSEC-2099-0001" "${FIRST_AUDIT}"

echo "--- render-ignores.sh --deny ---"
DENY_OUT="$(bash "${RENDER_IGNORES}" --deny "${FIXTURE}")"
DENY_LINES="$(printf '%s\n' "${DENY_OUT}" | wc -l | tr -d ' ')"
assert_eq "deny: line count == 3" "3" "${DENY_LINES}"
FIRST_DENY="$(printf '%s\n' "${DENY_OUT}" | head -1)"
assert_eq "deny: first line exact format" '    "RUSTSEC-2099-0001",' "${FIRST_DENY}"
assert_contains "deny: has quoted 0002" '    "RUSTSEC-2099-0002",' "${DENY_OUT}"
assert_contains "deny: has quoted 0003" '    "RUSTSEC-2099-0003",' "${DENY_OUT}"

# ---------------------------------------------------------------------
# Template + render-deny-toml.sh end-to-end.
# ---------------------------------------------------------------------
echo "--- render-deny-toml.sh with fixture template ---"
TEMPLATE="${TMPDIR_X}/deny.toml.in"
cat > "${TEMPLATE}" <<'EOF'
# fixture template
[advisories]
yanked = "deny"
ignore = [
@@RUSTSEC_IGNORES@@
]

[bans]
multiple-versions = "warn"
EOF

# render-deny-toml.sh wants the template + ignores file in its own
# SCRIPT_DIR, so we shim it by symlinking the real script into a temp
# dir that contains our fixture files. The script resolves paths via
# BASH_SOURCE, so the symlink target matters; we use a plain copy with
# adjacent files instead.
SHIM_DIR="${TMPDIR_X}/shim"
mkdir -p "${SHIM_DIR}"
cp "${RENDER_IGNORES}" "${SHIM_DIR}/render-ignores.sh"
cp "${RENDER_DENY_TOML}" "${SHIM_DIR}/render-deny-toml.sh"
cp "${TEMPLATE}" "${SHIM_DIR}/deny.toml.in"
cp "${FIXTURE}" "${SHIM_DIR}/rustsec-ignores.jsonl"
chmod +x "${SHIM_DIR}/render-ignores.sh" "${SHIM_DIR}/render-deny-toml.sh"

RENDERED="$(bash "${SHIM_DIR}/render-deny-toml.sh")"

assert_contains "deny.toml: has [advisories] header" "[advisories]" "${RENDERED}"
assert_contains "deny.toml: has [bans] header" "[bans]" "${RENDERED}"
assert_contains "deny.toml: has 0001 in array body" '"RUSTSEC-2099-0001",' "${RENDERED}"
assert_contains "deny.toml: has 0002 in array body" '"RUSTSEC-2099-0002",' "${RENDERED}"
assert_contains "deny.toml: has 0003 in array body" '"RUSTSEC-2099-0003",' "${RENDERED}"
if printf '%s\n' "${RENDERED}" | grep -qF '@@RUSTSEC_IGNORES@@'; then
  fail "deny.toml: placeholder substituted" "placeholder still present"
else
  pass "deny.toml: placeholder substituted"
fi

# TOML must parse, and the rendered ignore list must be exactly the
# three fixture entries in order. We write the rendered output to a
# tempfile rather than piping it on stdin because the python script
# below is itself read from stdin via heredoc.
RENDERED_FILE="${TMPDIR_X}/rendered.toml"
printf '%s\n' "${RENDERED}" > "${RENDERED_FILE}"
if python3 - "${RENDERED_FILE}" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    d = tomllib.load(f)
want = ["RUSTSEC-2099-0001", "RUSTSEC-2099-0002", "RUSTSEC-2099-0003"]
got = d["advisories"]["ignore"]
assert got == want, f"want {want}, got {got}"
print("ok")
PY
then
  pass "deny.toml: parses as TOML with expected ignore list"
else
  fail "deny.toml: parses as TOML with expected ignore list"
fi

# Output-to-file form.
OUTFILE="${TMPDIR_X}/out.toml"
bash "${SHIM_DIR}/render-deny-toml.sh" "${OUTFILE}" >/dev/null
if [ -s "${OUTFILE}" ] && grep -qF 'RUSTSEC-2099-0002' "${OUTFILE}"; then
  pass "deny.toml: output-to-path form"
else
  fail "deny.toml: output-to-path form"
fi

# ---------------------------------------------------------------------
# Malformed jsonl: render-ignores.sh should exit non-zero and not emit
# a partial list on stdout. This is the whole point of having a
# validator up front — a silently-short ignore list turns into
# "advisory not ignored" failures in the audit job.
# ---------------------------------------------------------------------
BAD="${TMPDIR_X}/bad.jsonl"
cat > "${BAD}" <<'EOF'
{"id": "RUSTSEC-2099-9001", "reason": "ok"}
not even close to json
EOF
if bash "${RENDER_IGNORES}" --audit "${BAD}" >/dev/null 2>&1; then
  fail "malformed jsonl: render-ignores exits non-zero"
else
  pass "malformed jsonl: render-ignores exits non-zero"
fi

# ---------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------
printf '\n%d tests, %d failed\n' "${TESTS}" "${FAIL}"
if [ "${FAIL}" -ne 0 ]; then
  exit 1
fi
exit 0
