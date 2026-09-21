#!/usr/bin/env bash
#
# generate.sh regenerates the golden-vector fixtures in
# ntlm_security_session_interop_fixtures_test.go by fetching the real,
# pinned github.com/bodgit/ntlmssp source (never vendored into this repo)
# and running it against a small glue file (friend_test.go.tmpl) that calls
# bodgit's own unexported newSecuritySession/SecuritySession.Wrap.
#
# This script is not part of `make test`/`make ci`/CI. It needs network
# access (go mod download from proxy.golang.org + sum.golang.org, or your
# GOPROXY/GOSUMDB) and runs by hand, on demand, only when the fixtures need
# to regenerate (for example, a BODGIT_VERSION bump below).
#
# Usage: scripts/ntlm-bodgit-fixtures/generate.sh
#
# Fixture generation has no randomness (fixed session key and plaintext,
# and bodgit's Wrap/calculateSignature chain has none either), so two runs
# at the same BODGIT_VERSION produce the same output and an empty diff.
set -euo pipefail

# Pinned to the exact version this repo depended on before the "Drop
# bodgit/ntlmssp and bodgit/windows from go.mod/go.sum" commit removed it.
# A bump here changes what "wire-compatible with bodgit" means, so bump it
# on purpose, not as a side effect of an unrelated change.
readonly BODGIT_MODULE="github.com/bodgit/ntlmssp"
readonly BODGIT_VERSION="v0.0.0-20240506230425-31973bb52d9b"

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly TARGET_FILE="${REPO_ROOT}/ntlm_security_session_interop_fixtures_test.go"
readonly BEGIN_MARK="// ntlm-bodgit-fixtures:generated:begin"
readonly END_MARK="// ntlm-bodgit-fixtures:generated:end"

readonly SCRATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ntlm-bodgit-fixtures.XXXXXX")"
trap 'rm -rf "${SCRATCH_DIR}"' EXIT

echo "==> fetching ${BODGIT_MODULE}@${BODGIT_VERSION} (verified against \$GOSUMDB)" >&2

DOWNLOAD_JSON="${SCRATCH_DIR}/download.json"
go mod download -json "${BODGIT_MODULE}@${BODGIT_VERSION}" > "${DOWNLOAD_JSON}" \
  || { echo "error: go mod download failed -- check network access / GOPROXY / GOSUMDB" >&2; exit 1; }

BODGIT_CACHE_DIR="$(grep -o '"Dir": *"[^"]*"' "${DOWNLOAD_JSON}" | sed -E 's/"Dir": *"([^"]*)"/\1/')"
if [[ -z "${BODGIT_CACHE_DIR}" || ! -d "${BODGIT_CACHE_DIR}" ]]; then
  echo "error: could not determine module cache dir from go mod download output" >&2
  cat "${DOWNLOAD_JSON}" >&2
  exit 1
fi

WORK_DIR="${SCRATCH_DIR}/bodgit-work"
cp -R "${BODGIT_CACHE_DIR}" "${WORK_DIR}"
chmod -R u+w "${WORK_DIR}"

echo "==> checking bodgit internals this script depends on still exist" >&2
required_symbols=(
  'func newSecuritySession('
  'sourceClient securitySource = iota'
  'ntlmsspNegotiateSign'
  'ntlmsspNegotiateSeal'
  'ntlmsspNegotiateExtendedSessionsecurity'
  'ntlmsspNegotiate128'
  'ntlmsspNegotiate56'
  'ntlmsspNegotiateKeyExch'
)
for sym in "${required_symbols[@]}"; do
  if ! grep -rqF -- "${sym}" "${WORK_DIR}"/*.go; then
    cat >&2 <<EOF
error: bodgit/ntlmssp@${BODGIT_VERSION} no longer contains expected symbol:
  ${sym}
friend_test.go.tmpl and/or this script need updating for this bodgit
version before fixtures can be regenerated.
EOF
    exit 1
  fi
done

echo "==> staging glue file and running it against real bodgit/ntlmssp" >&2
cp "${SCRIPT_DIR}/friend_test.go.tmpl" "${WORK_DIR}/friend_test.go"

GEN_OUTPUT="${SCRATCH_DIR}/generated.txt"
(
  cd "${WORK_DIR}"
  go test -run '^TestGenerateWinrmInteropFixtures$' -v .
) > "${GEN_OUTPUT}" 2> "${SCRATCH_DIR}/generated.stderr" \
  || { echo "error: go test against bodgit/ntlmssp + glue file failed:" >&2; cat "${SCRATCH_DIR}/generated.stderr" >&2; exit 1; }

BLOCK_FILE="${SCRATCH_DIR}/block.txt"
awk -v begin="${BEGIN_MARK}" -v end="${END_MARK}" '
  $0 == begin { inblock=1; next }
  $0 == end   { inblock=0; next }
  inblock     { print }
' "${GEN_OUTPUT}" > "${BLOCK_FILE}"

if [[ ! -s "${BLOCK_FILE}" ]]; then
  echo "error: generator produced no fixture block -- see raw output below:" >&2
  cat "${GEN_OUTPUT}" >&2
  exit 1
fi

fixture_count="$(grep -c '^\s*name:' "${BLOCK_FILE}" || true)"
if [[ "${fixture_count}" -ne 6 ]]; then
  echo "error: expected 6 generated fixtures, got ${fixture_count}:" >&2
  cat "${BLOCK_FILE}" >&2
  exit 1
fi

echo "==> splicing generated fixtures into ${TARGET_FILE}" >&2
if ! grep -qF "${BEGIN_MARK}" "${TARGET_FILE}" || ! grep -qF "${END_MARK}" "${TARGET_FILE}"; then
  echo "error: sentinel markers not found in ${TARGET_FILE} -- has it been restructured?" >&2
  echo "expected: ${BEGIN_MARK} / ${END_MARK}" >&2
  exit 1
fi

TMP_TARGET="${SCRATCH_DIR}/target.go"
awk -v begin="${BEGIN_MARK}" -v end="${END_MARK}" -v blockfile="${BLOCK_FILE}" '
  $0 == begin { print; while ((getline l < blockfile) > 0) print l; inblock=1; next }
  $0 == end   { print; inblock=0; next }
  inblock     { next }
  { print }
' "${TARGET_FILE}" > "${TMP_TARGET}"

mv "${TMP_TARGET}" "${TARGET_FILE}"
gofmt -w "${TARGET_FILE}"

echo "==> done. Review with: jj diff -- ntlm_security_session_interop_fixtures_test.go" >&2
