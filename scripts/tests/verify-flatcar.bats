#!/usr/bin/env bats
# Tests for scripts/lib/verify-flatcar.sh: verify_flatcar_file DIGESTS fetch,
# REQUIRE_VERIFICATION hard-fail gates, GPG clearsign verification, and the
# filename-bound SHA512 lookup.
#
# Requires: bats-core (https://github.com/bats-core/bats-core)
#
# Run: bats scripts/tests/verify-flatcar.bats

LIB="$BATS_TEST_DIRNAME/../lib/verify-flatcar.sh"
ORIGINAL_PATH="$PATH"
WORK=""

setup() {
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/verify-flatcar.XXXXXX")
  mkdir -p "$WORK/bin" "$WORK/tmp"

  export STUB_LOG="$WORK/calls.log"
  : >"$STUB_LOG"

  # curl stub: -o <file> <url>. Serves canned bodies from $WORK/serve/<basename>
  # and fails (exit 22, like curl -f) when the file is absent.
  cat >"$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
out=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "curl $url" >>"$STUB_LOG"
src="$SERVE_DIR/$(basename "$url")"
[[ -f "$src" ]] || exit 22
cat "$src" >"$out"
STUB

  # gpg stub: --import succeeds; --decrypt emits $SERVE_DIR/DIGESTS.verified and
  # honours STUB_GPG_RC for the signature-failure path.
  cat >"$WORK/bin/gpg" <<'STUB'
#!/usr/bin/env bash
echo "gpg $*" >>"$STUB_LOG"
for arg in "$@"; do
  if [[ "$arg" == "--import" ]]; then
    exit 0
  fi
  if [[ "$arg" == "--decrypt" ]]; then
    [[ "${STUB_GPG_RC:-0}" -eq 0 ]] || exit "$STUB_GPG_RC"
    cat "$SERVE_DIR/DIGESTS.verified"
    exit 0
  fi
done
exit 0
STUB

  # sha512sum stub: prints the caller-chosen hash of the local artifact.
  cat >"$WORK/bin/sha512sum" <<'STUB'
#!/usr/bin/env bash
echo "sha512sum $*" >>"$STUB_LOG"
printf '%s  %s\n' "${STUB_ACTUAL_HASH:-deadbeef}" "$1"
STUB

  chmod +x "$WORK"/bin/*
  export PATH="$WORK/bin:$ORIGINAL_PATH"

  export SERVE_DIR="$WORK/serve"
  mkdir -p "$SERVE_DIR"

  ARTIFACT="$WORK/flatcar_production_pxe.vmlinuz"
  echo "artifact bytes" >"$ARTIFACT"
  URL="https://example.invalid/flatcar_production_pxe.vmlinuz"
  NAME="flatcar_production_pxe.vmlinuz"

  # mktemp -d inside the lib lands here so cleanup is observable.
  export TMPDIR="$WORK/tmp"
}

teardown() {
  export PATH="$ORIGINAL_PATH"
  [ -n "$WORK" ] && rm -rf "$WORK"
}

# serve DIGESTS|DIGESTS.asc|DIGESTS.verified <<<content — publish a canned
# response. DIGESTS/DIGESTS.asc are keyed by the URL basename the lib requests;
# DIGESTS.verified is what the gpg stub emits from --decrypt.
serve() {
  case "$1" in
    DIGESTS.verified) cat >"$SERVE_DIR/DIGESTS.verified" ;;
    *) cat >"$SERVE_DIR/${NAME}.$1" ;;
  esac
}

# digests_body <hash> <filename> — a minimal Flatcar DIGESTS file.
digests_body() {
  printf '# SHA1 HASH\nabc123  %s\n\n# SHA512 HASH\n%s  %s\n' "$2" "$1" "$2"
}

# run_verify — source the lib and call verify_flatcar_file in one subshell so
# the function's `exit 1` paths surface as a non-zero status.
run_verify() {
  run bash -c 'source "$1"; verify_flatcar_file "$2" "$3" "$4"' _ \
    "$LIB" "$ARTIFACT" "$URL" "$NAME"
}

# ── DIGESTS availability / REQUIRE_VERIFICATION gate ─────────────────────────

@test "missing DIGESTS is a soft skip by default" {
  run_verify
  [ "$status" -eq 0 ]
  [[ "$output" == *"DIGESTS not available"* ]]
  [[ "$output" == *"skipping verification"* ]]
}

@test "missing DIGESTS is fatal under REQUIRE_VERIFICATION=1" {
  export REQUIRE_VERIFICATION=1
  run_verify
  [ "$status" -ne 0 ]
  [[ "$output" == *"--require-verification is set"* ]]
}

@test "REQUIRE_PXE_VERIFICATION=1 also arms the hard-fail gate" {
  export REQUIRE_PXE_VERIFICATION=1
  run_verify
  [ "$status" -ne 0 ]
  [[ "$output" == *"--require-verification is set"* ]]
}

@test "REQUIRE_VERIFICATION wins over REQUIRE_PXE_VERIFICATION" {
  export REQUIRE_VERIFICATION=0
  export REQUIRE_PXE_VERIFICATION=1
  run_verify
  [ "$status" -eq 0 ]
  [[ "$output" == *"skipping verification"* ]]
}

@test "missing .DIGESTS.asc is fatal under REQUIRE_VERIFICATION=1" {
  digests_body "goodhash" "$NAME" | serve DIGESTS
  export REQUIRE_VERIFICATION=1
  run_verify
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to trust unsigned DIGESTS"* ]]
}

@test "missing .DIGESTS.asc downgrades to unsigned DIGESTS by default" {
  digests_body "goodhash" "$NAME" | serve DIGESTS
  export STUB_ACTUAL_HASH=goodhash
  run_verify
  [ "$status" -eq 0 ]
  [[ "$output" == *"GPG check skipped"* ]]
  [[ "$output" == *"SHA512 verified"* ]]
}

# ── GPG clearsign verification ───────────────────────────────────────────────

@test "GPG decrypt failure aborts before any SHA512 check" {
  digests_body "goodhash" "$NAME" | serve DIGESTS
  echo signed | serve DIGESTS.asc
  digests_body "goodhash" "$NAME" | serve DIGESTS.verified
  export STUB_GPG_RC=2
  export STUB_ACTUAL_HASH=goodhash
  run_verify
  [ "$status" -ne 0 ]
  [[ "$output" == *"GPG signature verification failed"* ]]
  [[ "$output" != *"SHA512 verified"* ]]
  ! grep -q sha512sum "$STUB_LOG"
}

@test "verified DIGESTS content is used, not the unsigned download" {
  # Unsigned DIGESTS carries an attacker hash; the signed payload carries the
  # real one. The artifact matches only the signed payload.
  digests_body "attackerhash" "$NAME" | serve DIGESTS
  echo signed | serve DIGESTS.asc
  digests_body "realhash" "$NAME" | serve DIGESTS.verified
  export STUB_ACTUAL_HASH=realhash
  run_verify
  [ "$status" -eq 0 ]
  [[ "$output" == *"GPG signature verified"* ]]
  [[ "$output" == *"SHA512 verified"* ]]
}

@test "signing key is imported into a throwaway GNUPGHOME" {
  digests_body "goodhash" "$NAME" | serve DIGESTS
  echo signed | serve DIGESTS.asc
  digests_body "goodhash" "$NAME" | serve DIGESTS.verified
  export STUB_ACTUAL_HASH=goodhash
  run_verify
  [ "$status" -eq 0 ]
  grep -q -- "--import" "$STUB_LOG"
  [[ "$(grep -c -- "--import" "$STUB_LOG")" -eq 1 ]]
}

# ── SHA512 lookup ────────────────────────────────────────────────────────────

@test "SHA512 mismatch is fatal" {
  digests_body "goodhash" "$NAME" | serve DIGESTS
  echo signed | serve DIGESTS.asc
  digests_body "goodhash" "$NAME" | serve DIGESTS.verified
  export STUB_ACTUAL_HASH=otherhash
  run_verify
  [ "$status" -ne 0 ]
  [[ "$output" == *"SHA512 mismatch"* ]]
  [[ "$output" == *"expected goodhash"* ]]
  [[ "$output" == *"got otherhash"* ]]
}

@test "a DIGESTS file without our filename is fatal" {
  digests_body "goodhash" "some-other-artifact.img" | serve DIGESTS
  echo signed | serve DIGESTS.asc
  digests_body "goodhash" "some-other-artifact.img" | serve DIGESTS.verified
  export STUB_ACTUAL_HASH=goodhash
  run_verify
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found in DIGESTS"* ]]
}

@test "hashes outside the SHA512 section are never accepted" {
  # Our filename appears only under '# SHA1 HASH'; the SHA512 section lists a
  # different artifact. A section-blind parser would accept abc123.
  {
    printf '# SHA1 HASH\nabc123  %s\n\n' "$NAME"
    printf '# SHA512 HASH\ngoodhash  some-other-artifact.img\n'
  } | serve DIGESTS
  echo signed | serve DIGESTS.asc
  {
    printf '# SHA1 HASH\nabc123  %s\n\n' "$NAME"
    printf '# SHA512 HASH\ngoodhash  some-other-artifact.img\n'
  } | serve DIGESTS.verified
  export STUB_ACTUAL_HASH=abc123
  run_verify
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found in DIGESTS"* ]]
}

# ── Temp directory hygiene ───────────────────────────────────────────────────

@test "temp dir is removed on the success path" {
  digests_body "goodhash" "$NAME" | serve DIGESTS
  echo signed | serve DIGESTS.asc
  digests_body "goodhash" "$NAME" | serve DIGESTS.verified
  export STUB_ACTUAL_HASH=goodhash
  run_verify
  [ "$status" -eq 0 ]
  [ -z "$(ls -A "$TMPDIR")" ]
}

@test "temp dir is removed on the SHA512 mismatch path" {
  digests_body "goodhash" "$NAME" | serve DIGESTS
  echo signed | serve DIGESTS.asc
  digests_body "goodhash" "$NAME" | serve DIGESTS.verified
  export STUB_ACTUAL_HASH=otherhash
  run_verify
  [ "$status" -ne 0 ]
  [ -z "$(ls -A "$TMPDIR")" ]
}
