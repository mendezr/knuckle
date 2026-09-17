#!/usr/bin/env bash
# Flatcar artifact verification helpers — sourced by scripts/build-iso.sh and
# the Justfile _ensure-base recipe.
#
# Verifies a downloaded Flatcar artifact: fetches <url>.DIGESTS and
# <url>.DIGESTS.asc, confirms the GPG clearsigned signature against the embedded
# Flatcar signing key, then confirms the artifact's SHA512. Exits non-zero on a
# GPG or SHA512 mismatch.
#
# Fail closed by default: if the metadata (.DIGESTS or .DIGESTS.asc) is
# unreachable the build aborts. A network attacker who can serve a 404 for the
# digests (or a corrupted artifact) must not be able to silently degrade
# verification to zero. ALLOW_UNVERIFIED_PXE=1 is an explicit opt-out for the
# rare local-dev case where the CDN genuinely does not publish per-file digests;
# unverified builds must be a deliberate choice, never a silent default.
set -euo pipefail

# Resolve the repo root from this file's location: scripts/lib/verify-flatcar.sh
# -> two levels up is the repository root.
_FLATCAR_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT_DIR="$_FLATCAR_LIB_DIR"
FLATCAR_KEY="$ROOT_DIR/internal/bakery/keys/flatcar-signing.asc"

# ALLOW_UNVERIFIED_PXE=1 is the only opt-out from the fail-closed default (see the
# header note). Do not clobber a value an already-set caller may have chosen.
ALLOW_UNVERIFIED_PXE="${ALLOW_UNVERIFIED_PXE:-0}"

# verify_flatcar_file <local_file> <upstream_url> <upstream_name>
#
# upstream_url is the base artifact URL; .DIGESTS / .DIGESTS.asc are appended.
# upstream_name is the bare filename used to match the line inside DIGESTS.
verify_flatcar_file() {
    local local_file="$1"
    local upstream_url="$2"
    local upstream_name="$3"

    local digests_url="${upstream_url}.DIGESTS"
    local asc_url="${digests_url}.asc"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    local digests_file="$tmp_dir/DIGESTS"
    local asc_file="$tmp_dir/DIGESTS.asc"

    # Fetch DIGESTS. Fail closed by default: if the metadata is unreachable the
    # build aborts so an attacker who can serve a 404 (or a corrupted artifact)
    # cannot silently degrade verification to zero. ALLOW_UNVERIFIED_PXE=1 is an
    # explicit opt-out for the rare local-dev case where the CDN does not publish
    # per-file digests.
    if ! curl -fsSL --max-time 30 -o "$digests_file" "$digests_url" 2>/dev/null; then
        rm -rf "$tmp_dir"
        if [[ "${ALLOW_UNVERIFIED_PXE}" == "1" ]]; then
            echo "  ⚠ DIGESTS not available for $upstream_name — ALLOW_UNVERIFIED_PXE set, skipping verification" >&2
            return 0
        fi
        echo "error: DIGESTS not available for $upstream_name — refusing to build with unverified artifacts" >&2
        exit 1
    fi

    # GPG signature verification.
    # Flatcar .DIGESTS.asc is a clearsigned message (PGP SIGNED MESSAGE, not a
    # detached signature), so we use --decrypt which verifies and extracts the
    # content in one step. We then use the verified content for the SHA512 check
    # instead of the separately downloaded unsigned .DIGESTS file.
    if curl -fsSL --max-time 30 -o "$asc_file" "$asc_url" 2>/dev/null; then
        local gpg_home="$tmp_dir/gnupg"
        local verified_digests="$tmp_dir/DIGESTS.verified"
        mkdir -p "$gpg_home"
        chmod 700 "$gpg_home"
        GNUPGHOME="$gpg_home" gpg --quiet --import "$FLATCAR_KEY" 2>/dev/null
        if ! GNUPGHOME="$gpg_home" gpg --quiet --decrypt "$asc_file" > "$verified_digests" 2>/dev/null; then
            rm -rf "$tmp_dir"
            echo "error: GPG signature verification failed for $upstream_name" >&2
            exit 1
        fi
        echo "  ✓ GPG signature verified: $upstream_name"
        # Use the verified (signature-checked) content for the SHA512 lookup.
        digests_file="$verified_digests"
    else
        # Missing .DIGESTS.asc: fail closed by default so an attacker cannot skip
        # the GPG gate by 404ing the signature. ALLOW_UNVERIFIED_PXE=1 opts out.
        if [[ "${ALLOW_UNVERIFIED_PXE}" == "1" ]]; then
            echo "  ⚠ .DIGESTS.asc unavailable — GPG check skipped for $upstream_name" >&2
        else
            rm -rf "$tmp_dir"
            echo "error: .DIGESTS.asc unavailable for $upstream_name — refusing to trust unsigned DIGESTS" >&2
            exit 1
        fi
    fi

    # SHA512 verification against the DIGESTS file (filename-bound, not just hash)
    local insha512=0 expected_hash=""
    while IFS= read -r line; do
        if [[ "$line" == "# SHA512 HASH" ]]; then
            insha512=1; continue
        fi
        if [[ "$line" =~ ^# ]]; then
            insha512=0; continue
        fi
        if [[ "$insha512" -eq 1 && -n "$line" ]]; then
            local hash fname
            hash="${line%%  *}"
            fname="${line##*  }"
            if [[ "$fname" == "$upstream_name" ]]; then
                expected_hash="$hash"
                break
            fi
        fi
    done < "$digests_file"

    if [[ -z "$expected_hash" ]]; then
        rm -rf "$tmp_dir"
        echo "error: SHA512 for $upstream_name not found in DIGESTS" >&2
        exit 1
    fi

    local actual_hash
    actual_hash="$(sha512sum "$local_file" | awk '{print $1}')"
    if [[ "$actual_hash" != "$expected_hash" ]]; then
        rm -rf "$tmp_dir"
        echo "error: SHA512 mismatch for $upstream_name (expected $expected_hash, got $actual_hash)" >&2
        exit 1
    fi
    echo "  ✓ SHA512 verified: $upstream_name"

    rm -rf "$tmp_dir"
}
