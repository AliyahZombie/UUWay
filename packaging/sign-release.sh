#!/usr/bin/env bash
# Sign a drafted UUWay release so that `uuway update` will install it.
#
#   packaging/sign-release.sh vX.Y.Z [--key KEYID]... [--allow-published]
#
# --key may be given twice: while the release key is being replaced, a release is signed with
# both the old and the new key.
#
# Run it on the machine that holds the release key, after CI has drafted the release and
# before it is published. It downloads the deb and SHA256SUMS from the draft, checks the
# deb against SHA256SUMS, signs a SHA256SUMS it builds itself from the deb, uploads that file and
# its signature, and then downloads them again and verifies them with the code the clients use.
# See docs/release-signing.md.
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
usage() { sed -n '2,13p' "${BASH_SOURCE[0]}" >&2; }
tag=""
key_args=()
allow_published=0
while (($#)); do
    case "$1" in
        --key) key_args+=(--local-user "${2:?--key needs a key id}"); shift 2 ;;
        --allow-published) allow_published=1; shift ;;
        -h|--help) usage; exit 0 ;;
        v[0-9]*) tag="$1"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
done
if ! [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'give the release tag, for example v1.2.0\n' >&2
    usage
    exit 2
fi
version="${tag#v}"
for tool in gh gpg gpgv sha256sum python3 dpkg; do
    command -v "$tool" >/dev/null || { printf '%s is required\n' "$tool" >&2; exit 1; }
done
keyring="$repo_dir/config/uuway-release.gpg"
[[ -f "$keyring" ]] || { printf 'config/uuway-release.gpg is not in the repository yet; see docs/release-signing.md\n' >&2; exit 1; }

is_draft="$(gh release view "$tag" --json isDraft --jq .isDraft)"
if [[ "$is_draft" != true && "$allow_published" -ne 1 ]]; then
    printf '%s is already published. Sign it while it is a draft, or pass --allow-published.\n' "$tag" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
deb="uuway_${version}_amd64.deb"
gh release download "$tag" --dir "$work" --pattern "$deb" --pattern SHA256SUMS

actual="$(sha256sum "$work/$deb" | cut -d' ' -f1)"
listed="$(awk -v name="$deb" '$2 == name {print $1}' "$work/SHA256SUMS")"
if [[ "$actual" != "$listed" ]]; then
    printf 'The deb on the release does not match its SHA256SUMS:\n  deb       %s\n  SHA256SUMS %s\n' "$actual" "${listed:-<not listed>}" >&2
    printf 'Something replaced one of them after CI built it. Do not sign; find out why.\n' >&2
    exit 1
fi

# What gets signed is built here, from the file that was just hashed, not the file downloaded.
printf '%s  %s\n' "$actual" "$deb" >"$work/SHA256SUMS"
gpg --armor --detach-sign "${key_args[@]}" --output "$work/SHA256SUMS.asc" "$work/SHA256SUMS"

# The code the clients run, against the key that is committed to the repository.
verify_as_client() {
    python3 -I - "$repo_dir" "$1" "$tag" <<'PY'
import importlib.util
from pathlib import Path
import sys

repo, stage, tag = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
spec = importlib.util.spec_from_file_location('uuway_update_apply', repo / 'scripts/uuway_update_apply.py')
apply = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apply)
try:
    release = apply.check_release(stage, tag, '0', repo / 'config/uuway-release.gpg', apply.TRUSTED_FINGERPRINTS)
except apply.VerifyError as error:
    sys.exit(f'Does not verify the way a client would: {error}')
print(f'Verified as a client would: {release.version}, sha256 {release.sha256}')
PY
}

# Before anything is uploaded: is what was just signed good?
verify_as_client "$work" || {
    printf 'Is the key you signed with the one in config/uuway-release.gpg and in TRUSTED_FINGERPRINTS?\n' >&2
    exit 1
}

# Clients fetch the release's own SHA256SUMS, so the file that was signed goes up with its signature:
# a signature over bytes that are not on the release would be a BADSIG for everyone.
gh release upload "$tag" "$work/SHA256SUMS" "$work/SHA256SUMS.asc" --clobber

# And what clients will really get: download it again from the release and check that.
published="$work/published"
mkdir "$published"
gh release download "$tag" --dir "$published" --pattern "$deb" --pattern SHA256SUMS --pattern SHA256SUMS.asc
verify_as_client "$published" || {
    printf 'The files on the published release do not verify. Do not publish %s; look at the release.\n' "$tag" >&2
    exit 1
}
printf '\nSigned %s.\n  Review the draft, then publish it:\n  gh release edit %s --draft=false --latest\n' "$tag" "$tag"
