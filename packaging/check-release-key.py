#!/usr/bin/python3
"""Fail unless a release carries the key that `uuway update` trusts.

    packaging/check-release-key.py

Run by the release workflow before it builds. A release without the key would ship an updater that
refuses everything, and, since a new key can only be introduced by a release signed with the old
one, every machine on it would have to be updated by hand.

It checks that the keyring is in the repository, that the fingerprints pinned in the code are
those of that keyring, and that the package manifest ships it.
"""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
KEYRING = 'config/uuway-release.gpg'


def pinned_fingerprints(source):
    """The upper-case fingerprints in `TRUSTED_FINGERPRINTS = (...)`, read without importing the file."""
    match = re.search(r'^TRUSTED_FINGERPRINTS\s*=\s*\(([^)]*)\)', source, re.M)
    return {item.upper() for item in re.findall(r"['\"]([0-9A-Fa-f]{40})['\"]", match.group(1))} if match else set()


def keyring_fingerprints(keyring):
    listing = subprocess.run(['gpg', '--show-keys', '--with-colons', str(keyring)], capture_output=True, text=True,
                             check=True).stdout
    found, expect_primary = set(), False
    for line in listing.splitlines():
        if line.startswith('pub:'):
            expect_primary = True
        elif line.startswith('fpr:') and expect_primary:
            found.add(line.split(':')[9].upper())
            expect_primary = False
    return found


def problems(root=ROOT):
    root = Path(root)
    found = []
    keyring = root / KEYRING
    try:
        pinned = pinned_fingerprints((root / 'scripts/uuway_update_apply.py').read_text())
    except OSError as error:
        return [f'cannot read scripts/uuway_update_apply.py: {error.strerror}']
    if not keyring.is_file():
        found.append(f'{KEYRING} is not in the repository (docs/release-signing.md says how to make the release key)')
    if not pinned:
        found.append('TRUSTED_FINGERPRINTS in scripts/uuway_update_apply.py is empty')
    if keyring.is_file() and pinned:
        try:
            if keyring_fingerprints(keyring) != pinned:
                found.append(f'{KEYRING} and TRUSTED_FINGERPRINTS describe different keys')
        except (OSError, subprocess.CalledProcessError) as error:
            found.append(f'cannot read {KEYRING} with gpg: {error}')
    try:
        manifest = (root / 'packaging/deb_manifest.py').read_text()
    except OSError as error:
        found.append(f'cannot read packaging/deb_manifest.py: {error.strerror}')
    else:
        if KEYRING not in manifest:
            found.append(f'packaging/deb_manifest.py does not ship {KEYRING}')
    return found


def main():
    found = problems()
    if found:
        print('This checkout has no release key that the updater would trust, so it cannot be released:', file=sys.stderr)
        for problem in found:
            print(f'  - {problem}', file=sys.stderr)
        return 1
    print('release key: in the repository, pinned in the code, and shipped by the package')
    return 0


if __name__ == '__main__':
    sys.exit(main())
