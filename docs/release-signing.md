# Signing a release

`uuway update install` runs a package as root on someone's machine, so it installs only a
release whose `SHA256SUMS` carries a valid signature from the UUWay release key. Checksums
alone prove nothing here: whoever can change a release page can change the deb and its
checksum together.

The key is held by the maintainer, on their own machine. It is **not** in CI and never will
be: CI builds and drafts the release, the maintainer signs the draft, then publishes it.

## What is signed, and what that means

- Only `SHA256SUMS` is signed (`SHA256SUMS.asc`, a detached, ASCII-armored signature). The
  deb is trusted through the hash listed in it.
- The version is bound through that file: the deb's name is `uuway_<version>_amd64.deb`, the
  checksum line carries that name, and the deb's own `Version` field must equal the tag. An
  old signed release replayed under a newer tag therefore fails, and a version that is not
  strictly newer than the installed one is refused.
- A signature says "the maintainer approved this build", not "this build can be reproduced":
  the build is not byte-for-byte reproducible.
- It cannot prevent a *freeze*: someone who controls the network can keep serving an old but
  validly signed release, or hide a new one. That only denies updates; it cannot install
  anything unsigned or older.

## One-time setup (the maintainer)

1. Create the key. A plain Ed25519 signing key with a passphrase, and **no expiry**: an
   expiring key would silently end updates for every machine that has not updated yet.

   ```sh
   gpg --quick-generate-key "UUWay release signing <you@example.com>" ed25519 sign never
   gpg --list-keys --with-colons --fingerprint        # the 40-digit hex on the "fpr" line
   ```

2. Make a revocation certificate now, and keep it **offline** (not on this machine):

   ```sh
   gpg --gen-revoke <FINGERPRINT> > uuway-release-revoke.asc
   ```

   Back up the private key (`gpg --export-secret-keys --armor`) encrypted, offline.

3. Put the public key in the repository and pin its fingerprint in the code:

   ```sh
   gpg --export <FINGERPRINT> > config/uuway-release.gpg
   ```

   Then set `TRUSTED_FINGERPRINTS = ('<FINGERPRINT>',)` in `scripts/uuway_update_apply.py`
   and add `config/uuway-release.gpg` to the files in `packaging/deb_manifest.py` (next to
   `config/uuway-wine.preferences`, destination `usr/lib/uuway/config/`). The layout test
   fails if the file, the manifest entry and the pinned fingerprint disagree.

4. Publish the fingerprint where a stolen account cannot also change it: in `README.md` and
   `README.en.md`, and anywhere else that is separate from the release page. The first
   install of a release that carries the key is trusted on first use; the fingerprint is how
   anyone can check it.

## Every release

1. Tag the release. CI builds the deb, tests it in a clean container and drafts the
   release with the deb and `SHA256SUMS`.
2. Do the manual acceptance on the drafted deb, as before.
3. Sign the draft, on the machine that holds the key:

   ```sh
   packaging/sign-release.sh vX.Y.Z
   ```

   It downloads the deb and `SHA256SUMS` from the draft and refuses to go on if they do not
   match each other (something changed after CI built them). It then signs a `SHA256SUMS`
   that it builds itself from the deb, verifies the result with the code the clients run
   against the key committed to the repository, and only then uploads `SHA256SUMS.asc`.
4. Publish: `gh release edit vX.Y.Z --draft=false --latest`.

A release that is published but not yet signed is reported by `uuway update` as "not
installable yet"; it is never installed. Sign before publishing.

## Checking a download by hand

```sh
gpg --show-keys config/uuway-release.gpg           # compare the fingerprint with the README
gpgv --homedir "$(mktemp -d)" --keyring ./config/uuway-release.gpg SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

`--homedir` with an empty directory matters: it makes gpgv trust only the keyring you name.

## Replacing the key

The installed package carries the key it trusts, and a release is checked with the key that
is **already installed**, before the package is replaced. A new key therefore has to be
introduced in a release signed by the old one:

1. Release N: the keyring holds old and new key, the code pins both fingerprints, and the
   release is signed with both: `packaging/sign-release.sh vN --key OLD --key NEW`.
   An install that still has only the old key checks the old key's signature and ignores the
   one it has no key for (gpgv reports a missing key, which is not an error as long as one
   signature is valid and from a pinned key). Once N is installed it knows both keys.
2. Release N+1 and later: sign with the new key only. Drop the old key from the keyring and
   the pinned fingerprints once nobody is expected to update from before N.

A machine that skips N goes straight from the old key to a release it cannot verify, and has
to be updated by hand with `sudo apt install ./uuway_*.deb`.

## If the key is lost or stolen

- **Lost** (the private key is gone, the revocation certificate is not needed): releases can
  no longer be signed, so existing installs cannot update. Create a new key and ship it in a
  release that is installed by hand; announce it with the new fingerprint.
- **Stolen**: an attacker with the key still needs to control what GitHub serves, because
  clients fetch only from `github.com` over TLS. Even so, treat it as an emergency. Revoke
  the key (`gpg --import uuway-release-revoke.asc`), create a new one, and ship it in a
  release that users install by hand. Revocation reaches only machines that can still
  update to a release carrying it, so say plainly on the project page which releases are
  affected and ask people to reinstall by hand.

## Why gpgv, and why this way

`gpgv` ships with every Ubuntu (apt itself needs it), so nothing extra is installed. It is run
with an empty home directory and a single keyring, so keys in the user's own GnuPG setup count
for nothing, and the verdict is read from its status lines: a valid signature from a pinned
primary key, a strong hash, and none of `BADSIG`, `ERRSIG`, `EXPKEYSIG`, `REVKEYSIG`,
`EXPSIG` or `NO_PUBKEY`. Its exit code alone would not say whose signature it was.
