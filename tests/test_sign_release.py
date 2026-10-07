"""packaging/sign-release.sh: signs what it hashed itself, and uploads nothing that would not verify."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HAVE_TOOLS = all(shutil.which(tool) for tool in ("gpg", "gpgv", "dpkg-deb", "dpkg", "python3", "bash"))

FAKE_GH = r'''#!/usr/bin/env bash
# A stand-in for `gh`: the release is the directory $FAKE_RELEASE; uploads land in $FAKE_UPLOADS.
set -eu
case "$1 $2" in
    "release view") cat "$FAKE_RELEASE/.draft" ;;
    "release download")
        dest="" ; patterns=()
        shift 3
        while (($#)); do
            case "$1" in --dir) dest="$2"; shift 2 ;; --pattern) patterns+=("$2"); shift 2 ;; *) shift ;; esac
        done
        for name in "${patterns[@]}"; do cp "$FAKE_RELEASE/$name" "$dest/$name"; done ;;
    "release upload") cp "$4" "$FAKE_UPLOADS/" ; echo "uploaded $(basename "$4")" >> "$FAKE_UPLOADS/.log" ;;
    *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
'''


@unittest.skipUnless(HAVE_TOOLS, "gpg, gpgv, dpkg-deb, dpkg, python3 and bash are needed")
class SignReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.homes = []
        self.addCleanup(self.stop_agents)
        self.release = self.root / "release"
        self.uploads = self.root / "uploads"
        self.release.mkdir()
        self.uploads.mkdir()
        (self.release / ".draft").write_text("true")
        # A pretend checkout: the real script and the real verification code, with a test key pinned.
        self.repo = self.root / "repo"
        for relative in ("packaging/sign-release.sh", "scripts/uuway_update_apply.py"):
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, self.repo / relative)
        self.home, self.fingerprint = self.make_key("release")
        self.install_key(self.home, self.fingerprint)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
        self.bin = bin_dir
        self.deb = self.make_release_files("1.2.0")

    def stop_agents(self):
        for home in self.homes:
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True, check=False)

    def make_key(self, name):
        home = self.root / f"gnupg-{name}"
        home.mkdir(mode=0o700)
        self.homes.append(home)
        base = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        subprocess.run([*base, "--quick-generate-key", f"{name} <{name}@example.invalid>", "ed25519", "sign", "never"],
                       check=True, capture_output=True)
        listing = subprocess.run([*base, "--with-colons", "--list-keys"], check=True, capture_output=True, text=True).stdout
        return home, next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))

    def install_key(self, home, fingerprint):
        """Put `home`'s key into the pretend checkout as the release key."""
        keyring = subprocess.run(["gpg", "--homedir", str(home), "--export"], check=True, capture_output=True).stdout
        (self.repo / "config").mkdir(exist_ok=True)
        (self.repo / "config/uuway-release.gpg").write_bytes(keyring)
        script = self.repo / "scripts/uuway_update_apply.py"
        script.write_text(script.read_text().replace("TRUSTED_FINGERPRINTS = ()", f"TRUSTED_FINGERPRINTS = ('{fingerprint}',)"))

    def make_release_files(self, version):
        tree = self.root / "tree"
        (tree / "DEBIAN").mkdir(parents=True, exist_ok=True)
        (tree / "DEBIAN/control").write_text(f"Package: uuway\nVersion: {version}\nArchitecture: amd64\n"
                                             "Maintainer: t <t@example.invalid>\nDescription: test\n")
        deb = self.release / f"uuway_{version}_amd64.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "-b", str(tree), str(deb)], check=True, capture_output=True)
        (self.release / "SHA256SUMS").write_text(f"{hashlib.sha256(deb.read_bytes()).hexdigest()}  {deb.name}\n")
        return deb

    def sign(self, *arguments, home=None):
        environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", GNUPGHOME=str(home or self.home),
                           FAKE_RELEASE=str(self.release), FAKE_UPLOADS=str(self.uploads))
        return subprocess.run(["bash", str(self.repo / "packaging/sign-release.sh"), *arguments],
                              capture_output=True, text=True, env=environment, cwd=self.root)

    def uploaded(self):
        return sorted(path.name for path in self.uploads.iterdir() if not path.name.startswith("."))

    def test_a_draft_is_signed_and_the_signature_is_uploaded(self):
        result = self.sign("v1.2.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.uploaded(), ["SHA256SUMS.asc"])
        self.assertIn("Verified as a client would", result.stdout)
        self.assertIn("gh release edit v1.2.0 --draft=false --latest", result.stdout)
        # what was uploaded verifies, with the same code the clients run
        spec = importlib.util.spec_from_file_location("apply", self.repo / "scripts/uuway_update_apply.py")
        apply = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(apply)
        stage = self.root / "stage"
        stage.mkdir()
        shutil.copy(self.deb, stage)
        shutil.copy(self.release / "SHA256SUMS", stage)
        shutil.copy(self.uploads / "SHA256SUMS.asc", stage)
        release = apply.check_release(stage, "v1.2.0", "1.1.2", self.repo / "config/uuway-release.gpg",
                                      apply.TRUSTED_FINGERPRINTS)
        self.assertEqual(release.version, "1.2.0")

    def test_a_deb_that_does_not_match_its_checksums_is_not_signed(self):
        with (self.release / self.deb.name).open("ab") as deb:
            deb.write(b"swapped after CI built it")
        result = self.sign("v1.2.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Do not sign", result.stderr)
        self.assertEqual(self.uploaded(), [])

    def test_the_signed_file_is_built_from_the_deb_not_taken_from_the_download(self):
        (self.release / "SHA256SUMS").write_text(
            f"{hashlib.sha256(self.deb.read_bytes()).hexdigest()}  {self.deb.name}\n{'0' * 64}  something-else\n")
        result = self.sign("v1.2.0")
        self.assertEqual(result.returncode, 0, result.stderr)  # the extra line is simply not what gets signed

    def test_a_signature_by_the_wrong_key_is_not_uploaded(self):
        other_home, _ = self.make_key("intruder")
        result = self.sign("v1.2.0", home=other_home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not verify the way a client would", result.stderr)
        self.assertEqual(self.uploaded(), [])

    def test_the_key_flag_decides_which_key_signs(self):
        base = ["gpg", "--homedir", str(self.home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        subprocess.run([*base, "--quick-generate-key", "second <second@example.invalid>", "ed25519", "sign", "never"],
                       check=True, capture_output=True)
        listing = subprocess.run([*base, "--with-colons", "--list-keys"], check=True, capture_output=True,
                                 text=True).stdout
        fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
        second = next(fingerprint for fingerprint in fingerprints if fingerprint != self.fingerprint)
        wrong = self.sign("v1.2.0", "--key", second)
        self.assertNotEqual(wrong.returncode, 0)  # signed, but not by the pinned key
        self.assertEqual(self.uploaded(), [])
        right = self.sign("v1.2.0", "--key", self.fingerprint)
        self.assertEqual(right.returncode, 0, right.stderr)
        self.assertEqual(self.uploaded(), ["SHA256SUMS.asc"])

    def test_a_published_release_needs_an_explicit_flag(self):
        (self.release / ".draft").write_text("false")
        result = self.sign("v1.2.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already published", result.stderr)
        self.assertEqual(self.uploaded(), [])
        self.assertEqual(self.sign("v1.2.0", "--allow-published").returncode, 0)
        self.assertEqual(self.uploaded(), ["SHA256SUMS.asc"])

    def test_without_the_committed_keyring_it_refuses_to_start(self):
        (self.repo / "config/uuway-release.gpg").unlink()
        result = self.sign("v1.2.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("uuway-release.gpg", result.stderr)

    def test_only_a_plain_release_tag_is_accepted(self):
        for argument in ("v1.2", "1.2.0", "v1.2.0-rc1", "v01.2.0"):
            result = self.sign(argument)
            self.assertNotEqual(result.returncode, 0, argument)
        self.assertEqual(self.sign().returncode, 2)
        self.assertEqual(self.uploaded(), [])


if __name__ == "__main__":
    unittest.main()
