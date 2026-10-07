"""uuway update: what is trusted, and what is refused, before anything is installed as root."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("uuway_update_apply", ROOT / "scripts/uuway_update_apply.py")
apply = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apply)

HAVE_GPG = bool(shutil.which("gpg") and shutil.which("gpgv"))
HAVE_DPKG = bool(shutil.which("dpkg-deb") and shutil.which("dpkg"))


def completed(argv, code=0, out=""):
    return subprocess.CompletedProcess(argv, code, stdout=out, stderr="")


class Workspace(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.homes = []
        self.addCleanup(self.stop_agents)

    def stop_agents(self):
        for home in self.homes:
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True, check=False)

    def gpg(self, home, *arguments, **kwargs):
        return subprocess.run(["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback",
                               "--passphrase", "", *arguments], check=True, capture_output=True, **kwargs)

    def make_key(self, name):
        """A throwaway Ed25519 key: (gnupg home, primary fingerprint, binary keyring file)."""
        home = self.root / f"gnupg-{name}"
        home.mkdir(mode=0o700)
        self.homes.append(home)
        self.gpg(home, "--quick-generate-key", f"{name} <{name}@example.invalid>", "ed25519", "sign", "never")
        listing = self.gpg(home, "--with-colons", "--list-keys", text=True).stdout
        fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        keyring = self.root / f"{name}.gpg"
        keyring.write_bytes(self.gpg(home, "--export").stdout)
        return home, fingerprint, keyring

    def sign(self, home, sums):
        signature = Path(str(sums) + ".asc")
        signature.unlink(missing_ok=True)
        self.gpg(home, "--yes", "--armor", "--detach-sign", "-o", str(signature), str(sums))
        return signature

    def make_deb(self, path, version="1.2.1", package="uuway", architecture="amd64"):
        tree = Path(tempfile.mkdtemp(prefix="tree-", dir=self.root))
        (tree / "DEBIAN").mkdir()
        (tree / "DEBIAN/control").write_text(f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
                                             "Maintainer: test <test@example.invalid>\nDescription: test\n")
        subprocess.run(["dpkg-deb", "--root-owner-group", "-b", str(tree), str(path)], check=True, capture_output=True)
        return path

    def release(self, home, version="1.2.1", **deb_fields):
        """A staged release as the updater downloads it: deb, SHA256SUMS, SHA256SUMS.asc."""
        stage = self.root / f"stage-{version}"
        stage.mkdir(exist_ok=True)
        deb = self.make_deb(stage / f"uuway_{version}_amd64.deb", version=deb_fields.pop("deb_version", version),
                            **deb_fields)
        sums = stage / "SHA256SUMS"
        sums.write_text(f"{hashlib.sha256(deb.read_bytes()).hexdigest()}  {deb.name}\n")
        self.sign(home, sums)
        return stage


@unittest.skipUnless(HAVE_GPG and HAVE_DPKG, "gpg, gpgv and dpkg-deb are needed")
class CheckReleaseTests(Workspace):
    def setUp(self):
        super().setUp()
        self.home, self.fingerprint, self.keyring = self.make_key("release")

    def check(self, stage, tag="v1.2.1", installed="1.2.0", keyring=None, fingerprints=None):
        return apply.check_release(stage, tag, installed, keyring or self.keyring,
                                   fingerprints if fingerprints is not None else (self.fingerprint,))

    def test_a_signed_release_is_accepted(self):
        result = self.check(self.release(self.home))
        self.assertEqual(result.version, "1.2.1")
        self.assertEqual(result.deb.name, "uuway_1.2.1_amd64.deb")
        self.assertEqual(result.sha256, hashlib.sha256(result.deb.read_bytes()).hexdigest())

    def test_a_changed_deb_is_refused(self):
        stage = self.release(self.home)
        with (stage / "uuway_1.2.1_amd64.deb").open("ab") as deb:
            deb.write(b"x")
        with self.assertRaisesRegex(apply.VerifyError, "哈希"):
            self.check(stage)

    def test_changed_checksums_break_the_signature(self):
        stage = self.release(self.home)
        sums = stage / "SHA256SUMS"
        data = sums.read_bytes()
        sums.write_bytes(bytes([data[0] ^ 1]) + data[1:])  # one character of the hash differs
        with self.assertRaisesRegex(apply.VerifyError, "签名"):
            self.check(stage)

    def test_a_missing_signature_is_refused(self):
        stage = self.release(self.home)
        (stage / "SHA256SUMS.asc").unlink()
        with self.assertRaisesRegex(apply.VerifyError, "签名"):
            self.check(stage)

    def test_a_release_signed_by_another_key_is_refused(self):
        other_home, other_fingerprint, other_keyring = self.make_key("intruder")
        stage = self.release(other_home)
        with self.assertRaises(apply.VerifyError):
            self.check(stage)  # the intruder's key is not in the shipped keyring
        with self.assertRaisesRegex(apply.VerifyError, "指纹"):
            self.check(stage, keyring=other_keyring)  # in the keyring, but not a pinned fingerprint

    def test_keys_in_the_default_gnupg_home_are_not_honoured(self):
        other_home, _, _ = self.make_key("intruder")
        stage = self.release(other_home)
        default_home = self.root / "default-gnupg"
        default_home.mkdir(mode=0o700)
        self.homes.append(default_home)
        exported = self.gpg(other_home, "--export").stdout
        subprocess.run(["gpg", "--homedir", str(default_home), "--batch", "--no-default-keyring",
                        "--keyring", str(default_home / "trustedkeys.kbx"), "--import"],
                       input=exported, check=True, capture_output=True)
        previous = os.environ.get("GNUPGHOME")
        os.environ["GNUPGHOME"] = str(default_home)
        try:
            with self.assertRaises(apply.VerifyError):
                self.check(stage)
        finally:
            if previous is None:
                os.environ.pop("GNUPGHOME")
            else:
                os.environ["GNUPGHOME"] = previous

    def test_without_a_pinned_fingerprint_nothing_is_trusted(self):
        with self.assertRaisesRegex(apply.VerifyError, "指纹"):
            self.check(self.release(self.home), fingerprints=())

    def test_a_missing_keyring_is_refused(self):
        with self.assertRaisesRegex(apply.VerifyError, "公钥"):
            self.check(self.release(self.home), keyring=self.root / "no-such.gpg")

    def test_only_plain_release_tags_are_accepted(self):
        stage = self.release(self.home)
        for tag in ("v1.2", "1.2.1", "v1.2.1-rc1", "v1.2.1\n", "v1.2.1/../x", "V1.2.1", "v01.2.1x", ""):
            with self.assertRaisesRegex(apply.VerifyError, "tag", msg=repr(tag)):
                self.check(stage, tag=tag)

    def test_an_old_signed_release_cannot_be_replayed_under_a_newer_tag(self):
        stage = self.release(self.home, version="1.2.0")
        shutil.copy(stage / "uuway_1.2.0_amd64.deb", stage / "uuway_1.2.1_amd64.deb")
        with self.assertRaisesRegex(apply.VerifyError, "SHA256SUMS"):
            self.check(stage, tag="v1.2.1", installed="1.1.2")

    def test_the_deb_must_say_what_the_tag_says(self):
        for fields, expected in ((dict(deb_version="1.2.2"), "版本"), (dict(package="other"), "软件包"),
                                 (dict(architecture="arm64"), "架构")):
            stage = self.release(self.home, **fields)
            with self.assertRaisesRegex(apply.VerifyError, expected, msg=str(fields)):
                self.check(stage)

    def test_only_a_strictly_newer_version_is_accepted(self):
        stage = self.release(self.home)
        self.check(stage, installed="1.2.0")
        self.check(stage, installed="1.1.2")
        self.check(stage, installed="0.0.0~git1234567")
        for installed in ("1.2.1", "1.3.0", "2.0.0"):
            with self.assertRaisesRegex(apply.VerifyError, "不比", msg=installed):
                self.check(stage, installed=installed)


class ChecksumFileTests(unittest.TestCase):
    HASH = "a" * 64
    OTHER = "b" * 64

    def test_the_hash_for_the_named_file_is_returned(self):
        text = f"{self.HASH}  uuway_1.2.1_amd64.deb\n"
        self.assertEqual(apply.parse_sums(text, "uuway_1.2.1_amd64.deb"), self.HASH)

    def test_other_well_formed_entries_are_ignored(self):
        text = f"{self.OTHER}  something-else.txt\n{self.HASH}  uuway_1.2.1_amd64.deb\n"
        self.assertEqual(apply.parse_sums(text, "uuway_1.2.1_amd64.deb"), self.HASH)

    def test_malformed_duplicate_or_missing_entries_are_refused(self):
        name = "uuway_1.2.1_amd64.deb"
        bad = (
            f"{self.HASH} {name}\n",  # one space
            f"{self.HASH.upper()}  {name}\n",
            f"{self.HASH[:-1]}  {name}\n",
            f"{self.HASH}  {name}\nextra line\n",
            f"{self.HASH}  {name}\n{self.OTHER}  {name}\n",  # two answers for the same file
            f"{self.HASH}  ../{name}\n",
            f"{self.OTHER}  something-else.txt\n",  # not there
            "",
        )
        for text in bad:
            with self.assertRaises(apply.VerifyError, msg=repr(text)):
                apply.parse_sums(text, name)


class SignatureStatusTests(unittest.TestCase):
    """What gpgv says is parsed from its status lines; its exit code alone is not enough."""

    FPR = "A" * 40
    SUBKEY = "B" * 40

    def valid(self, primary=None, algorithm="10", subkey=None):
        return (f"[GNUPG:] VALIDSIG {subkey or self.SUBKEY} 2026-10-07 1791360000 0 4 0 22 {algorithm} 00 "
                f"{primary or self.FPR}\n")

    def verify(self, output, code=0, fingerprints=None):
        keyring = Path(tempfile.mkdtemp()) / "k.gpg"
        keyring.write_bytes(b"x")
        self.addCleanup(shutil.rmtree, keyring.parent)
        return apply.verify_signature(Path("sums"), Path("sums.asc"), keyring,
                                      fingerprints or (self.FPR,),
                                      run=lambda argv, **kwargs: completed(argv, code, output))

    def test_a_valid_signature_from_a_pinned_primary_key_is_accepted(self):
        self.verify(self.valid())
        self.verify(self.valid(algorithm="8"))
        self.verify(self.valid(primary=self.FPR.lower()))

    def test_the_primary_key_decides_not_the_signing_subkey(self):
        self.verify(self.valid(subkey="C" * 40))
        with self.assertRaisesRegex(apply.VerifyError, "指纹"):
            self.verify(self.valid(primary="D" * 40))

    def test_weak_hashes_are_refused(self):
        for algorithm in ("1", "2", "3"):
            with self.assertRaisesRegex(apply.VerifyError, "哈希算法", msg=algorithm):
                self.verify(self.valid(algorithm=algorithm))

    def test_every_bad_status_is_refused_even_next_to_a_valid_signature(self):
        for status in ("BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG", "EXPSIG", "NO_PUBKEY"):
            with self.assertRaises(apply.VerifyError, msg=status):
                self.verify(self.valid() + f"[GNUPG:] {status} {self.FPR} x\n")

    def test_a_failing_exit_code_or_no_valid_signature_is_refused(self):
        with self.assertRaises(apply.VerifyError):
            self.verify(self.valid(), code=1)
        with self.assertRaises(apply.VerifyError):
            self.verify("[GNUPG:] NEWSIG\n")
        with self.assertRaises(apply.VerifyError):
            self.verify("")

    def test_two_signatures_are_fine_during_a_key_rotation(self):
        second = "E" * 40
        self.verify(self.valid() + self.valid(primary=second), fingerprints=(self.FPR, second))
        with self.assertRaises(apply.VerifyError):  # both have to be pinned
            self.verify(self.valid() + self.valid(primary=second))

    def test_a_missing_gpgv_is_reported_not_crashed_on(self):
        def missing(argv, **kwargs):
            raise FileNotFoundError("gpgv")
        keyring = Path(tempfile.mkdtemp()) / "k.gpg"
        keyring.write_bytes(b"x")
        self.addCleanup(shutil.rmtree, keyring.parent)
        with self.assertRaisesRegex(apply.VerifyError, "gpgv"):
            apply.verify_signature(Path("s"), Path("s.asc"), keyring, (self.FPR,), run=missing)


if __name__ == "__main__":
    unittest.main()
