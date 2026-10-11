"""uuway update: what is believed, and what is refused, before anything is installed as root."""
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("uuway_update_apply", ROOT / "scripts/uuway_update_apply.py")
apply = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apply)

HAVE_DPKG = bool(shutil.which("dpkg-deb") and shutil.which("dpkg"))


class Workspace(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def make_deb(self, path, version="1.2.1", package="uuway", architecture="amd64"):
        tree = Path(tempfile.mkdtemp(prefix="tree-", dir=self.root))
        (tree / "DEBIAN").mkdir()
        (tree / "DEBIAN/control").write_text(f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
                                             "Maintainer: test <test@example.invalid>\nDescription: test\n")
        subprocess.run(["dpkg-deb", "--root-owner-group", "-b", str(tree), str(path)], check=True, capture_output=True)
        return path

    def release(self, version="1.2.1", **deb_fields):
        """A staged release as the updater downloads it: the deb and SHA256SUMS."""
        stage = self.root / f"stage-{version}"
        stage.mkdir(exist_ok=True)
        deb = self.make_deb(stage / f"uuway_{version}_amd64.deb", version=deb_fields.pop("deb_version", version),
                            **deb_fields)
        (stage / "SHA256SUMS").write_text(f"{hashlib.sha256(deb.read_bytes()).hexdigest()}  {deb.name}\n")
        return stage


@unittest.skipUnless(HAVE_DPKG, "dpkg-deb is needed")
class CheckReleaseTests(Workspace):
    def check(self, stage, tag="v1.2.1", installed="1.2.0"):
        return apply.check_release(stage, tag, installed)

    def test_a_release_whose_deb_matches_its_checksums_is_accepted(self):
        result = self.check(self.release())
        self.assertEqual(result.version, "1.2.1")
        self.assertEqual(result.deb.name, "uuway_1.2.1_amd64.deb")
        self.assertEqual(result.sha256, hashlib.sha256(result.deb.read_bytes()).hexdigest())

    def test_the_checksum_can_be_read_without_the_deb(self):
        stage = self.release()
        digest = apply.check_checksums(stage, "v1.2.1")
        self.assertEqual(digest, hashlib.sha256((stage / "uuway_1.2.1_amd64.deb").read_bytes()).hexdigest())
        (stage / "uuway_1.2.1_amd64.deb").unlink()  # not needed for this
        self.assertEqual(apply.check_checksums(stage, "v1.2.1"), digest)

    def test_that_early_check_refuses_what_the_full_check_refuses(self):
        stage = self.release()
        (stage / "SHA256SUMS").unlink()
        with self.assertRaisesRegex(apply.VerifyError, "SHA256SUMS"):
            apply.check_checksums(stage, "v1.2.1")
        (stage / "SHA256SUMS").write_text("a" * 64 + "  something-else.txt\n")  # does not list the deb
        with self.assertRaisesRegex(apply.VerifyError, "SHA256SUMS"):
            apply.check_checksums(stage, "v1.2.1")
        with self.assertRaisesRegex(apply.VerifyError, "tag"):
            apply.check_checksums(self.release(version="1.2.5"), "v1.2")

    def test_a_changed_deb_is_refused(self):
        stage = self.release()
        with (stage / "uuway_1.2.1_amd64.deb").open("ab") as deb:
            deb.write(b"x")
        with self.assertRaisesRegex(apply.VerifyError, "哈希"):
            self.check(stage)

    def test_a_cut_off_deb_is_refused(self):
        stage = self.release()
        deb = stage / "uuway_1.2.1_amd64.deb"
        deb.write_bytes(deb.read_bytes()[:-5])
        with self.assertRaisesRegex(apply.VerifyError, "哈希"):
            self.check(stage)

    def test_changed_checksums_are_refused(self):
        stage = self.release()
        sums = stage / "SHA256SUMS"
        data = sums.read_bytes()
        sums.write_bytes((b"0" if data[:1] != b"0" else b"1") + data[1:])  # one character of the hash differs
        with self.assertRaisesRegex(apply.VerifyError, "哈希"):
            self.check(stage)

    def test_missing_files_are_refused(self):
        stage = self.release()
        (stage / "uuway_1.2.1_amd64.deb").unlink()
        with self.assertRaisesRegex(apply.VerifyError, "uuway_1.2.1_amd64.deb"):
            self.check(stage)
        stage = self.release(version="1.2.2")
        (stage / "SHA256SUMS").unlink()
        with self.assertRaisesRegex(apply.VerifyError, "SHA256SUMS"):
            self.check(stage, tag="v1.2.2")

    def test_only_plain_release_tags_are_accepted(self):
        stage = self.release()
        for tag in ("v1.2", "1.2.1", "v1.2.1-rc1", "v1.2.1\n", "v1.2.1/../x", "V1.2.1", "v01.2.1x", ""):
            with self.assertRaisesRegex(apply.VerifyError, "tag", msg=repr(tag)):
                self.check(stage, tag=tag)

    def test_an_old_release_cannot_be_replayed_under_a_newer_tag(self):
        stage = self.release(version="1.2.0")
        shutil.copy(stage / "uuway_1.2.0_amd64.deb", stage / "uuway_1.2.1_amd64.deb")
        with self.assertRaisesRegex(apply.VerifyError, "SHA256SUMS"):
            self.check(stage, tag="v1.2.1", installed="1.1.2")

    def test_the_deb_must_say_what_the_tag_says(self):
        for fields, expected in ((dict(deb_version="1.2.2"), "版本"), (dict(package="other"), "软件包"),
                                 (dict(architecture="arm64"), "架构")):
            stage = self.release(**fields)
            with self.assertRaisesRegex(apply.VerifyError, expected, msg=str(fields)):
                self.check(stage)

    def test_only_a_strictly_newer_version_is_accepted(self):
        stage = self.release()
        self.check(stage, installed="1.2.0")
        self.check(stage, installed="1.1.2")
        self.check(stage, installed="0.0.0~git1234567")
        for installed in ("1.2.1", "1.3.0", "2.0.0"):
            with self.assertRaisesRegex(apply.VerifyError, "不比", msg=installed):
                self.check(stage, installed=installed)

    def test_there_is_no_signature_to_check(self):
        # A release is a deb and its SHA256SUMS; nothing of the signing scheme is left to trip over.
        for name in ("verify_signature", "check_signed_checksums", "KEYRING", "TRUSTED_FINGERPRINTS"):
            self.assertFalse(hasattr(apply, name), name)


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


if __name__ == "__main__":
    unittest.main()
