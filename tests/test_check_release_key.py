"""packaging/check-release-key.py: a tagged release may not go out without the key that `uuway update` trusts."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_release_key", ROOT / "packaging/check-release-key.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

HAVE_GPG = bool(shutil.which("gpg"))
SOURCE = "TRUSTED_FINGERPRINTS = ()\n"
MANIFEST_ENTRY = "('config/uuway-release.gpg', f'{LIB}/config/uuway-release.gpg', 0o644),"


class Tree(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "scripts").mkdir()
        (self.root / "config").mkdir()
        (self.root / "packaging").mkdir()
        self.write_source(SOURCE)
        self.write_manifest("")

    def write_source(self, text):
        (self.root / "scripts/uuway_update_apply.py").write_text(text)

    def write_manifest(self, entry):
        (self.root / "packaging/deb_manifest.py").write_text(f"def files():\n    return [\n        {entry}\n    ]\n")

    def make_key(self):
        home = self.root / "gnupg"
        home.mkdir(mode=0o700, exist_ok=True)
        base = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        subprocess.run([*base, "--quick-generate-key", "k <k@example.invalid>", "ed25519", "sign", "never"],
                       check=True, capture_output=True)
        listing = subprocess.run([*base, "--with-colons", "--list-keys"], check=True, capture_output=True, text=True).stdout
        fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        (self.root / "config/uuway-release.gpg").write_bytes(
            subprocess.run(["gpg", "--homedir", str(home), "--export"], check=True, capture_output=True).stdout)
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True, check=False)
        return fingerprint


class WithoutAKeyTests(Tree):
    def test_the_current_state_of_a_new_checkout_is_not_releasable(self):
        problems = check.problems(self.root)
        self.assertTrue(any("uuway-release.gpg" in problem for problem in problems), problems)
        self.assertTrue(any("TRUSTED_FINGERPRINTS" in problem for problem in problems), problems)

    def test_a_missing_source_file_is_a_problem_not_a_crash(self):
        (self.root / "scripts/uuway_update_apply.py").unlink()
        self.assertTrue(check.problems(self.root))


@unittest.skipUnless(HAVE_GPG, "gpg is needed")
class WithAKeyTests(Tree):
    def set_up_everything(self):
        fingerprint = self.make_key()
        self.write_source(f"TRUSTED_FINGERPRINTS = ('{fingerprint}',)\n")
        self.write_manifest(MANIFEST_ENTRY)
        return fingerprint

    def test_a_complete_setup_has_no_problems(self):
        self.set_up_everything()
        self.assertEqual(check.problems(self.root), [])

    def test_the_package_must_ship_the_keyring(self):
        self.set_up_everything()
        self.write_manifest("")
        self.assertTrue(any("deb_manifest" in problem for problem in check.problems(self.root)))

    def test_the_pinned_fingerprint_must_be_the_keyrings(self):
        self.set_up_everything()
        self.write_source(f"TRUSTED_FINGERPRINTS = ('{'A' * 40}',)\n")
        self.assertTrue(any("different keys" in problem for problem in check.problems(self.root)))

    def test_a_pinned_fingerprint_without_the_keyring_is_a_problem(self):
        self.set_up_everything()
        (self.root / "config/uuway-release.gpg").unlink()
        self.assertTrue(any("uuway-release.gpg" in problem for problem in check.problems(self.root)))

    def test_a_keyring_without_a_pinned_fingerprint_is_a_problem(self):
        self.set_up_everything()
        self.write_source(SOURCE)
        self.assertTrue(any("TRUSTED_FINGERPRINTS" in problem for problem in check.problems(self.root)))

    def test_a_file_that_is_not_a_keyring_is_a_problem(self):
        self.set_up_everything()
        (self.root / "config/uuway-release.gpg").write_bytes(b"not a key")
        self.assertTrue(check.problems(self.root))


class RealRepositoryTests(unittest.TestCase):
    def test_the_script_runs_and_says_what_is_missing_until_the_key_exists(self):
        result = subprocess.run(["/usr/bin/python3", str(ROOT / "packaging/check-release-key.py")],
                                capture_output=True, text=True, cwd=ROOT)
        if check.problems(ROOT):
            self.assertEqual(result.returncode, 1)
            self.assertIn("release key", result.stderr)
        else:
            self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
