import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tests" / "probes" / "terminal_osc_filter.c"
FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "src")]


class TerminalOscFilterTests(unittest.TestCase):
    """src/terminal_osc_filter.h against an independent whole-buffer implementation, on random
    streams cut at random places (tests/probes/terminal_osc_filter.c)."""

    def test_streamed_filter_matches_the_reference(self):
        with tempfile.TemporaryDirectory(prefix="uurb-osc-filter-") as directory:
            binary = os.path.join(directory, "filter")
            sanitize = ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
            built = subprocess.run(["cc", *FLAGS, *sanitize, "-o", binary, str(PROBE)],
                                   capture_output=True, text=True)
            cases = "1000"
            if built.returncode != 0:
                # No sanitizer runtime on this machine: still run the comparison, with more cases.
                subprocess.run(["cc", *FLAGS, "-O2", "-o", binary, str(PROBE)], check=True)
                cases = "20000"
            result = subprocess.run([binary, cases], capture_output=True, text=True, timeout=300)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ok:", result.stdout)


if __name__ == "__main__":
    unittest.main()
