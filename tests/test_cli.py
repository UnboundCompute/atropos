import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ToolCliTests(unittest.TestCase):
    def run_tool(self, name, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools" / name), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_help_is_fast_and_explicit(self):
        for name in ("validate.py", "stats.py", "bind.py"):
            with self.subTest(name=name):
                result = self.run_tool(name, "--help")
                self.assertEqual(0, result.returncode)
                self.assertIn("usage:", result.stdout)

    def test_unknown_arguments_are_usage_errors(self):
        for name in ("validate.py", "stats.py", "bind.py"):
            with self.subTest(name=name):
                result = self.run_tool(name, "--unknown")
                self.assertEqual(2, result.returncode)
                self.assertIn("usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
