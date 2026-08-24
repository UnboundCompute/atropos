import subprocess
import sys
import json
import tempfile
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
        for name in ("validate.py", "stats.py", "bind.py", "new_model.py"):
            with self.subTest(name=name):
                result = self.run_tool(name, "--help")
                self.assertEqual(0, result.returncode)
                self.assertIn("usage:", result.stdout)

    def test_unknown_arguments_are_usage_errors(self):
        for name in ("validate.py", "stats.py", "bind.py", "new_model.py"):
            with self.subTest(name=name):
                result = self.run_tool(name, "--unknown")
                self.assertEqual(2, result.returncode)
                self.assertIn("usage:", result.stderr)

    def test_new_model_scaffolds_a_role_grouped_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "models" / "python" / "sinks.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({"role_group": "sink", "entries": []}))
            result = self.run_tool(
                "new_model.py", "python.demo.exec.arg0", "--root", str(root),
                "--language", "python", "--role", "sink", "--method", "exec",
                "--access-path", "Argument[0]", "--kind", "command-injection",
                "--cwe", "CWE-78", "--package", "demo",
            )
            self.assertEqual(0, result.returncode, result.stderr)
            document = json.loads(target.read_text())
            self.assertEqual("sink", document["role_group"])
            self.assertEqual("python.demo.exec.arg0", document["entries"][0]["id"])

    def test_new_model_rejects_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "models" / "python" / "sinks.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({"role_group": "sink", "entries": [{"id": "python.demo.exec.arg0"}]}))
            result = self.run_tool(
                "new_model.py", "python.demo.exec.arg0", "--root", str(root),
                "--language", "python", "--role", "sink", "--method", "exec",
                "--access-path", "Argument[0]", "--kind", "command-injection", "--cwe", "CWE-78",
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("already exists", result.stderr)


if __name__ == "__main__":
    unittest.main()
