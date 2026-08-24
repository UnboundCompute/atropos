import subprocess
import sys
import json
import tempfile
import zipfile
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
        for name in ("validate.py", "stats.py", "bind.py", "new_model.py", "new_fixture.py", "validate_pack.py", "build_pack.py", "install_pack.py"):
            with self.subTest(name=name):
                result = self.run_tool(name, "--help")
                self.assertEqual(0, result.returncode)
                self.assertIn("usage:", result.stdout)

    def test_unknown_arguments_are_usage_errors(self):
        for name in ("validate.py", "stats.py", "bind.py", "new_model.py", "new_fixture.py", "validate_pack.py", "build_pack.py", "install_pack.py"):
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

    def test_new_fixture_generates_bindable_index_and_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model_file = root / "models" / "python" / "sinks.json"
            output = root / "fixtures"
            model_file.parent.mkdir(parents=True)
            output.mkdir()
            model_file.write_text(json.dumps({"role_group": "sink", "entries": [{
                "id": "python.demo.exec.arg0", "language": "python", "package": "demo",
                "type": None, "method": "exec", "access_path": "Argument[0]",
                "role": "sink", "kind": "command-injection", "cwe": ["CWE-78"],
                "confidence": "high"
            }]}))
            result = self.run_tool(
                "new_fixture.py", "python.demo.exec.arg0", "--root", str(root),
                "--output-dir", str(output),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            index = json.loads(next(output.glob("*.index.json")).read_text())
            self.assertEqual("atropos-symbol-index", index["format"])
            self.assertEqual("exec", index["callsites"][0]["callee"]["name"])
            self.assertEqual(["v_arg0"], index["callsites"][0]["arg_value_ids"])

    def test_build_pack_is_deterministic_for_a_minimal_pack(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "pack"
            root.mkdir()
            (root / "VERSION").write_text("0.0.1\n")
            (root / "LICENSE").write_text("demo license\n")
            (root / "models.json").write_text(json.dumps({"entries": [{"id": "x"}]}))
            (root / "pack.json").write_text(json.dumps({
                "format": "atropos-model-pack", "schema_version": 1,
                "id": "demo.pack", "name": "Demo", "version": "0.0.1",
                "license": "CC0", "license_file": "LICENSE", "languages": ["python"], "model_globs": ["models.json"],
                "verified_entries": 1, "provenance": {
                    "source_of_truth": "test", "binding_required": True,
                    "candidate_rows_are_consumed": False,
                },
            }))
            first, second = Path(directory) / "one.zip", Path(directory) / "two.zip"
            for output in (first, second):
                result = self.run_tool("build_pack.py", "--root", str(root), "--output", str(output))
                self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            checksums = Path(directory) / "one.sha256"
            provenance = Path(directory) / "one.provenance.json"
            result = self.run_tool(
                "build_pack.py", "--root", str(root), "--output", str(first),
                "--checksums", str(checksums), "--provenance", str(provenance),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("one.zip", checksums.read_text())
            self.assertEqual("demo.pack", json.loads(provenance.read_text())["pack"]["id"])
            with zipfile.ZipFile(first) as archive:
                self.assertIn("LICENSE", archive.namelist())

    def test_install_pack_validates_checksum_and_returns_consumable_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "pack"
            root.mkdir()
            (root / "LICENSE").write_text("demo license\n")
            (root / "models.json").write_text(json.dumps({"entries": [{"id": "x"}]}))
            (root / "pack.json").write_text(json.dumps({
                "format": "atropos-model-pack", "schema_version": 1,
                "id": "demo.pack", "name": "Demo", "version": "0.0.1",
                "license": "CC0", "license_file": "LICENSE", "languages": ["python"], "model_globs": ["models.json"],
                "verified_entries": 1, "provenance": {
                    "source_of_truth": "test", "binding_required": True,
                    "candidate_rows_are_consumed": False,
                },
            }))
            archive = Path(directory) / "demo.zip"
            self.assertEqual(0, self.run_tool("build_pack.py", "--root", str(root), "--output", str(archive)).returncode)
            digest = __import__("hashlib").sha256(archive.read_bytes()).hexdigest()
            store = Path(directory) / "store"
            result = self.run_tool("install_pack.py", str(archive), "--destination", str(store), "--sha256", digest)
            self.assertEqual(0, result.returncode, result.stderr)
            installed = store / "demo.pack" / "0.0.1"
            self.assertTrue((installed / "pack.json").is_file())
            self.assertEqual(str(installed.resolve()), result.stdout.splitlines()[0].removeprefix("installed "))

    def test_install_pack_rejects_bad_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "not-a-pack.zip"
            archive.write_bytes(b"archive")
            result = self.run_tool("install_pack.py", str(archive), "--sha256", "0" * 64)
            self.assertEqual(1, result.returncode)
            self.assertIn("sha256 mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
