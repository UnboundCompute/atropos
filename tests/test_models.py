"""Model-set invariants. Run: python3 -m unittest discover -s tests"""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT / "tools"))
import validate  # noqa: E402


class TestModels(unittest.TestCase):
    def setUp(self):
        self.files = sorted((ROOT / "models").rglob("*.json"))
        self.entries = []
        for f in self.files:
            doc = json.loads(f.read_text())
            for e in doc["entries"]:
                self.entries.append((f, e))

    def test_validator_passes(self):
        self.assertEqual(validate.main(), 0, "validate.py reported problems")

    def test_have_models(self):
        self.assertGreater(len(self.entries), 0)

    def test_ids_unique(self):
        ids = [e["id"] for _, e in self.entries]
        self.assertEqual(len(ids), len(set(ids)), "duplicate ids present")

    def test_sink_arg_has_index_or_return(self):
        # A sink must attach to a concrete position the engine can bind.
        for f, e in self.entries:
            if e["role"] == "sink":
                self.assertRegex(
                    e["access_path"], r"^(Argument\[|ReturnValue|Receiver)",
                    f"{e['id']} sink has non-bindable access_path",
                )

    def test_memcpy_size_sink_present(self):
        # The regression that motivated the repo: memcpy's size arg must be a sink.
        ids = {e["id"] for _, e in self.entries}
        self.assertIn("c.mem.memcpy.n", ids)


if __name__ == "__main__":
    unittest.main()
