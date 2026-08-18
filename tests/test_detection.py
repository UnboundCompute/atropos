"""Detection-layer invariants. Run: python3 -m unittest discover -s tests

The detection layer is pure data (detection/*.json). These tests pin the two
cross-cutting facts the JSON cannot express on its own: every sink kind the
catalog actually stamps has a recipe, and every recipe/bridge target resolves.
"""
import json
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import detection  # noqa: E402


def _catalog_sink_kinds():
    kinds = set()
    for f in (ROOT / "models").rglob("*.json"):
        for e in json.loads(f.read_text()).get("entries", []):
            if e["role"] == "sink":
                kinds.add(e["kind"])
    return kinds


class TestDetection(unittest.TestCase):
    def setUp(self):
        self.d = detection.load_detection()

    def test_loads_and_self_checks(self):
        # load_detection raises on a dangling evaluator/kind; reaching here means clean.
        self.assertIn("reachability", self.d["evaluators"])
        self.assertTrue(self.d["kind_evaluator"])

    def test_recipe_targets_are_declared_evaluators(self):
        for kind, ev in self.d["kind_evaluator"].items():
            self.assertIn(ev, self.d["evaluators"], f"{kind} -> unknown evaluator {ev}")

    def test_every_catalog_sink_kind_has_a_recipe(self):
        # A sink kind in the catalog with no evaluator is a silent coverage hole.
        missing = _catalog_sink_kinds() - set(self.d["kind_evaluator"])
        self.assertEqual(missing, set(), f"catalog sink kinds without a recipe: {missing}")

    def test_no_recipe_for_a_kind_the_catalog_never_stamps(self):
        # Keeps the table honest: no evaluator rows for kinds nothing produces.
        extra = set(self.d["kind_evaluator"]) - _catalog_sink_kinds()
        self.assertEqual(extra, set(), f"recipe rows with no catalog sink kind: {extra}")

    def test_bridge_targets_have_recipes(self):
        for vocab, bridge in self.d["role_bridges"].items():
            for role, kind in bridge.items():
                self.assertIn(kind, self.d["kind_evaluator"],
                              f"bridge[{vocab}] {role} -> {kind} has no recipe")

    def test_generic_security_roles_bridge_present(self):
        self.assertIn("generic-security-roles", self.d["role_bridges"])


if __name__ == "__main__":
    unittest.main()
