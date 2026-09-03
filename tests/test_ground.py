"""Tests for the grounding layer: CWE/kind/symbol retrieval context and the
validation oracle for LLM-proposed sinks/sources.
Run: python3 -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import atropos  # noqa: E402
from atropos import cli, ground  # noqa: E402


class TestRetrieve(unittest.TestCase):
    def setUp(self):
        self.cat = atropos.load()

    def test_retrieve_by_cwe_groups_by_kind(self):
        r = ground.retrieve(self.cat, cwe="89", language="python")
        self.assertGreater(r["match_count"], 0)
        self.assertIn("sql-injection", r["grounding"])
        g = r["grounding"]["sql-injection"]
        self.assertIn("CWE-89", g["cwe"])
        self.assertTrue(g["sinks"])

    def test_cwe_normalization(self):
        a = ground.retrieve(self.cat, cwe="89")["match_count"]
        b = ground.retrieve(self.cat, cwe="CWE-89")["match_count"]
        self.assertEqual(a, b)

    def test_render_context_is_prompt_ready(self):
        r = ground.retrieve(self.cat, kind="command-injection", language="python")
        text = ground.render_context(r)
        self.assertIn("Grounded taint facts", text)
        self.assertIn("command-injection", text)

    def test_ground_cli_json(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["ground", "--cwe", "79", "-l", "javascript", "--json"])
        self.assertEqual(rc, 0)
        r = json.loads(buf.getvalue())
        self.assertGreater(r["match_count"], 0)


class TestValidateOracle(unittest.TestCase):
    def setUp(self):
        self.cat = atropos.load()

    def test_confirmed(self):
        r = ground.validate(self.cat, "python", "system", access_path="Argument[0]",
                            role="sink", package="os")
        self.assertEqual(r["verdict"], ground.V_CONFIRMED)
        self.assertTrue(r["evidence"])

    def test_partial_on_wrong_access_path(self):
        r = ground.validate(self.cat, "python", "system", access_path="Argument[9]",
                            role="sink", package="os")
        self.assertEqual(r["verdict"], ground.V_PARTIAL)

    def test_unknown_symbol(self):
        r = ground.validate(self.cat, "python", "not_a_real_symbol_xyz",
                            access_path="Argument[0]", role="sink")
        self.assertEqual(r["verdict"], ground.V_UNKNOWN)

    def test_validate_cli_exit_codes(self):
        # confirmed -> 0
        with contextlib.redirect_stdout(io.StringIO()):
            rc_ok = cli.main(["validate", "python", "system", "-a", "Argument[0]",
                              "--role", "sink", "-p", "os"])
        # unknown -> 1
        with contextlib.redirect_stdout(io.StringIO()):
            rc_bad = cli.main(["validate", "python", "nope_not_here", "--role", "sink"])
        self.assertEqual(rc_ok, 0)
        self.assertEqual(rc_bad, 1)


if __name__ == "__main__":
    unittest.main()
