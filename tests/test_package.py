"""Tests for the installable ``atropos`` package: the loader, the Catalog query API,
and the command-line surface. Run: python3 -m unittest discover -s tests

These exercise the package against the live catalog in this checkout (discovery walks
up to the repo root), so they also guard that the data stays loadable and queryable.
"""
from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import atropos  # noqa: E402
from atropos import cli  # noqa: E402
from atropos.catalog import Entry  # noqa: E402


class TestLoad(unittest.TestCase):
    def setUp(self):
        self.cat = atropos.load()

    def test_loads_all_languages(self):
        self.assertGreater(len(self.cat), 500)
        self.assertEqual(
            self.cat.languages(), ["c", "javascript", "python", "typescript"]
        )

    def test_version_is_semver(self):
        parts = atropos.__version__.split(".")
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(p.isdigit() for p in parts))

    def test_roles_partition_entries(self):
        total = (
            len(self.cat.sinks)
            + len(self.cat.sources)
            + len(self.cat.sanitizers)
            + len(self.cat.summaries)
        )
        self.assertEqual(total, len(self.cat))

    def test_every_entry_has_required_fields(self):
        for e in self.cat:
            self.assertIsInstance(e, Entry)
            self.assertTrue(e.id and e.language and e.method)
            self.assertTrue(e.access_path and e.role and e.kind)

    def test_ids_are_unique(self):
        ids = [e.id for e in self.cat]
        self.assertEqual(len(ids), len(set(ids)))


class TestQueries(unittest.TestCase):
    def setUp(self):
        self.cat = atropos.load()

    def test_find_filters_are_conjunctive(self):
        got = self.cat.find(language="python", role="sink", kind="command-injection")
        self.assertTrue(got)
        for e in got:
            self.assertEqual(e.language, "python")
            self.assertEqual(e.role, "sink")
            self.assertEqual(e.kind, "command-injection")

    def test_find_by_cwe_accepts_bare_number(self):
        a = self.cat.find(cwe="CWE-89")
        b = self.cat.find(cwe="89")
        self.assertEqual({e.id for e in a}, {e.id for e in b})

    def test_resolve_module_function(self):
        got = self.cat.resolve("javascript", "exec", package="child_process")
        self.assertTrue(got)
        self.assertTrue(any(e.kind == "command-injection" for e in got))

    def test_resolve_bare_method_returns_superset(self):
        narrow = self.cat.resolve("python", "execute", type="Cursor")
        broad = self.cat.resolve("python", "execute")
        self.assertTrue(set(e.id for e in narrow).issubset(e.id for e in broad))

    def test_search_matches_notes_and_symbol(self):
        self.assertTrue(self.cat.search("redirect"))

    def test_get_roundtrips(self):
        first = self.cat.entries[0]
        self.assertEqual(self.cat.get(first.id).id, first.id)
        self.assertIsNone(self.cat.get("no.such.id.exists"))

    def test_stats_shape(self):
        s = self.cat.stats()
        self.assertEqual(s["total"], len(self.cat))
        self.assertIn("by_kind", s)
        self.assertIn("by_language_role", s)

    def test_entry_to_dict_roundtrips_schema_fields(self):
        e = self.cat.entries[0]
        d = e.to_dict()
        self.assertNotIn("source_file", d)
        self.assertEqual(d["id"], e.id)


class TestDetection(unittest.TestCase):
    def test_detection_layer_self_checks(self):
        d = atropos.load_detection()
        self.assertIn("reachability", d["evaluators"])
        for kind, ev in d["kind_evaluator"].items():
            names = [ev] if isinstance(ev, str) else ev
            for name in names:
                self.assertIn(name, d["evaluators"])


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(argv)
        return rc, out.getvalue()

    def test_stats_json(self):
        rc, out = self._run(["stats", "--json"])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertIn("total", payload)

    def test_sinks_filtered(self):
        rc, out = self._run(["sinks", "-l", "c", "--json", "--limit", "5"])
        self.assertEqual(rc, 0)
        rows = json.loads(out)
        self.assertLessEqual(len(rows), 5)
        self.assertTrue(all(r["language"] == "c" and r["role"] == "sink" for r in rows))

    def test_resolve(self):
        rc, out = self._run(
            ["resolve", "javascript", "exec", "-p", "child_process", "--json"]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out))

    def test_export_csv_has_header(self):
        rc, out = self._run(["export", "-l", "python", "--role", "source", "-f", "csv"])
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("id,language,package"))

    def test_show_unknown_id_errors(self):
        rc, _ = self._run(["show", "definitely.not.here"])
        self.assertEqual(rc, 1)

    def test_no_command_prints_help(self):
        rc, out = self._run([])
        self.assertEqual(rc, 0)
        self.assertIn("usage", out.lower())


if __name__ == "__main__":
    unittest.main()
