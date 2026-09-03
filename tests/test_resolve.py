"""Tests for the resolver/enumerator: the language scanners, the match-confidence
spectrum, and the ``atropos audit`` command. Run: python3 -m unittest discover -s tests

These build tiny in-memory targets and audit them against the live catalog in this
checkout, so they verify both the scanning (import resolution, string/comment masking,
argument recovery) and the join (exact / heuristic / name-only classification).
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import atropos  # noqa: E402
from atropos import cli  # noqa: E402
from atropos.resolve import python_scanner, generic_scanner  # noqa: E402
from atropos.resolve.engine import Auditor  # noqa: E402
from atropos.resolve.model import (  # noqa: E402
    MATCH_EXACT,
    MATCH_HEURISTIC,
    MATCH_NAME_ONLY,
)


class TestPythonScanner(unittest.TestCase):
    def sites(self, src):
        return python_scanner.scan("t.py", src)

    def test_module_alias_resolution(self):
        (s,) = [s for s in self.sites("import os as o\no.system(x)") if s.callee == "system"]
        self.assertEqual(s.module, "os")
        self.assertFalse(s.is_method)
        self.assertEqual(s.args, ("x",))

    def test_from_import_binds_module(self):
        (s,) = [s for s in self.sites("from os import system\nsystem(x)")
                if s.callee == "system"]
        self.assertEqual(s.module, "os")
        self.assertFalse(s.is_method)

    def test_from_import_alias(self):
        (s,) = [s for s in self.sites("from subprocess import call as c\nc([x])")
                if s.callee == "call"]
        self.assertEqual(s.module, "subprocess")

    def test_unresolved_method(self):
        (s,) = [s for s in self.sites("cur.execute(q)") if s.callee == "execute"]
        self.assertIsNone(s.module)
        self.assertTrue(s.is_method)
        self.assertEqual(s.receiver, "cur")

    def test_syntax_error_raises(self):
        with self.assertRaises(SyntaxError):
            self.sites("def (:\n")


class TestGenericScanner(unittest.TestCase):
    def test_c_flat_call(self):
        (s,) = generic_scanner.scan("t.c", "memcpy(a, b, n);", "c")
        self.assertEqual(s.callee, "memcpy")
        self.assertIsNone(s.receiver)
        self.assertEqual(s.args, ("a", "b", "n"))

    def test_string_is_masked(self):
        # A call spelled inside a string literal must not be found.
        sites = generic_scanner.scan("t.c", 'puts("memcpy(evil)");', "c")
        self.assertEqual([s.callee for s in sites], ["puts"])

    def test_comment_is_masked(self):
        sites = generic_scanner.scan("t.c", "x = 1; // memcpy(a,b,c)\nputs(y);", "c")
        self.assertEqual([s.callee for s in sites], ["puts"])

    def test_js_require_destructure(self):
        src = 'const { exec } = require("child_process");\nexec(cmd);'
        s = [s for s in generic_scanner.scan("t.js", src, "javascript")
             if s.callee == "exec"][0]
        self.assertEqual(s.module, "child_process")
        self.assertFalse(s.is_method)

    def test_js_module_alias(self):
        src = 'const cp = require("child_process");\ncp.spawn(x);'
        s = [s for s in generic_scanner.scan("t.js", src, "javascript")
             if s.callee == "spawn"][0]
        self.assertEqual(s.module, "child_process")
        self.assertFalse(s.is_method)

    def test_line_numbers_survive_masking(self):
        src = '/* a\n b\n c */\nmemcpy(d, s, n);'
        (s,) = [x for x in generic_scanner.scan("t.c", src, "c") if x.callee == "memcpy"]
        self.assertEqual(s.line, 4)


class TestClassification(unittest.TestCase):
    def setUp(self):
        self.cat = atropos.load()
        self.au = Auditor(self.cat, roles=["sink"], min_match=MATCH_NAME_ONLY)

    def _audit_src(self, path, lang, src):
        from atropos.resolve.model import AuditReport
        rep = AuditReport()
        self.au.audit_source(path, lang, src, rep)
        return rep

    def test_resolved_module_call_is_exact(self):
        rep = self._audit_src("a.py", "python", "import os\nos.system(x)")
        m = [f for f in rep.findings if f.entry.symbol == "os.system"]
        self.assertTrue(m and all(f.match == MATCH_EXACT for f in m))

    def test_c_builtin_is_exact(self):
        rep = self._audit_src("a.c", "c", "memcpy(a,b,n);")
        m = [f for f in rep.findings if f.entry.method == "memcpy"]
        self.assertTrue(m and all(f.match == MATCH_EXACT for f in m))

    def test_unresolved_method_is_heuristic(self):
        rep = self._audit_src("a.py", "python", "cur.execute(q)")
        m = [f for f in rep.findings if f.entry.method == "execute"
             and f.entry.type is not None]
        self.assertTrue(m)
        self.assertTrue(any(f.match == MATCH_HEURISTIC for f in m))

    def test_focus_expr_recovered(self):
        rep = self._audit_src("a.py", "python", "import os\nos.system(danger)")
        f = [f for f in rep.findings if f.entry.symbol == "os.system"][0]
        self.assertEqual(f.focus, "argument 0")
        self.assertEqual(f.focus_expr, "danger")

    def test_summaries_are_never_findings(self):
        # A summary access path (in -> out) is propagation, not a watchpoint.
        rep = self._audit_src("a.py", "python", "import os\nos.system(x)\ncur.execute(q)")
        self.assertFalse(any("->" in f.entry.access_path for f in rep.findings))
        self.assertFalse(any(f.entry.role == "summary" for f in rep.findings))


class TestAuditCLI(unittest.TestCase):
    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(list(argv))
        return rc, buf.getvalue()

    def test_audit_json_shape(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.py")
            with open(p, "w") as fh:
                fh.write("import os\nos.system(cmd)\n")
            rc, out = self._run("audit", p, "--json")
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["files_scanned"], 1)
        syms = {f["symbol"] for f in payload["findings"]}
        self.assertIn("os.system", syms)

    def test_audit_min_match_exact_filters(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.py")
            with open(p, "w") as fh:
                fh.write("import os\nos.system(cmd)\ncur.execute(q)\n")
            rc, out = self._run("audit", p, "--min-match", "exact", "--json")
        payload = json.loads(out)
        self.assertTrue(payload["findings"])
        self.assertTrue(all(f["match"] == "exact" for f in payload["findings"]))


class TestSarif(unittest.TestCase):
    def _sarif(self, src):
        from atropos.resolve.model import AuditReport
        from atropos.resolve.sarif import to_sarif
        cat = atropos.load()
        au = Auditor(cat, roles=["sink"], min_match=MATCH_NAME_ONLY)
        rep = AuditReport()
        au.audit_source("x.py", "python", src, rep)
        return to_sarif(rep)

    def test_sarif_shape_and_backreferences(self):
        doc = self._sarif("import os\nos.system(cmd)\ncur.execute(q)\n")
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertTrue(rules)
        for r in run["results"]:
            # ruleIndex must point back at the matching ruleId
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])
            self.assertIn(r["level"], ("warning", "note"))
            self.assertIn("atroposMatch/v1", r["partialFingerprints"])

    def test_sarif_cwe_taxonomy_resolves(self):
        doc = self._sarif("import os\nos.system(cmd)\n")
        run = doc["runs"][0]
        taxa = {t["id"] for t in run["taxonomies"][0]["taxa"]}
        for rule in run["tool"]["driver"]["rules"]:
            for rel in rule.get("relationships", []):
                self.assertIn(rel["target"]["id"], taxa)

    def test_sarif_fingerprint_is_stable(self):
        a = self._sarif("import os\nos.system(cmd)\n")
        b = self._sarif("import os\nos.system(cmd)\n")
        fa = a["runs"][0]["results"][0]["partialFingerprints"]["atroposMatch/v1"]
        fb = b["runs"][0]["results"][0]["partialFingerprints"]["atroposMatch/v1"]
        self.assertEqual(fa, fb)

    def test_audit_sarif_via_cli(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.py")
            with open(p, "w") as fh:
                fh.write("import os\nos.system(cmd)\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["audit", p, "-f", "sarif"])
        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
