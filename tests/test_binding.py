"""Binding acceptance tests: prove models attach to the exact graph node.

Unlike the schema validator (which only proves JSON shape), these run the
binder over committed neutral symbol-index fixtures and assert the node a model
lands on. They encode the binding contract: a sink binds to exactly
Argument[n], neighbouring arguments are NOT sinks, a summary yields the right
edge, and same-named application symbols are reported ambiguous, not silently
bound. They also lock in the C semantic fixes (read/getenv are not sinks).
"""
import json, unittest
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import bind  # noqa: E402

FIX = ROOT / "fixtures"


def load_index(name):
    return json.loads((FIX / name).read_text())


def models_by_id():
    return {m["id"]: m for m in bind.load_models()}


class BufferFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = load_index("c_buffer.index.json")
        cls.models = models_by_id()
        cls.report = bind.bind_all(bind.load_models(), cls.index)
        cls.byid = {r["model_id"]: r for r in cls.report["results"]}

    def bound_node(self, mid):
        r = self.byid[mid]
        self.assertEqual(r["status"], "bound", f"{mid}: {r}")
        atts = r["attachments"]
        self.assertEqual(len(atts), 1, f"{mid} should hit one callsite")
        return atts[0]["node"]

    def test_sink_binds_to_exact_argument(self):
        # buffer-size sink is Argument[2] (the length), not the whole call.
        self.assertEqual(self.bound_node("c.std.memcpy.a2"), "v_mc_len")
        self.assertEqual(self.bound_node("c.std.memcpy.a0"), "v_mc_dst")
        self.assertEqual(self.bound_node("c.std.scanf.a1"), "v_sc_buf")

    def test_returnvalue_source_binds_to_call_value(self):
        self.assertEqual(self.bound_node("c.std.getenv.ret"), "v_ge_ret")

    def test_read_buffer_source_binds_to_arg1(self):
        self.assertEqual(self.bound_node("c.std.read.a1"), "v_rd_buf")

    def test_neighbour_arguments_are_not_sinks(self):
        # The precision claim: collect every node any SINK model attaches to,
        # then assert the innocent neighbours are absent.
        sink_nodes = set()
        for r in self.report["results"]:
            if r.get("role") == "sink" and r["status"] == "bound":
                sink_nodes.update(a["node"] for a in r["attachments"])
        # memcpy source pointer (Arg1) is read-from, not a write target.
        self.assertNotIn("v_mc_src", sink_nodes)
        # read fd (Arg0) is not a buffer — regression guard.
        self.assertNotIn("v_rd_fd", sink_nodes)
        # getenv name (Arg0) is not a buffer-write sink either.
        self.assertNotIn("v_ge_name", sink_nodes)

    def test_no_model_silently_dropped(self):
        s = self.report["summary"]
        counted = sum(s[k] for k in bind.STATUS)
        self.assertEqual(counted, s["attempted"])
        self.assertEqual(s["attempted"], sum(1 for m in bind.load_models() if m["language"] == "c"))


class AmbiguityFixture(unittest.TestCase):
    def test_same_named_app_symbol_is_ambiguous_not_bound(self):
        index = load_index("c_ambiguous.index.json")
        report = bind.bind_all(bind.load_models(), index)
        r = {x["model_id"]: x for x in report["results"]}["c.std.system.a0"]
        self.assertEqual(r["status"], "ambiguous", r)
        self.assertGreaterEqual(len(r.get("candidates", [])), 2)


class BinderMechanics(unittest.TestCase):
    """Contract behaviours proven with synthetic models, so the catalog is not
    grown before we deliberately add that data (summaries come next, on purpose)."""

    index = {
        "language": "c", "source": "synthetic",
        "callsites": [{
            "id": "cs", "callee": {"name": "strdup", "module": None, "receiver_type": None, "arity": 1},
            "call_value_id": "v_ret", "receiver_value_id": None, "arg_value_ids": ["v_a0"],
        }, {
            "id": "cs2", "callee": {"name": "memcpy", "module": None, "receiver_type": None, "arity": 3},
            "call_value_id": "v_mret", "receiver_value_id": None,
            "arg_value_ids": ["v_d", "v_s", "v_n"],
        }],
    }

    def bind1(self, method, ap, role="summary"):
        m = {"id": "x", "language": "c", "package": None, "type": None,
             "method": method, "access_path": ap, "role": role}
        return bind.bind_model(m, self.index)

    def test_summary_produces_edge(self):
        r = self.bind1("strdup", "Argument[0] -> ReturnValue")
        self.assertEqual(r["status"], "bound")
        edge = r["attachments"][0]["edge"]
        self.assertEqual(edge, {"from": "v_a0", "to": "v_ret"})

    def test_arity_mismatch_reported(self):
        r = self.bind1("memcpy", "Argument[3]", role="sink")
        self.assertEqual(r["status"], "arity-mismatch")

    def test_symbol_not_found_reported(self):
        r = self.bind1("nonexistent_fn", "Argument[0]", role="sink")
        self.assertEqual(r["status"], "symbol-not-found")

    def test_receiver_required_but_absent(self):
        r = self.bind1("strdup", "Receiver", role="summary")
        self.assertEqual(r["status"], "unsupported-path")
        self.assertIn("receiver", r.get("detail", ""))


class SummaryFixture(unittest.TestCase):
    """Real catalog summary models bind to the correct src->dest / in->ret edge."""

    @classmethod
    def setUpClass(cls):
        index = load_index("c_summary.index.json")
        report = bind.bind_all(bind.load_models(), index)
        cls.byid = {r["model_id"]: r for r in report["results"]}

    def edge(self, mid):
        r = self.byid[mid]
        self.assertEqual(r["status"], "bound", f"{mid}: {r}")
        self.assertEqual(len(r["attachments"]), 1)
        return r["attachments"][0]["edge"]

    def test_copy_src_to_dest(self):
        self.assertEqual(self.edge("c.std.memcpy.a1-a0"), {"from": "v_src", "to": "v_dst"})
        self.assertEqual(self.edge("c.std.strcpy.a1-a0"), {"from": "v2_src", "to": "v2_dst"})
        self.assertEqual(self.edge("c.std.strcat.a1-a0"), {"from": "v3_src", "to": "v3_dst"})

    def test_strdup_input_to_return(self):
        self.assertEqual(self.edge("c.std.strdup.a0-ret"), {"from": "v_sd_in", "to": "v_sd_ret"})

    def test_summaries_carry_no_cwe(self):
        summ = [m for m in bind.load_models() if m["role"] == "summary"]
        self.assertGreater(len(summ), 0)
        self.assertTrue(all(m["cwe"] == [] for m in summ), "a summary is not a vulnerability")


class JsBuilderSummaryFixture(unittest.TestCase):
    """The JS/TS builder summaries bind to the exact receiver/arg handles, carrying
    receiver taint the engine's every-argument default would otherwise drop."""

    @classmethod
    def setUpClass(cls):
        index = load_index("js_builders.index.json")
        report = bind.bind_all(bind.load_models(), index)
        cls.byid = {r["model_id"]: r for r in report["results"]}

    def edge(self, mid):
        r = self.byid[mid]
        self.assertEqual(r["status"], "bound", f"{mid}: {r}")
        self.assertEqual(len(r["attachments"]), 1)
        return r["attachments"][0]["edge"]

    def test_receiver_summary_binds(self):
        # userInput.toLowerCase(): the tainted receiver flows to the result.
        self.assertEqual(self.edge("javascript.string.tolowercase.recv-ret"),
                         {"from": "v_user", "to": "v_low_ret"})

    def test_object_assign_binds_both_edges(self):
        self.assertEqual(self.edge("javascript.object.assign.a1-a0"),
                         {"from": "v_src", "to": "v_tgt"})
        self.assertEqual(self.edge("javascript.object.assign.a1-ret"),
                         {"from": "v_src", "to": "v_asn_ret"})

    def test_array_join_receiver_and_separator(self):
        self.assertEqual(self.edge("javascript.array.join.recv-ret"),
                         {"from": "v_parts", "to": "v_join_ret"})
        self.assertEqual(self.edge("javascript.array.join.a0-ret"),
                         {"from": "v_sep", "to": "v_join_ret"})


if __name__ == "__main__":
    unittest.main()
