#!/usr/bin/env python3
"""Load the detection layer -- the CLASS-first recipe that routes a sink kind to a
generic evaluator, plus front-end sink-role bridges. Stdlib only, pure data.

Two tables live under ``detection/``:

  evaluators.json   the closed evaluator vocabulary and the ``kind -> evaluator``
                    recipe, keyed by the same ``kind`` the models/ catalog stamps.
  sink-roles.json   per-front-end bridges from a coarse runtime sink vocabulary
                    (e.g. Lachesis ``generic-security-roles``) to catalog kinds.

A consumer calls :func:`load_detection` and reads the returned tables; the engine
that dispatches on them lives outside this repo. This module also self-checks the
data on load (every recipe target is a known evaluator; every bridge target is a
known kind) so a bad edit fails here rather than in a downstream engine.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTION = ROOT / "detection"


def _read(name: str) -> dict:
    return json.loads((DETECTION / name).read_text())


def load_detection(root: Path = DETECTION) -> dict:
    """Return {evaluators, kind_evaluator, role_bridges} with the data self-checked.

    role_bridges is {vocabulary -> {role -> kind}}, one entry per sink-role file, so
    a consumer can select the bridge for whichever front-end stamped its graph.
    """
    ev_doc = json.loads((root / "evaluators.json").read_text())
    evaluators = ev_doc["evaluators"]
    kind_evaluator = ev_doc["kind_evaluator"]

    # Every recipe target must name a declared evaluator -- the closed-set promise.
    # A target is one evaluator name or a LIST of them (a kind can select several
    # patterns over one flow, e.g. a memory copy is both a size and a guard check).
    for kind, ev in kind_evaluator.items():
        names = [ev] if isinstance(ev, str) else ev
        if not isinstance(names, list) or not names:
            raise ValueError(f"kind '{kind}' has a malformed evaluator target '{ev}'")
        for name in names:
            if name not in evaluators:
                raise ValueError(f"kind '{kind}' routes to unknown evaluator '{name}'")

    role_bridges: dict = {}
    for f in sorted(root.glob("sink-roles*.json")):
        doc = json.loads(f.read_text())
        vocab = doc["vocabulary"]
        bridge = doc["role_kind"]
        # Every bridge target must be a kind the recipe knows -- no dangling roles.
        for role, kind in bridge.items():
            if kind not in kind_evaluator:
                raise ValueError(
                    f"{f.name}: role '{role}' bridges to kind '{kind}' with no recipe"
                )
        role_bridges[vocab] = bridge

    flow_patterns = _load_flow_patterns(root)

    return {
        "evaluators": evaluators,
        "kind_evaluator": kind_evaluator,
        "role_bridges": role_bridges,
        "flow_patterns": flow_patterns,
    }


_PATTERN_STATUS = {"shipped", "todo", "blocked"}


def _load_flow_patterns(root: Path = DETECTION) -> list:
    """The flow-skeleton pattern directory, self-checked. Empty list if absent.

    A pattern is a structural shape over the control skeleton, a layer distinct from
    the kind->evaluator recipe. Self-checks keep the directory honest: unique ids,
    a valid tier/status, a non-empty ``requires`` naming only alphabet the file itself
    declares, and a blocked pattern must say what it is ``blocked_on``.
    """
    f = root / "flow-patterns.json"
    if not f.exists():
        return []
    doc = json.loads(f.read_text())
    known = set((doc.get("skeleton_alphabet") or {}).get("sink_families") or {})
    known |= set((doc.get("skeleton_alphabet") or {}).get("control_alphabet") or [])
    seen: set = set()
    for p in doc.get("patterns", []):
        pid = p.get("id")
        if not pid or pid in seen:
            raise ValueError(f"flow-patterns: missing or duplicate id '{pid}'")
        seen.add(pid)
        if p.get("tier") not in (1, 2):
            raise ValueError(f"flow-patterns: '{pid}' has bad tier {p.get('tier')}")
        if p.get("status") not in _PATTERN_STATUS:
            raise ValueError(f"flow-patterns: '{pid}' has bad status {p.get('status')}")
        req = p.get("requires") or []
        if not req:
            raise ValueError(f"flow-patterns: '{pid}' declares no requires")
        for token in req:
            if token not in known:
                raise ValueError(
                    f"flow-patterns: '{pid}' requires '{token}' absent from the alphabet")
        if p.get("status") == "blocked" and not p.get("blocked_on"):
            raise ValueError(f"flow-patterns: blocked '{pid}' must state blocked_on")
    return doc.get("patterns", [])


if __name__ == "__main__":
    d = load_detection()
    print(f"evaluators:     {', '.join(sorted(d['evaluators']))}")
    print(f"flow_patterns:  {len(d['flow_patterns'])} patterns")
    print(f"kind_evaluator: {len(d['kind_evaluator'])} kinds")
    for vocab, bridge in d["role_bridges"].items():
        print(f"bridge[{vocab}]: {len(bridge)} roles")
