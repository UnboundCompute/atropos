"""Read the optional detection layer: the class-first ``kind -> evaluator`` recipe and
the front-end sink-role bridges that ship under ``detection/``.

This layer is what lets a consumer route a sink *kind* to a generic evaluator without
hard-coding the mapping. It is self-checked on load (every recipe target is a declared
evaluator; every bridge target is a known kind) so a bad edit fails here, not downstream.
The engine that dispatches on these tables lives outside this repo; here we just load
and validate them.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import loader


def load_detection(root: Optional[str] = None) -> dict:
    """Return ``{evaluators, kind_evaluator, role_bridges}``, self-checked.

    Returns an empty-shaped dict if the catalog carries no ``detection/`` directory.
    """
    catalog_root = loader.find_catalog_root(root)
    det = catalog_root / "detection"
    if not det.is_dir():
        return {"evaluators": {}, "kind_evaluator": {}, "role_bridges": {}}

    ev_doc = loader.read_json(det / "evaluators.json")
    evaluators = ev_doc["evaluators"]
    kind_evaluator = ev_doc["kind_evaluator"]

    for kind, ev in kind_evaluator.items():
        names = [ev] if isinstance(ev, str) else ev
        if not isinstance(names, list) or not names:
            raise ValueError(f"kind '{kind}' has a malformed evaluator target '{ev}'")
        for name in names:
            if name not in evaluators:
                raise ValueError(f"kind '{kind}' routes to unknown evaluator '{name}'")

    role_bridges: dict = {}
    for f in sorted(det.glob("sink-roles*.json")):
        doc = loader.read_json(f)
        vocab = doc["vocabulary"]
        bridge = doc["role_kind"]
        for role, kind in bridge.items():
            if kind not in kind_evaluator:
                raise ValueError(
                    f"{f.name}: role '{role}' bridges to kind '{kind}' with no recipe"
                )
        role_bridges[vocab] = bridge

    return {
        "evaluators": evaluators,
        "kind_evaluator": kind_evaluator,
        "role_bridges": role_bridges,
    }
