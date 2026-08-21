#!/usr/bin/env python3
"""Bind Atropos models to a neutral symbol index and report every outcome.

This is the acceptance contract Atropos owns. It does NOT depend on any engine:
a graph tool (Lachesis) exports its symbols into the neutral
`atropos-symbol-index` format (schema/symbol-index.schema.json); this binder
resolves each model's (language, package, type, method) against that index and
applies the model's access_path to an exact node handle. Stdlib only.

The cardinal rule: a model is never silently ignored. Every model gets one of:
  bound | symbol-not-found | ambiguous | arity-mismatch | unsupported-path

Access-path -> node mapping:
  Argument[n]              -> callsite.arg_value_ids[n]
  ReturnValue              -> callsite.call_value_id
  Receiver                 -> callsite.receiver_value_id
  X -> Y  (summary)        -> a semantic-flow edge {from: node(X), to: node(Y)}
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"

STATUS = ("bound", "symbol-not-found", "ambiguous", "arity-mismatch", "unsupported-path")
_ARG = re.compile(r"^Argument\[([0-9]+)\]$")  # binder resolves concrete indices, not Argument[*]


def load_models(root: Path = MODELS) -> list:
    out = []
    for f in sorted(root.rglob("*.json")):
        for e in json.loads(f.read_text()).get("entries", []):
            out.append(e)
    return out


def _matches(model: dict, callee: dict) -> bool:
    """A model matches a callsite's callee by name, with package/type as
    disambiguating hints. A hint constrains only when the model supplies it and
    the callsite carries a value to check it against."""
    if model.get("method") != callee.get("name"):
        return False
    pkg = model.get("package")
    if pkg is not None and callee.get("module") is not None and callee["module"] != pkg:
        return False
    typ = model.get("type")
    if typ is not None and callee.get("receiver_type") is not None and callee["receiver_type"] != typ:
        return False
    # Arity, when pinned, is a hard discriminator: a same-named callsite with a
    # different parameter count is a different symbol (a project's own recv[]()
    # pointer, say, that shadows the libc name). Only constrains when the callsite
    # actually carries an arity to check.
    ar = model.get("arity")
    if ar is not None and callee.get("arity") is not None and callee["arity"] != ar:
        return False
    return True


def _endpoint(term: str):
    """Return ('argument', n) | ('return', None) | ('receiver', None) | None (unsupported)."""
    if term == "ReturnValue":
        return ("return", None)
    if term == "Receiver":
        return ("receiver", None)
    m = _ARG.match(term)
    if m:
        return ("argument", int(m.group(1)))
    return None  # Argument[*] or any richer path the binder does not yet resolve


def _resolve(endpoint, callsite: dict):
    """Map an endpoint onto a concrete node id at one callsite.
    Returns (node_id, kind, index) or raises ('arity' | 'missing', detail)."""
    kind, idx = endpoint
    if kind == "return":
        nid = callsite.get("call_value_id")
        if nid is None:
            raise LookupError(("missing", "callsite has no call_value_id"))
        return nid, "return", None
    if kind == "receiver":
        nid = callsite.get("receiver_value_id")
        if nid is None:
            raise LookupError(("missing", "model expects a receiver; callsite has none"))
        return nid, "receiver", None
    args = callsite.get("arg_value_ids", [])
    arity = callsite.get("callee", {}).get("arity")
    if idx >= len(args) or (arity is not None and idx >= arity):
        raise LookupError(("arity", f"Argument[{idx}] out of range (callsite arity {arity or len(args)})"))
    return args[idx], "argument", idx


def bind_model(model: dict, index: dict) -> dict:
    lang = index.get("language")
    callsites = [c for c in index.get("callsites", [])
                 if (lang is None or model.get("language") == lang) and _matches(model, c["callee"])]
    res = {"model_id": model.get("id"), "method": model.get("method"),
           "access_path": model.get("access_path"), "role": model.get("role")}

    if not callsites:
        res["status"] = "symbol-not-found"
        return res

    # Ambiguous when the name resolves to more than one distinct symbol identity
    # -- a (module, receiver_type) pair -- that the model did not pin down (a
    # libc symbol and an application symbol of the same name, say). Arity is NOT
    # an identity axis: a variadic function (the printf family) legitimately
    # appears at many arities, and a fixed positional access_path binds each
    # callsite on its own, so an arity spread must not sink the whole model.
    identities = {(c["callee"].get("module"), c["callee"].get("receiver_type"))
                  for c in callsites}
    if len(identities) > 1:
        res["status"] = "ambiguous"
        distinct = {(c["callee"].get("module"), c["callee"].get("receiver_type"),
                     c["callee"].get("arity")) for c in callsites}
        res["candidates"] = [dict(zip(("module", "receiver_type", "arity"), d))
                              for d in sorted(distinct, key=str)]
        return res

    terms = [t.strip() for t in model["access_path"].split("->")]
    endpoints = [_endpoint(t) for t in terms]
    if any(ep is None for ep in endpoints):
        res["status"] = "unsupported-path"
        return res

    # Bind every callsite where the referenced position exists. A callsite too
    # short for this argument is skipped and recorded -- never used to discard
    # the callsites that do fit (the whole point of tolerating an arity spread).
    attachments, skipped, unsupported = [], [], None
    for cs in callsites:
        try:
            nodes = [_resolve(ep, cs) for ep in endpoints]
        except LookupError as ex:
            kind, detail = ex.args[0]
            if kind == "arity":
                skipped.append({"callsite": cs["id"], "detail": detail})
                continue
            unsupported = detail
            break
        if len(nodes) == 1:
            nid, kind, idx = nodes[0]
            attachments.append({"callsite": cs["id"], "node": nid, "kind": kind, "index": idx})
        else:  # summary: an edge from first endpoint to last
            (fnid, fk, fi), (tnid, tk, ti) = nodes[0], nodes[-1]
            attachments.append({"callsite": cs["id"], "edge": {"from": fnid, "to": tnid},
                                "from_kind": fk, "to_kind": tk})

    if unsupported is not None:
        res["status"] = "unsupported-path"
        res["detail"] = unsupported
        return res
    if not attachments:
        # Every matching callsite was too short for the referenced position.
        res["status"] = "arity-mismatch"
        res["detail"] = skipped[0]["detail"] if skipped else "no bindable callsite"
        return res
    res["status"] = "bound"
    res["attachments"] = attachments
    if skipped:
        res["skipped"] = skipped
    return res


def bind_all(models: list, index: dict) -> dict:
    results = [bind_model(m, index) for m in models
               if index.get("language") in (None, m.get("language"))]
    summary = {s: 0 for s in STATUS}
    for r in results:
        summary[r["status"]] += 1
    summary["attempted"] = len(results)
    return {"format": "atropos-binding-report", "version": 1,
            "index": index.get("source", index.get("id")),
            "summary": summary, "results": results}


def main(argv: list) -> int:
    if argv[1:] in (["-h"], ["--help"]):
        print("usage: bind.py <symbol-index.json>")
        print("Bind catalog entries to a neutral symbol index and emit a JSON report.")
        return 0
    if len(argv) == 2 and argv[1].startswith("-"):
        print("usage: bind.py <symbol-index.json>", file=sys.stderr)
        return 2
    if len(argv) != 2:
        print("usage: bind.py <symbol-index.json>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        index = json.loads(path.read_text())
    except OSError as error:
        print(f"bind.py: cannot read {path}: {error}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as error:
        print(f"bind.py: invalid JSON in {path}: {error}", file=sys.stderr)
        return 2
    if not isinstance(index, dict):
        print(f"bind.py: symbol index {path} must be a JSON object", file=sys.stderr)
        return 2
    report = bind_all(load_models(), index)
    print(json.dumps(report, indent=2))
    s = report["summary"]
    # Report only; the caller decides what is acceptable. Surface the shape.
    print(f"\n{s['bound']} bound / {s['attempted']} applicable  "
          f"(not-found {s['symbol-not-found']}, ambiguous {s['ambiguous']}, "
          f"arity {s['arity-mismatch']}, unsupported {s['unsupported-path']})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
