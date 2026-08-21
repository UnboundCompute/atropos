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


class CatalogError(ValueError):
    """A catalog or symbol-index input that cannot be safely bound."""


def load_models(root: Path = MODELS) -> list:
    out = []
    for f in sorted(root.rglob("*.json")):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except OSError as error:
            raise CatalogError(f"cannot read model file {f}: {error}") from error
        except json.JSONDecodeError as error:
            raise CatalogError(f"invalid JSON in model file {f}: {error}") from error
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
            raise CatalogError(f"invalid model document shape: {f}")
        for e in doc["entries"]:
            if not isinstance(e, dict):
                raise CatalogError(f"invalid model entry in {f}")
            out.append(e)
    return out


def validate_index(index: dict) -> None:
    """Check the binder's required index envelope before resolving any models."""
    if not isinstance(index, dict):
        raise CatalogError("symbol index must be an object")
    allowed = {"format", "version", "language", "source", "callsites", "declarations"}
    unknown = sorted(set(index) - allowed)
    if unknown:
        raise CatalogError(f"symbol index has unknown field(s): {', '.join(unknown)}")
    if index.get("format") != "atropos-symbol-index":
        raise CatalogError("symbol index has unsupported or missing format")
    if (not isinstance(index.get("version"), int)
            or isinstance(index["version"], bool) or index["version"] < 1):
        raise CatalogError("symbol index version must be a positive integer")
    if index.get("language") not in {"c", "python", "javascript", "typescript"}:
        raise CatalogError("symbol index language is missing or unsupported")
    if "source" in index and index["source"] is not None and not isinstance(index["source"], str):
        raise CatalogError("symbol index source must be a string or null")
    callsites = index.get("callsites")
    if not isinstance(callsites, list):
        raise CatalogError("symbol index callsites must be an array")
    for position, callsite in enumerate(callsites):
        prefix = f"symbol index callsites[{position}]"
        if not isinstance(callsite, dict):
            raise CatalogError(f"{prefix} must be an object")
        unknown = sorted(set(callsite) - {
            "id", "callee", "call_value_id", "receiver_value_id", "arg_value_ids",
            "file", "line",
        })
        if unknown:
            raise CatalogError(f"{prefix} has unknown field(s): {', '.join(unknown)}")
        if not isinstance(callsite.get("id"), str):
            raise CatalogError(f"{prefix} is missing a string id")
        callee = callsite.get("callee")
        if not isinstance(callee, dict):
            raise CatalogError(f"{prefix} is missing a callee object")
        unknown = sorted(set(callee) - {"name", "module", "receiver_type", "arity", "static"})
        if unknown:
            raise CatalogError(f"{prefix}.callee has unknown field(s): {', '.join(unknown)}")
        if not isinstance(callee.get("name"), str):
            raise CatalogError(f"{prefix} callee.name must be a string")
        for field in ("module", "receiver_type"):
            if field in callee and callee[field] is not None and not isinstance(callee[field], str):
                raise CatalogError(f"{prefix} callee.{field} must be a string or null")
        if "arity" in callee and callee["arity"] is not None:
            arity = callee["arity"]
            if not isinstance(arity, int) or isinstance(arity, bool) or arity < 0:
                raise CatalogError(f"{prefix} callee.arity must be a non-negative integer or null")
        if "static" in callee and callee["static"] is not None and not isinstance(callee["static"], bool):
            raise CatalogError(f"{prefix} callee.static must be a boolean or null")
        args = callsite.get("arg_value_ids")
        if not isinstance(args, list) or not all(isinstance(node, str) for node in args):
            raise CatalogError(f"{prefix} arg_value_ids must be an array of strings")
        for field in ("call_value_id", "receiver_value_id", "file"):
            if field in callsite and callsite[field] is not None and not isinstance(callsite[field], str):
                raise CatalogError(f"{prefix} {field} must be a string or null")
        if "line" in callsite and callsite["line"] is not None:
            line = callsite["line"]
            if not isinstance(line, int) or isinstance(line, bool):
                raise CatalogError(f"{prefix} line must be an integer or null")

    declarations = index.get("declarations", [])
    if not isinstance(declarations, list):
        raise CatalogError("symbol index declarations must be an array")
    for position, declaration in enumerate(declarations):
        prefix = f"symbol index declarations[{position}]"
        if not isinstance(declaration, dict):
            raise CatalogError(f"{prefix} must be an object")
        if not isinstance(declaration.get("id"), str) or not isinstance(declaration.get("name"), str):
            raise CatalogError(f"{prefix} requires string id and name")
        for field in ("module", "receiver_type", "kind", "file"):
            if field in declaration and declaration[field] is not None and not isinstance(declaration[field], str):
                raise CatalogError(f"{prefix} {field} must be a string or null")
        if "arity" in declaration and declaration["arity"] is not None:
            arity = declaration["arity"]
            if not isinstance(arity, int) or isinstance(arity, bool) or arity < 0:
                raise CatalogError(f"{prefix} arity must be a non-negative integer or null")
        if "line" in declaration and declaration["line"] is not None:
            line = declaration["line"]
            if not isinstance(line, int) or isinstance(line, bool):
                raise CatalogError(f"{prefix} line must be an integer or null")


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
        index = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        print(f"bind.py: cannot read {path}: {error}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as error:
        print(f"bind.py: invalid JSON in {path}: {error}", file=sys.stderr)
        return 2
    if not isinstance(index, dict):
        print(f"bind.py: symbol index {path} must be a JSON object", file=sys.stderr)
        return 2
    try:
        validate_index(index)
        models = load_models()
    except CatalogError as error:
        print(f"bind.py: {error}", file=sys.stderr)
        return 2
    report = bind_all(models, index)
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
