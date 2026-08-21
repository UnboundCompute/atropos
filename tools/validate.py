#!/usr/bin/env python3
"""Validate every model file against schema/model.schema.json. Stdlib only.

Enforces the schema directly: a small draft-07 subset validator (type, enum,
pattern, required, additionalProperties, minimum, array items) reads
schema/model.schema.json and applies it to every entry, so the schema is the
single source of truth rather than a second hand-maintained copy of the rules.
On top of the schema it adds two cross-cutting checks the schema cannot express:
global id uniqueness, and that each file's role_group matches every entry's role.
Exit non-zero on any violation so CI and pre-commit can gate on it.
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"
CANDIDATES = ROOT / "candidates"   # unverified/unbindable; gated for shape, not loaded by consumers
SCHEMA = ROOT / "schema" / "model.schema.json"


def resolve(schema: dict, node: dict) -> dict:
    """Follow a local $ref (#/definitions/x) one hop; return node unchanged otherwise."""
    ref = node.get("$ref")
    if not ref or not ref.startswith("#/"):
        return node
    cur = schema
    for part in ref[2:].split("/"):
        cur = cur[part]
    return cur


def check(schema: dict, node: dict, value, where: str, errs: list) -> None:
    node = resolve(schema, node)
    t = node.get("type")
    types = t if isinstance(t, list) else [t] if t else []

    def is_type(name):
        if name == "string": return isinstance(value, str)
        if name == "integer": return isinstance(value, int) and not isinstance(value, bool)
        if name == "number": return isinstance(value, (int, float)) and not isinstance(value, bool)
        if name == "array": return isinstance(value, list)
        if name == "object": return isinstance(value, dict)
        if name == "null": return value is None
        return True

    if types and not any(is_type(n) for n in types):
        errs.append(f"{where}: expected type {t}, got {type(value).__name__}")
        return
    if value is None and "null" in types:
        return

    if "enum" in node and value not in node["enum"]:
        errs.append(f"{where}: {value!r} not in {node['enum']}")
    if "pattern" in node and isinstance(value, str) and not re.match(node["pattern"], value):
        errs.append(f"{where}: {value!r} violates pattern {node['pattern']}")
    if "minimum" in node and isinstance(value, (int, float)) and value < node["minimum"]:
        errs.append(f"{where}: {value} below minimum {node['minimum']}")

    if "object" in types and isinstance(value, dict):
        props = node.get("properties", {})
        for req in node.get("required", []):
            if req not in value:
                errs.append(f"{where}: missing required field '{req}'")
        if node.get("additionalProperties") is False:
            for k in value:
                if k not in props:
                    errs.append(f"{where}: unknown field '{k}'")
        for k, v in value.items():
            if k in props:
                check(schema, props[k], v, f"{where}.{k}", errs)

    if "array" in types and isinstance(value, list) and "items" in node:
        for i, item in enumerate(value):
            check(schema, node["items"], item, f"{where}[{i}]", errs)


def main() -> int:
    schema = json.loads(SCHEMA.read_text())
    entry_schema = schema["definitions"]["entry"]
    roles = entry_schema["properties"]["role"]["enum"]

    errs: list = []
    seen: dict = {}
    files = sorted(MODELS.rglob("*.json"))
    if not files:
        print("no model files found under models/", file=sys.stderr)
        return 1
    files += sorted(CANDIDATES.rglob("*.json"))   # share the id namespace with facts
    total = 0
    for f in files:
        rel = f.relative_to(ROOT)
        try:
            doc = json.loads(f.read_text())
        except OSError as ex:
            errs.append(f"{rel}: cannot read file: {ex}")
            continue
        except json.JSONDecodeError as ex:
            errs.append(f"{rel}: invalid JSON: {ex}")
            continue
        if not isinstance(doc, dict):
            errs.append(f"{rel}: top-level value must be an object")
            continue
        # File-level shape is the schema's top object (role_group + entries).
        rg = doc.get("role_group")
        if rg not in roles:
            errs.append(f"{rel}: bad or missing role_group '{rg}'")
            rg = None
        entries = doc.get("entries", [])
        if not isinstance(entries, list):
            errs.append(f"{rel}: 'entries' must be an array")
            continue
        for i, e in enumerate(entries):
            total += 1
            where = f"{rel}[{i}] id={e.get('id','?') if isinstance(e, dict) else '?'}"
            check(schema, entry_schema, e, where, errs)
            if not isinstance(e, dict):
                continue
            # Cross-cutting checks the schema can't express:
            if rg is not None and e.get("role") != rg:
                errs.append(f"{where}: role '{e.get('role')}' != file role_group '{rg}'")
            eid = e.get("id")
            if eid in seen:
                errs.append(f"{where}: duplicate id (also in {seen[eid]})")
            elif eid:
                seen[eid] = rel
    if errs:
        for m in errs:
            print("FAIL", m, file=sys.stderr)
        print(f"\n{len(errs)} problem(s) across {len(files)} file(s)", file=sys.stderr)
        return 1
    ncand = sum(1 for f in files if str(f).startswith(str(CANDIDATES)))
    tail = f" ({ncand} candidate file(s))" if ncand else ""
    print(f"OK: {total} entries in {len(files)} files, schema-valid, ids unique{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
