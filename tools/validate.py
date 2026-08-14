#!/usr/bin/env python3
"""Validate every model file against the Atropos entry rules. Stdlib only.

Checks structure, enums, id uniqueness, access-path grammar, CWE format, and
that each file's declared role_group matches every entry's role. Exit non-zero
on any violation so CI and pre-commit can gate on it.
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"

ROLES = {"sink", "source", "sanitizer", "summary"}
LANGS = {"c", "python", "javascript", "typescript"}
CONF = {"high", "medium", "low"}
ID_RE = re.compile(r"^[a-z0-9]+(\.[a-z0-9_*<>-]+)+$")
AP_TERM = r"(Argument\[(\*|[0-9]+)\]|ReturnValue|Receiver)"
AP_RE = re.compile(rf"^{AP_TERM}(\s*->\s*{AP_TERM})?$")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
REQUIRED = ("id", "language", "method", "access_path", "role", "kind", "cwe", "confidence")


def validate_entry(e: dict, role_group: str, where: str, errs: list) -> None:
    def err(m): errs.append(f"{where}: {m}")
    for k in REQUIRED:
        if k not in e:
            err(f"missing required field '{k}'")
    if "id" in e and not ID_RE.match(e["id"]):
        err(f"bad id '{e['id']}'")
    if e.get("language") not in LANGS:
        err(f"bad language '{e.get('language')}'")
    if e.get("role") not in ROLES:
        err(f"bad role '{e.get('role')}'")
    if e.get("role") != role_group:
        err(f"role '{e.get('role')}' != file role_group '{role_group}'")
    if e.get("confidence") not in CONF:
        err(f"bad confidence '{e.get('confidence')}'")
    if "access_path" in e and not AP_RE.match(e["access_path"]):
        err(f"bad access_path '{e['access_path']}'")
    if "corroboration" in e and (not isinstance(e["corroboration"], int) or e["corroboration"] < 1):
        err(f"bad corroboration '{e.get('corroboration')}'")
    for c in e.get("cwe", []):
        if not CWE_RE.match(c):
            err(f"bad CWE id '{c}'")


def main() -> int:
    errs: list = []
    seen: dict = {}
    files = sorted(MODELS.rglob("*.json"))
    if not files:
        print("no model files found under models/", file=sys.stderr)
        return 1
    total = 0
    for f in files:
        rel = f.relative_to(ROOT)
        try:
            doc = json.loads(f.read_text())
        except json.JSONDecodeError as ex:
            errs.append(f"{rel}: invalid JSON: {ex}")
            continue
        rg = doc.get("role_group")
        if rg not in ROLES:
            errs.append(f"{rel}: bad or missing role_group '{rg}'")
            rg = None
        for i, e in enumerate(doc.get("entries", [])):
            total += 1
            where = f"{rel}[{i}] id={e.get('id','?')}"
            validate_entry(e, rg, where, errs)
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
    print(f"OK: {total} entries in {len(files)} files, all valid, ids unique")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
