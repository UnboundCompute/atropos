#!/usr/bin/env python3
"""Validate the Atropos model-pack manifest against this checkout."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "pack.json"
VERSION = ROOT / "VERSION"


def main(argv=None) -> int:
    argv = [] if argv is None else argv
    if argv in (["-h"], ["--help"]):
        print("usage: validate_pack.py")
        print("Validate pack metadata, version authority, and model coverage.")
        return 0
    if argv:
        print("usage: validate_pack.py", file=sys.stderr)
        return 2
    try:
        pack = json.loads(PACK.read_text(encoding="utf-8"))
        version = VERSION.read_text(encoding="utf-8").strip()
    except (OSError, json.JSONDecodeError) as error:
        print(f"validate_pack.py: cannot read pack metadata: {error}", file=sys.stderr)
        return 2
    errors = []
    if pack.get("format") != "atropos-model-pack":
        errors.append("format must be atropos-model-pack")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(pack.get("version", ""))):
        errors.append("version must be semantic version text")
    if pack.get("version") != version:
        errors.append(f"pack version {pack.get('version')} != VERSION {version}")
    if not pack.get("provenance", {}).get("binding_required"):
        errors.append("provenance.binding_required must be true")
    if pack.get("provenance", {}).get("candidate_rows_are_consumed"):
        errors.append("candidate rows must remain outside verified consumer models")
    files = []
    for pattern in pack.get("model_globs", []):
        files.extend(ROOT.glob(pattern))
    files = sorted(set(path for path in files if path.is_file()))
    entries = 0
    for path in files:
        try:
            entries += len(json.loads(path.read_text(encoding="utf-8")).get("entries", []))
        except (OSError, json.JSONDecodeError, AttributeError):
            errors.append(f"cannot count entries in {path.relative_to(ROOT)}")
    if entries != pack.get("verified_entries"):
        errors.append(f"verified_entries {pack.get('verified_entries')} != counted models {entries}")
    if not files:
        errors.append("model_globs matched no files")
    if errors:
        for error in errors:
            print(f"FAIL {error}", file=sys.stderr)
        return 1
    print(f"OK: pack {pack['id']} v{pack['version']} covers {entries} verified entries in {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
