#!/usr/bin/env python3
"""Quick coverage snapshot of the model set. Stdlib only."""
from __future__ import annotations
import json
import sys
from collections import Counter
from pathlib import Path

if len(sys.argv) > 1:
    if sys.argv[1:] in (["-h"], ["--help"]):
        print("usage: stats.py")
        print("Print model coverage by language, role, and kind.")
        raise SystemExit(0)
    print("usage: stats.py", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent.parent
by_lang_role = Counter()
by_kind = Counter()
total = 0
for f in sorted((ROOT / "models").rglob("*.json")):
    doc = json.loads(f.read_text())
    for e in doc.get("entries", []):
        total += 1
        by_lang_role[(e["language"], e["role"])] += 1
        by_kind[e["kind"]] += 1

print(f"Atropos model coverage: {total} entries\n")
print("by language / role:")
for (lang, role), n in sorted(by_lang_role.items()):
    print(f"  {lang:12} {role:10} {n}")
print("\nby kind:")
for kind, n in sorted(by_kind.items(), key=lambda x: -x[1]):
    print(f"  {kind:20} {n}")
