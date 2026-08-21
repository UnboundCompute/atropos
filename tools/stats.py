#!/usr/bin/env python3
"""Quick coverage snapshot of the model set. Stdlib only."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def main(argv=None) -> int:
    argv = [] if argv is None else argv
    if argv in (["-h"], ["--help"]):
        print("usage: stats.py")
        print("Print model coverage by language, role, and kind.")
        return 0
    if argv:
        print("usage: stats.py", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parent.parent
    by_lang_role = Counter()
    by_kind = Counter()
    total = 0
    for f in sorted((root / "models").rglob("*.json")):
        try:
            doc = json.loads(f.read_text())
        except OSError as error:
            print(f"stats.py: cannot read {f}: {error}", file=sys.stderr)
            return 2
        except json.JSONDecodeError as error:
            print(f"stats.py: invalid JSON in {f}: {error}", file=sys.stderr)
            return 2
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
            print(f"stats.py: invalid model document shape: {f}", file=sys.stderr)
            return 2
        for entry in doc["entries"]:
            if not isinstance(entry, dict):
                print(f"stats.py: invalid entry in {f}", file=sys.stderr)
                return 2
            try:
                total += 1
                by_lang_role[(entry["language"], entry["role"])] += 1
                by_kind[entry["kind"]] += 1
            except KeyError as error:
                print(f"stats.py: entry in {f} is missing {error.args[0]!r}", file=sys.stderr)
                return 2

    print(f"Atropos model coverage: {total} entries\n")
    print("by language / role:")
    for (lang, role), n in sorted(by_lang_role.items()):
        print(f"  {lang:12} {role:10} {n}")
    print("\nby kind:")
    for kind, n in sorted(by_kind.items(), key=lambda x: -x[1]):
        print(f"  {kind:20} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
