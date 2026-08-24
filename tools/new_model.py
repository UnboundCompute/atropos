#!/usr/bin/env python3
"""Scaffold one Atropos model entry into a role-grouped JSON file.

The command deliberately creates data only; ``validate.py`` and a binding fixture
remain the quality gates. Use ``--root`` in tests or when generating into a fork.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FILE_SUFFIX = {"sink": "sinks", "source": "sources", "sanitizer": "sanitizers", "summary": "summaries"}
LANGUAGES = ("c", "python", "javascript", "typescript")
ROLES = tuple(FILE_SUFFIX)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Scaffold one validated Atropos model entry.")
    p.add_argument("id", help="stable dotted lowercase model id")
    p.add_argument("--root", type=Path, default=ROOT, help="Atropos checkout (default: this checkout)")
    p.add_argument("--language", required=True, choices=LANGUAGES)
    p.add_argument("--role", required=True, choices=ROLES)
    p.add_argument("--method", required=True)
    p.add_argument("--access-path", required=True)
    p.add_argument("--kind", required=True)
    p.add_argument("--cwe", action="append", required=True, help="CWE id; repeat or comma-separate")
    p.add_argument("--package")
    p.add_argument("--type", dest="owner_type")
    p.add_argument("--signature")
    p.add_argument("--arity", type=int)
    p.add_argument("--confidence", choices=("high", "medium", "low"), default="medium")
    p.add_argument("--corroboration", type=int)
    p.add_argument("--notes")
    return p


def all_ids(root: Path) -> set[str]:
    found: set[str] = set()
    for directory in (root / "models", root / "candidates"):
        if not directory.exists():
            continue
        for path in directory.rglob("*.json"):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for entry in doc.get("entries", []):
                if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                    found.add(entry["id"])
    return found


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = args.root.resolve()
    target = root / "models" / args.language / f"{FILE_SUFFIX[args.role]}.json"
    if args.id in all_ids(root):
        print(f"new_model.py: id already exists: {args.id}", file=sys.stderr)
        return 1
    cwes = [item.strip() for group in args.cwe for item in group.split(",") if item.strip()]
    entry = {
        "id": args.id,
        "language": args.language,
        "package": args.package,
        "type": args.owner_type,
        "method": args.method,
        "signature": args.signature,
        "access_path": args.access_path,
        "role": args.role,
        "kind": args.kind,
        "cwe": cwes,
        "confidence": args.confidence,
    }
    if args.arity is not None:
        entry["arity"] = args.arity
    if args.corroboration is not None:
        entry["corroboration"] = args.corroboration
    if args.notes is not None:
        entry["notes"] = args.notes

    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        try:
            document = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"new_model.py: cannot read {target}: {error}", file=sys.stderr)
            return 2
        if document.get("role_group") != args.role:
            print(f"new_model.py: {target} has role_group {document.get('role_group')!r}", file=sys.stderr)
            return 2
        entries = document.setdefault("entries", [])
    else:
        document = {"role_group": args.role, "entries": []}
        entries = document["entries"]
    entries.append(entry)
    target.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"created {args.id} in {target.relative_to(root)}")
    print("next: run python3 tools/validate.py and add a binding fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
