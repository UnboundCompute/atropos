#!/usr/bin/env python3
"""Generate a tiny source reference and neutral index for one model.

The generated source is illustrative; the ``*.index.json`` file is the binding
authority. The tool intentionally stays engine-independent and writes only into
an explicitly selected output directory.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LANG_EXT = {"c": "c", "python": "py", "javascript": "js", "typescript": "ts"}
ARGUMENT = re.compile(r"Argument\[(\d+)\]")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate a source and symbol-index binding fixture.")
    p.add_argument("model_id", help="existing model ID to fixture")
    p.add_argument("--root", type=Path, default=ROOT, help="Atropos checkout (default: this checkout)")
    p.add_argument("--output-dir", type=Path, required=True, help="existing directory for generated fixture files")
    return p


def models(root: Path) -> list[dict]:
    result = []
    for path in sorted((root / "models").rglob("*.json")):
        try:
            result.extend(json.loads(path.read_text(encoding="utf-8")).get("entries", []))
        except (OSError, json.JSONDecodeError, AttributeError):
            continue
    return result


def source_for(language: str, method: str, arity: int) -> str:
    args = ", ".join(f"arg{i}" for i in range(arity))
    if language == "c":
        return f"int fixture(void) {{\n    return {method}({args});\n}}\n"
    if language == "python":
        return f"def fixture({args}):\n    return {method}({args})\n"
    return f"export function fixture({args}) {{\n  return {method}({args});\n}}\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = args.root.resolve()
    output = args.output_dir.resolve()
    if not output.is_dir():
        print(f"new_fixture.py: output directory does not exist: {output}", file=sys.stderr)
        return 2
    model = next((entry for entry in models(root) if entry.get("id") == args.model_id), None)
    if model is None:
        print(f"new_fixture.py: model ID not found: {args.model_id}", file=sys.stderr)
        return 1
    language = model["language"]
    path_terms = model.get("access_path", "").split("->")
    indexes = [int(match.group(1)) for term in path_terms if (match := ARGUMENT.fullmatch(term.strip()))]
    arity = model.get("arity")
    if arity is None:
        arity = max(indexes, default=-1) + 1
    if arity < 0:
        arity = 0
    slug = re.sub(r"[^a-z0-9]+", "_", args.model_id.lower()).strip("_")
    extension = LANG_EXT[language]
    source_name = f"{slug}.{extension}"
    index_name = f"{slug}.index.json"
    source_path = output / source_name
    index_path = output / index_name
    if source_path.exists() or index_path.exists():
        print(f"new_fixture.py: refusing to overwrite {source_name} or {index_name}", file=sys.stderr)
        return 1
    arg_ids = [f"v_arg{i}" for i in range(arity)]
    callsite = {
        "id": f"cs_{slug}",
        "callee": {
            "name": model["method"],
            "module": model.get("package"),
            "receiver_type": model.get("type"),
            "arity": arity,
            "static": True,
        },
        "call_value_id": "v_return",
        "receiver_value_id": "v_receiver" if "Receiver" in model.get("access_path", "") else None,
        "arg_value_ids": arg_ids,
        "file": f"fixtures/{source_name}",
        "line": 2,
    }
    index = {
        "format": "atropos-symbol-index",
        "version": 1,
        "language": language,
        "source": f"fixtures/{source_name}",
        "callsites": [callsite],
    }
    source_path.write_text(source_for(language, model["method"], arity), encoding="utf-8")
    index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"created {source_path.name} and {index_path.name} for {args.model_id}")
    print(f"next: python3 tools/bind.py {index_path.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
