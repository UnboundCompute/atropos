"""The ``atropos`` command line: query the taint catalog without an engine.

Every subcommand is a lookup over the same data the library exposes -- list sinks or
sources filtered by language / kind / package / CWE, resolve a concrete call to the
facts that attach to it, search free text, show one entry, or export the set as JSON,
JSONL, or CSV. Nothing here makes a security verdict; it answers "what does the catalog
say about this symbol."
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from typing import List, Optional

from ._version import __version__
from .catalog import Catalog, Entry, load
from .detection import load_detection
from .loader import CatalogNotFound, find_catalog_root, pack_version


# -- rendering ---------------------------------------------------------------

_TABLE_COLS = ("language", "role", "kind", "symbol", "access_path", "confidence")


def _entry_row(e: Entry) -> "List[str]":
    return [
        e.language,
        e.role,
        e.kind,
        e.symbol,
        e.access_path,
        e.confidence or "-",
    ]


def _print_table(entries: "List[Entry]", show_id: bool = False) -> None:
    if not entries:
        print("(no matching entries)")
        return
    cols = (("id",) + _TABLE_COLS) if show_id else _TABLE_COLS
    rows = []
    for e in entries:
        base = _entry_row(e)
        rows.append(([e.id] + base) if show_id else base)
    widths = [len(c) for c in cols]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    header = "  ".join(c.upper().ljust(widths[i]) for i, c in enumerate(cols))
    print(header)
    print("  ".join("-" * widths[i] for i in range(len(cols))))
    for r in rows:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(r)))
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")


def _emit(entries: "List[Entry]", as_json: bool, show_id: bool = True) -> None:
    if as_json:
        print(json.dumps([e.to_dict() for e in entries], indent=2))
    else:
        _print_table(entries, show_id=show_id)


def _sorted(entries: "List[Entry]") -> "List[Entry]":
    return sorted(entries, key=lambda e: (e.language, e.role, e.kind, e.symbol))


# -- subcommands -------------------------------------------------------------

def _cmd_list(cat: Catalog, role: str, args) -> int:
    entries = cat.find(
        language=args.language,
        role=role,
        kind=args.kind,
        package=args.package,
        cwe=args.cwe,
        confidence=args.confidence,
    )
    entries = _sorted(entries)
    if args.limit:
        entries = entries[: args.limit]
    _emit(entries, args.json)
    return 0


def _cmd_resolve(cat: Catalog, args) -> int:
    entries = cat.resolve(args.language, args.method, package=args.package, type=args.type)
    entries = _sorted(entries)
    if not entries and not args.json:
        print(
            f"no catalog fact attaches to {args.language} call {args.method!r}"
            + (f" (package={args.package})" if args.package else "")
            + (f" (type={args.type})" if args.type else "")
        )
        return 0
    _emit(entries, args.json)
    return 0


def _cmd_search(cat: Catalog, args) -> int:
    entries = _sorted(cat.search(args.text))
    if args.limit:
        entries = entries[: args.limit]
    _emit(entries, args.json)
    return 0


def _cmd_show(cat: Catalog, args) -> int:
    e = cat.get(args.id)
    if e is None:
        print(f"no entry with id {args.id!r}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(e.to_dict(include_source=True), indent=2))
        return 0
    d = e.to_dict(include_source=True)
    width = max(len(k) for k in d)
    for k, v in d.items():
        print(f"{k.rjust(width)} : {v}")
    return 0


def _cmd_stats(cat: Catalog, args) -> int:
    s = cat.stats()
    if args.json:
        print(json.dumps(s, indent=2, sort_keys=True))
        return 0
    print(f"Atropos catalog: {s['total']} facts across {', '.join(s['languages'])}\n")
    print("by language / role:")
    for key, n in s["by_language_role"].items():
        lang, role = key.split(":")
        print(f"  {lang:12} {role:10} {n}")
    print(f"\nby kind ({s['kinds']} kinds):")
    for kind, n in s["by_kind"].items():
        print(f"  {kind:26} {n}")
    return 0


def _cmd_kinds(cat: Catalog, args) -> int:
    kinds = cat.kinds(language=args.language)
    if args.json:
        print(json.dumps(kinds, indent=2))
        return 0
    for k in kinds:
        print(k)
    return 0


def _cmd_packages(cat: Catalog, args) -> int:
    pkgs = cat.packages(language=args.language)
    if args.json:
        print(json.dumps(pkgs, indent=2))
        return 0
    for p in pkgs:
        print(p)
    return 0


def _cmd_cwes(cat: Catalog, args) -> int:
    cwes = cat.cwes()
    if args.json:
        print(json.dumps(cwes, indent=2))
        return 0
    for c in cwes:
        print(c)
    return 0


def _cmd_export(cat: Catalog, args) -> int:
    entries = _sorted(
        cat.find(language=args.language, role=args.role, kind=args.kind)
    )
    text = _render_export(entries, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"wrote {len(entries)} entries to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _render_export(entries: "List[Entry]", fmt: str) -> str:
    if fmt == "json":
        return json.dumps([e.to_dict() for e in entries], indent=2) + "\n"
    if fmt == "jsonl":
        return "".join(json.dumps(e.to_dict()) + "\n" for e in entries)
    if fmt == "csv":
        buf = io.StringIO()
        cols = [
            "id", "language", "package", "type", "method", "access_path",
            "role", "kind", "cwe", "confidence", "corroboration",
        ]
        writer = csv.writer(buf)
        writer.writerow(cols)
        for e in entries:
            d = e.to_dict()
            d["cwe"] = ";".join(d.get("cwe") or [])
            writer.writerow([d.get(c, "") if d.get(c) is not None else "" for c in cols])
        return buf.getvalue()
    raise ValueError(f"unknown export format {fmt!r}")


def _cmd_detection(cat: Catalog, args) -> int:
    try:
        d = load_detection(args.root)
    except (CatalogNotFound, ValueError) as error:
        print(f"detection layer unavailable: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(d, indent=2, sort_keys=True))
        return 0
    print(f"evaluators ({len(d['evaluators'])}): {', '.join(sorted(d['evaluators']))}")
    print(f"\nkind -> evaluator ({len(d['kind_evaluator'])} kinds):")
    for kind, ev in sorted(d["kind_evaluator"].items()):
        target = ev if isinstance(ev, str) else ", ".join(ev)
        print(f"  {kind:26} -> {target}")
    for vocab, bridge in d["role_bridges"].items():
        print(f"\nrole bridge [{vocab}] ({len(bridge)} roles):")
        for role, kind in sorted(bridge.items()):
            print(f"  {role:28} -> {kind}")
    return 0


def _cmd_where(cat: Catalog, args) -> int:
    root = find_catalog_root(args.root)
    info = {
        "catalog_root": str(root),
        "pack_version": pack_version(root),
        "package_version": __version__,
        "total_facts": len(cat),
        "languages": cat.languages(),
    }
    if args.json:
        print(json.dumps(info, indent=2, sort_keys=True))
        return 0
    for k, v in info.items():
        print(f"{k}: {v}")
    return 0


# -- argument parser ---------------------------------------------------------

def _add_filters(p: argparse.ArgumentParser) -> None:
    p.add_argument("--language", "-l", help="c | python | javascript | typescript")
    p.add_argument("--kind", "-k", help="vulnerability subclass, e.g. sql-injection")
    p.add_argument("--package", "-p", help="owning module/package")
    p.add_argument("--cwe", help="CWE id, e.g. CWE-89 or 89")
    p.add_argument("--confidence", choices=["high", "medium", "low"])
    p.add_argument("--limit", type=int, default=0, help="cap the number of rows")
    p.add_argument("--json", action="store_true", help="emit JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atropos",
        description="Query the Atropos taint-model catalog (sinks, sources, "
        "sanitizers, flow summaries). Pure data; no security verdicts.",
    )
    parser.add_argument("--version", action="version", version=f"atropos {__version__}")
    parser.add_argument(
        "--root",
        help="catalog root override (else ATROPOS_ROOT, a checkout, or a bundled copy)",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    for role, name in (
        ("sink", "sinks"),
        ("source", "sources"),
        ("sanitizer", "sanitizers"),
        ("summary", "summaries"),
    ):
        sp = sub.add_parser(name, help=f"list {name}")
        _add_filters(sp)
        sp.set_defaults(func=lambda cat, args, r=role: _cmd_list(cat, r, args))

    sp = sub.add_parser("resolve", help="map a concrete call to the facts on it")
    sp.add_argument("language")
    sp.add_argument("method")
    sp.add_argument("--package", "-p")
    sp.add_argument("--type", "-t", help="receiver type for a member call")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_resolve)

    sp = sub.add_parser("search", help="free-text search over id/symbol/kind/notes")
    sp.add_argument("text")
    sp.add_argument("--limit", type=int, default=0)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_search)

    sp = sub.add_parser("show", help="print one entry by id")
    sp.add_argument("id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_show)

    sp = sub.add_parser("stats", help="coverage snapshot")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_stats)

    sp = sub.add_parser("kinds", help="list vulnerability kinds")
    sp.add_argument("--language", "-l")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_kinds)

    sp = sub.add_parser("packages", help="list packages/modules covered")
    sp.add_argument("--language", "-l")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_packages)

    sp = sub.add_parser("cwes", help="list CWE ids covered")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_cwes)

    sp = sub.add_parser("export", help="dump entries as json / jsonl / csv")
    sp.add_argument("--language", "-l")
    sp.add_argument("--role", choices=["sink", "source", "sanitizer", "summary"])
    sp.add_argument("--kind", "-k")
    sp.add_argument("--format", "-f", choices=["json", "jsonl", "csv"], default="json")
    sp.add_argument("--output", "-o", help="write to a file instead of stdout")
    sp.set_defaults(func=_cmd_export)

    sp = sub.add_parser("detection", help="show the kind->evaluator recipe layer")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_detection)

    sp = sub.add_parser("where", help="show the catalog root and versions")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_where)

    return parser


def main(argv: "Optional[List[str]]" = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        cat = load(args.root)
    except CatalogNotFound as error:
        print(f"atropos: {error}", file=sys.stderr)
        return 2
    return args.func(cat, args)


if __name__ == "__main__":
    raise SystemExit(main())
