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


def _render_audit(report, as_json: bool, limit: int) -> None:
    findings = report.sorted()
    if limit:
        findings = findings[:limit]
    if as_json:
        print(json.dumps({
            "files_scanned": report.files_scanned,
            "files_skipped": report.files_skipped,
            "findings": [f.to_dict() for f in findings],
            "errors": report.errors,
        }, indent=2))
        return
    if not findings:
        print(f"(no findings; scanned {report.files_scanned} files)")
        return
    cols = ("MATCH", "LANG", "SYMBOL", "KIND", "FOCUS", "LOCATION")
    rows = []
    for f in findings:
        rows.append([
            f.match,
            f.entry.language,
            f.entry.symbol,
            f.entry.kind,
            (f.focus + (f" = {f.focus_expr}" if f.focus_expr else "")),
            f"{f.site.file}:{f.site.line}",
        ])
    widths = [len(c) for c in cols]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    print("  ".join(cols[i].ljust(widths[i]) for i in range(len(cols))))
    print("  ".join("-" * widths[i] for i in range(len(cols))))
    for r in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)))
    by_match = {}
    for f in report.findings:
        by_match[f.match] = by_match.get(f.match, 0) + 1
    tally = ", ".join(f"{by_match[m]} {m}" for m in ("exact", "heuristic", "name-only") if by_match.get(m))
    print(f"\n{len(report.findings)} finding(s) [{tally}] across "
          f"{report.files_scanned} files ({report.files_skipped} skipped)")
    if report.errors:
        print(f"{len(report.errors)} file error(s); rerun with --json to see them",
              file=sys.stderr)


def _cmd_audit(cat: Catalog, args) -> int:
    import os as _os

    from .resolve.engine import Auditor  # local import: scanners only load on demand
    from .resolve.model import AuditReport

    roles = args.role or ["sink"]
    auditor = Auditor(cat, roles=roles, min_match=args.min_match)
    if args.language and _os.path.isfile(args.path):
        report = AuditReport()
        auditor.audit_file(args.path, report, language=args.language)
    else:
        report = auditor.audit_path(args.path)
    if args.kind:
        report.findings = [f for f in report.findings if f.entry.kind == args.kind]

    fmt = "json" if args.json else args.format
    if fmt == "sarif":
        from .resolve.sarif import to_sarif
        print(json.dumps(to_sarif(report), indent=2))
    else:
        _render_audit(report, fmt == "json", args.limit)
    return 0


def _cmd_coverage(cat: Catalog, args) -> int:
    from .resolve.engine import Auditor
    from .resolve.coverage import summarize, render_text

    roles = args.role or ["sink"]
    auditor = Auditor(cat, roles=roles, min_match=args.min_match)
    report = auditor.audit_path(args.path)
    summary = summarize(report, cat, top=args.top)
    if args.json:
        print(json.dumps(summary, indent=2))
        return 0
    for line in render_text(summary):
        print(line)
    return 0


def _cmd_ground(cat: Catalog, args) -> int:
    from .ground import retrieve, render_context

    result = retrieve(cat, text=args.text, cwe=args.cwe, kind=args.kind,
                      language=args.language, limit=args.limit or 40)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    if result["match_count"] == 0:
        print("no catalog facts match this query", file=sys.stderr)
        return 0
    print(render_context(result))
    return 0


def _cmd_validate(cat: Catalog, args) -> int:
    from .ground import validate

    result = validate(cat, args.language, args.method, access_path=args.access_path,
                      role=args.role, package=args.package, type=args.type, cwe=args.cwe)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"verdict: {result['verdict']}")
        if result["note"]:
            print(result["note"])
        for e in result["evidence"]:
            print(f"  {e['id']}  {e['symbol']}  {e['role']}  {e['access_path']}  {e['kind']}")
    # Non-confirmed proposals return non-zero so a pipeline can gate on grounding.
    return 0 if result["verdict"] in ("confirmed", "partial") else 1


def _cmd_rules(cat: Catalog, args) -> int:
    from .resolve.policy import build, render_text

    policy = build(cat, language=args.language, role=args.role,
                   banned_only=args.banned_only)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(policy, fh, indent=2)
        print(f"wrote {policy['rule_count']} rules to {args.output}", file=sys.stderr)
        return 0
    if args.json:
        print(json.dumps(policy, indent=2))
        return 0
    for line in render_text(policy):
        print(line)
    return 0


def _cmd_surface(cat: Catalog, args) -> int:
    from .resolve.surface import build, render_text

    surface = build(cat, args.path, min_match=args.min_match)
    if args.json:
        print(json.dumps(surface, indent=2))
        return 0
    for line in render_text(surface, top=args.top):
        print(line)
    return 0


def _cmd_diff(cat: Catalog, args) -> int:
    from .resolve.engine import Auditor
    from .resolve.model import AuditReport
    from .resolve.diff import diff as diff_findings

    try:
        with open(args.baseline, "r", encoding="utf-8") as fh:
            baseline_doc = json.load(fh)
    except (OSError, ValueError) as error:
        print(f"atropos: cannot read baseline {args.baseline!r}: {error}", file=sys.stderr)
        return 2
    if isinstance(baseline_doc, dict):
        baseline = baseline_doc.get("findings", baseline_doc.get("new", []))
    else:
        baseline = baseline_doc  # a bare list of finding dicts

    roles = args.role or ["sink"]
    auditor = Auditor(cat, roles=roles, min_match=args.min_match)
    report = auditor.audit_path(args.path)
    if args.kind:
        report.findings = [f for f in report.findings if f.entry.kind == args.kind]

    new, fixed = diff_findings(report.findings, baseline, min_match=args.min_match)
    new_report = AuditReport(findings=new, files_scanned=report.files_scanned,
                             files_skipped=report.files_skipped, errors=report.errors)
    if args.json:
        print(json.dumps({
            "new": [f.to_dict() for f in new_report.sorted()],
            "new_count": len(new),
            "fixed_count": fixed,
        }, indent=2))
    else:
        if new:
            print(f"{len(new)} new finding(s) vs baseline "
                  f"({fixed} no longer present):\n")
            _render_audit(new_report, False, args.limit)
        else:
            print(f"no new findings vs baseline ({fixed} no longer present)")
    if new and not args.exit_zero:
        return 1
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

    sp = sub.add_parser(
        "audit",
        help="enumerate catalogued symbol uses in a file or directory tree",
    )
    sp.add_argument("path", help="file or directory to scan")
    sp.add_argument("--language", "-l", help="force a language instead of by extension")
    sp.add_argument("--role", action="append",
                    choices=["sink", "source", "sanitizer"],
                    help="role(s) to enumerate (repeatable; default: sink)")
    sp.add_argument("--kind", "-k", help="restrict to one vulnerability kind")
    sp.add_argument("--min-match", choices=["exact", "heuristic", "name-only"],
                    default="heuristic",
                    help="weakest binding to report (default: heuristic)")
    sp.add_argument("--format", "-f", choices=["table", "json", "sarif"],
                    default="table", help="output format (default: table)")
    sp.add_argument("--limit", type=int, default=0)
    sp.add_argument("--json", action="store_true", help="alias for --format json")
    sp.set_defaults(func=_cmd_audit)

    sp = sub.add_parser(
        "ground",
        help="retrieve catalog facts as grounding context for a language model",
    )
    sp.add_argument("text", nargs="?", help="free-text query (symbol, term)")
    sp.add_argument("--cwe", help="ground on a CWE id, e.g. CWE-89 or 89")
    sp.add_argument("--kind", "-k", help="ground on a vulnerability kind")
    sp.add_argument("--language", "-l", help="restrict to one language")
    sp.add_argument("--limit", type=int, default=0, help="max facts per role (default 40)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_ground)

    sp = sub.add_parser(
        "validate",
        help="adjudicate a proposed sink/source against the catalog (grounding oracle)",
    )
    sp.add_argument("language")
    sp.add_argument("method", help="bare callee, e.g. system or execute")
    sp.add_argument("--access-path", "-a", help="e.g. Argument[0], Receiver, ReturnValue")
    sp.add_argument("--role", choices=["sink", "source", "sanitizer"])
    sp.add_argument("--package", "-p")
    sp.add_argument("--type", "-t", help="receiver type for a member call")
    sp.add_argument("--cwe")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_validate)

    sp = sub.add_parser(
        "rules",
        help="emit the catalog as a portable enforcement policy (lint / banned-API)",
    )
    sp.add_argument("--language", "-l", help="restrict to one language")
    sp.add_argument("--role", choices=["sink", "source", "sanitizer"],
                    help="restrict to one role")
    sp.add_argument("--banned-only", action="store_true",
                    help="only the hard-ban tier (severity error)")
    sp.add_argument("--output", "-o", help="write JSON to a file instead of stdout")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_rules)

    sp = sub.add_parser(
        "surface",
        help="rank files that hold both a catalogued source and sink (review worklist)",
    )
    sp.add_argument("path", help="file or directory to map")
    sp.add_argument("--min-match", choices=["exact", "heuristic", "name-only"],
                    default="heuristic", help="weakest binding to count")
    sp.add_argument("--top", type=int, default=25, help="files to list")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_surface)

    sp = sub.add_parser(
        "diff",
        help="fail on findings new since a recorded audit baseline (CI gate)",
    )
    sp.add_argument("path", help="file or directory to re-audit")
    sp.add_argument("--baseline", "-b", required=True,
                    help="a prior `audit --json` (or `diff --json`) file")
    sp.add_argument("--role", action="append",
                    choices=["sink", "source", "sanitizer"],
                    help="role(s) to enumerate (repeatable; default: sink)")
    sp.add_argument("--kind", "-k", help="restrict to one vulnerability kind")
    sp.add_argument("--min-match", choices=["exact", "heuristic", "name-only"],
                    default="heuristic",
                    help="weakest new binding that fails the gate (default: heuristic)")
    sp.add_argument("--exit-zero", action="store_true",
                    help="report new findings but always exit 0")
    sp.add_argument("--limit", type=int, default=0)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_diff)

    sp = sub.add_parser(
        "coverage",
        help="summarize catalogued symbol usage across a tree (kinds, hot files, gaps)",
    )
    sp.add_argument("path", help="file or directory to summarize")
    sp.add_argument("--role", action="append",
                    choices=["sink", "source", "sanitizer"],
                    help="role(s) to count (repeatable; default: sink)")
    sp.add_argument("--min-match", choices=["exact", "heuristic", "name-only"],
                    default="heuristic", help="weakest binding to count")
    sp.add_argument("--top", type=int, default=15, help="rows in the top-N lists")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_coverage)

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
