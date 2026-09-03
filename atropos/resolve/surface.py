"""Threat-surface view: co-locate where untrusted input *enters* with where it must
not *land*, per file.

Atropos has no engine, so it cannot prove that a source flows to a sink. What it can
do cheaply and honestly is point at the files that hold *both* -- a catalogued source
(a request parameter, an environment read, a socket recv) and a catalogued sink
(exec, a query, a copy) in the same file. That co-location is not a bug; it is where
a reviewer, or a real taint engine, should look first, because a same-file source and
sink is the precondition for the shortest kind of flow.

The report ranks files by that pairing and lists the sources and sinks each holds, so
"audit the attack surface" becomes a worklist instead of a wall of findings.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from ..catalog import Catalog
from .engine import Auditor
from .model import AuditReport, Finding


def _entry_label(f: Finding) -> str:
    loc = "%s:%d" % (f.site.file, f.site.line)
    return "%s [%s] @ %s" % (f.entry.symbol, f.entry.kind, loc)


def build(auditor_catalog: Catalog, root: str, min_match: str = "heuristic") -> Dict:
    """Audit ``root`` for both sources and sinks and return a per-file surface report,
    ranked so files holding both a source and a sink come first."""
    auditor = Auditor(auditor_catalog, roles=["source", "sink"], min_match=min_match)
    report: AuditReport = auditor.audit_path(root)

    per_file: Dict[str, Dict[str, List[Finding]]] = defaultdict(
        lambda: {"source": [], "sink": []}
    )
    for f in report.findings:
        if f.entry.role in ("source", "sink"):
            per_file[f.site.file][f.entry.role].append(f)

    files = []
    for path, roles in per_file.items():
        srcs, sinks = roles["source"], roles["sink"]
        files.append({
            "file": path,
            "sources": len(srcs),
            "sinks": len(sinks),
            "both": bool(srcs) and bool(sinks),
            "source_symbols": sorted({f.entry.symbol for f in srcs}),
            "sink_kinds": sorted({f.entry.kind for f in sinks}),
            "sink_symbols": sorted({f.entry.symbol for f in sinks}),
        })
    # Rank: files with both first, then by total surface (sources * sinks captures
    # pairing density), then by name for stability.
    files.sort(key=lambda d: (not d["both"], -(d["sources"] * d["sinks"]),
                              -(d["sources"] + d["sinks"]), d["file"]))

    return {
        "files_scanned": report.files_scanned,
        "files_skipped": report.files_skipped,
        "files_with_both": sum(1 for d in files if d["both"]),
        "files": files,
    }


def render_text(surface: Dict, top: int = 25) -> "List[str]":
    out: List[str] = []
    out.append("Threat surface over %d files: %d hold both a source and a sink" % (
        surface["files_scanned"], surface["files_with_both"],
    ))
    both = [d for d in surface["files"] if d["both"]][:top]
    if both:
        out.append("\nfiles where untrusted input enters and a sink exists "
                   "(review first):")
        for d in both:
            out.append("  %s  (%d source, %d sink)" % (d["file"], d["sources"], d["sinks"]))
            out.append("      sources: " + ", ".join(d["source_symbols"]))
            out.append("      sinks:   " + ", ".join(d["sink_kinds"]))
    else:
        out.append("\nno file holds both a catalogued source and sink.")
    return out
