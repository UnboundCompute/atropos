"""Aggregate an :class:`~atropos.resolve.model.AuditReport` into a coverage summary.

The audit answers "where is each catalogued symbol used"; this rolls that up into
"what does this codebase's attack surface look like, through the catalog's eyes" --
counts by vulnerability kind, by language, by role, and by binding confidence, the
symbols that appear most, and the files that carry the most findings. It also names
the *gap*: which catalogued kinds (for the languages actually present in the target)
never appeared, so a reviewer can tell an genuinely clean class from one the catalog
simply does not model here.

Like everything in this layer it is measurement, not a verdict: a hot file is where
to look first, not where a bug is proven to be.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List

from ..catalog import Catalog
from .model import AuditReport


def summarize(report: AuditReport, catalog: Catalog, top: int = 15) -> Dict:
    """Return a JSON-serialisable coverage summary of ``report``."""
    findings = report.findings
    by_kind = Counter(f.entry.kind for f in findings)
    by_language = Counter(f.entry.language for f in findings)
    by_role = Counter(f.entry.role for f in findings)
    by_match = Counter(f.match for f in findings)
    by_symbol = Counter(f.entry.symbol for f in findings)
    by_file = Counter(f.site.file for f in findings)

    # The gap: catalogued kinds available for the languages present here that this
    # target never exercised. Scope to observed languages so the gap is meaningful
    # (a C target should not be "missing" JS-only kinds).
    langs = set(by_language)
    catalog_kinds = {
        e.kind for e in catalog.entries
        if e.role == "sink" and (not langs or e.language in langs)
    }
    unseen = sorted(catalog_kinds - set(by_kind))

    return {
        "files_scanned": report.files_scanned,
        "files_skipped": report.files_skipped,
        "total_findings": len(findings),
        "by_confidence": dict(by_match),
        "by_language": dict(by_language),
        "by_role": dict(by_role),
        "by_kind": dict(by_kind.most_common()),
        "top_symbols": by_symbol.most_common(top),
        "hottest_files": by_file.most_common(top),
        "unexercised_sink_kinds": unseen,
    }


def render_text(summary: Dict) -> "List[str]":
    """Human-readable coverage report as a list of lines."""
    out: List[str] = []
    out.append("Coverage over %d files (%d skipped): %d findings" % (
        summary["files_scanned"], summary["files_skipped"], summary["total_findings"],
    ))
    conf = summary["by_confidence"]
    out.append("  by confidence: " + ", ".join(
        "%d %s" % (conf[m], m) for m in ("exact", "heuristic", "name-only") if conf.get(m)
    ) or "  by confidence: -")

    def _bar(title: str, counts: Dict) -> None:
        if not counts:
            return
        out.append("\n%s:" % title)
        width = max((len(str(k)) for k in counts), default=0)
        for key, n in sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0]))):
            out.append("  %s  %d" % (str(key).ljust(width), n))

    _bar("by language", summary["by_language"])
    _bar("by role", summary["by_role"])
    _bar("by kind", dict(summary["by_kind"]))

    if summary["top_symbols"]:
        out.append("\ntop symbols:")
        width = max(len(s) for s, _ in summary["top_symbols"])
        for sym, n in summary["top_symbols"]:
            out.append("  %s  %d" % (sym.ljust(width), n))

    if summary["hottest_files"]:
        out.append("\nhottest files:")
        for path, n in summary["hottest_files"]:
            out.append("  %4d  %s" % (n, path))

    unseen = summary["unexercised_sink_kinds"]
    if unseen:
        out.append("\nunexercised sink kinds (catalogued for the languages present, "
                   "not seen here): " + ", ".join(unseen))
    return out
