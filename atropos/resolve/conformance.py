"""Sanitizer-conformance view: for each sink kind a codebase actually exercises, does
a sanitizer catalogued for that kind appear in the codebase at all?

Atropos has no engine, so it cannot prove that a sanitizer guards a particular sink on
a particular path -- that needs flow reasoning this layer deliberately does not do.
What it *can* do cheaply and honestly is a hygiene check at the granularity of a whole
target: the catalog knows, per kind, which symbols neutralize the flow (an escaper, a
parameterizer, a coercion). For every kind whose sinks are used here, this reports
whether any of those catalogued sanitizers is used here too.

The three outcomes are, honestly:

* ``no-sanitizer-seen``  -- sinks of this kind are used and the catalog models a
  sanitizer for it, but none appears anywhere in the target. The actionable flag: the
  neutralizer the catalog knows about is absent from the code.
* ``sanitizer-present``  -- a catalogued sanitizer for the kind does appear. This is
  NOT proof any sink is guarded (no flow is traced); it means the tool exists in the
  codebase and the sinks are worth a closer, path-aware look rather than a blind flag.
* ``no-sanitizer-modeled`` -- sinks are used but the catalog models no sanitizer for
  the kind (for the languages present), so conformance cannot be assessed here; a
  catalog gap, not a code finding.

Same discipline as the surface view: co-occurrence is a lead, never a verdict.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from ..catalog import Catalog
from .engine import Auditor
from .model import AuditReport, Finding

# Conformance outcomes for a sink kind exercised by the target.
C_NO_SANITIZER_SEEN = "no-sanitizer-seen"      # sinks used, sanitizer modeled, none in code
C_SANITIZER_PRESENT = "sanitizer-present"      # a catalogued sanitizer for the kind appears
C_NO_SANITIZER_MODELED = "no-sanitizer-modeled"  # sinks used, catalog models no sanitizer

_RANK = {C_NO_SANITIZER_SEEN: 0, C_NO_SANITIZER_MODELED: 1, C_SANITIZER_PRESENT: 2}


def build(catalog: Catalog, root: str, min_match: str = "heuristic") -> Dict:
    """Audit ``root`` for sinks and sanitizers and report, per sink kind used, whether
    a sanitizer catalogued for that kind is also used in the target."""
    # include_summaries: a sanitizer is catalogued as a propagation (``in -> out``),
    # so it only surfaces as a call site when summary-shaped paths are kept. This is a
    # presence check -- the sanitizer being *called* is the signal, not which slot.
    auditor = Auditor(catalog, roles=["sink", "sanitizer"], min_match=min_match,
                      include_summaries=True)
    report: AuditReport = auditor.audit_path(root)

    sinks_by_kind: Dict[str, List[Finding]] = defaultdict(list)
    sanitizers_by_kind: Dict[str, List[Finding]] = defaultdict(list)
    langs: Set[str] = set()
    for f in report.findings:
        langs.add(f.entry.language)
        if f.entry.role == "sink":
            sinks_by_kind[f.entry.kind].append(f)
        elif f.entry.role == "sanitizer":
            sanitizers_by_kind[f.entry.kind].append(f)

    kinds = []
    for kind in sorted(sinks_by_kind):
        sink_findings = sinks_by_kind[kind]
        # Sanitizers the catalog models for this kind, scoped to languages present so a
        # C target is not judged against a Python-only sanitizer.
        modeled = [
            e for e in catalog.find(role="sanitizer", kind=kind)
            if not langs or e.language in langs
        ]
        used = sanitizers_by_kind.get(kind, [])
        if used:
            status = C_SANITIZER_PRESENT
        elif modeled:
            status = C_NO_SANITIZER_SEEN
        else:
            status = C_NO_SANITIZER_MODELED
        kinds.append({
            "kind": kind,
            "status": status,
            "sinks_used": len(sink_findings),
            "sink_symbols": sorted({f.entry.symbol for f in sink_findings}),
            "sanitizers_modeled": sorted({e.symbol for e in modeled}),
            "sanitizers_used": sorted({f.entry.symbol for f in used}),
        })
    # Most actionable first: absent-but-modeled, then unassessable, then present.
    kinds.sort(key=lambda d: (_RANK[d["status"]], -d["sinks_used"], d["kind"]))

    return {
        "files_scanned": report.files_scanned,
        "files_skipped": report.files_skipped,
        "languages": sorted(langs),
        "kinds_with_sinks": len(kinds),
        "flagged": sum(1 for d in kinds if d["status"] == C_NO_SANITIZER_SEEN),
        "kinds": kinds,
    }


def render_text(conf: Dict) -> "List[str]":
    out: List[str] = []
    out.append("Sanitizer conformance over %d files: %d sink kinds exercised, "
               "%d with no catalogued sanitizer present" % (
                   conf["files_scanned"], conf["kinds_with_sinks"], conf["flagged"],
               ))
    flagged = [d for d in conf["kinds"] if d["status"] == C_NO_SANITIZER_SEEN]
    if flagged:
        out.append("\nsink kinds used with NO catalogued sanitizer anywhere in the "
                   "code (review first):")
        for d in flagged:
            out.append("  %s  (%d sink use%s)" % (
                d["kind"], d["sinks_used"], "" if d["sinks_used"] == 1 else "s"))
            out.append("      sinks:      " + ", ".join(d["sink_symbols"]))
            out.append("      sanitizers: " + ", ".join(d["sanitizers_modeled"]))

    present = [d for d in conf["kinds"] if d["status"] == C_SANITIZER_PRESENT]
    if present:
        out.append("\nsink kinds where a catalogued sanitizer also appears "
                   "(co-located, not proven to guard):")
        for d in present:
            out.append("  %s: sinks {%s}  sanitizers seen {%s}" % (
                d["kind"], ", ".join(d["sink_symbols"]), ", ".join(d["sanitizers_used"])))

    unmodeled = [d for d in conf["kinds"] if d["status"] == C_NO_SANITIZER_MODELED]
    if unmodeled:
        out.append("\nsink kinds the catalog models no sanitizer for "
                   "(cannot assess): " + ", ".join(d["kind"] for d in unmodeled))
    return out
