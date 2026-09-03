"""Render an :class:`~atropos.resolve.model.AuditReport` as SARIF 2.1.0.

SARIF (Static Analysis Results Interchange Format, OASIS) is the lingua franca for
analysis results: GitHub code scanning, Azure DevOps, and most IDEs ingest it. This
renderer produces a full, valid 2.1.0 log, not a thin stub -- a driver with one
reporting *rule* per vulnerability kind, a CWE *taxonomy* with taxa referenced from
each rule, per-result physical locations with a source region, and stable
``partialFingerprints`` so the same finding matches itself across runs and code
scanning can track a lead over time.

The severity carried is honest about what Atropos is. A finding is a *lead* -- a
catalogued symbol is used here -- not an adjudicated bug, so sinks map to SARIF
level ``warning`` and sources/sanitizers to ``note``. Nothing here is emitted as
``error``: this layer makes no verdict.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List

from .._version import __version__
from .model import AuditReport, Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_INFO_URI = "https://github.com/UnboundCompute/atropos"
_CWE_URI = "https://cwe.mitre.org/data/definitions/%s.html"

_LEVEL_BY_ROLE = {"sink": "warning", "source": "note", "sanitizer": "note"}


def _uri_and_index(file: str, base_index: Dict[str, int]) -> Dict:
    if file not in base_index:
        base_index[file] = len(base_index)
    return {"uri": file}


def _fingerprint(f: Finding) -> str:
    key = "|".join([
        f.entry.id, f.site.file, str(f.site.line), str(f.site.col), f.entry.access_path,
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _cwe_taxa(findings: "List[Finding]") -> "List[Dict]":
    """One taxon per distinct CWE seen, for the CWE taxonomy component."""
    seen: Dict[str, Dict] = {}
    for f in findings:
        for cwe in f.entry.cwe or []:
            num = cwe.split("-")[-1]
            if cwe not in seen:
                seen[cwe] = {
                    "id": cwe,
                    "name": cwe,
                    "helpUri": _CWE_URI % num,
                }
    return [seen[k] for k in sorted(seen)]


def _rules(findings: "List[Finding]") -> "List[Dict]":
    """One reporting rule per vulnerability kind, with its CWE relationships."""
    by_kind: Dict[str, Finding] = {}
    kind_cwes: Dict[str, set] = {}
    for f in findings:
        by_kind.setdefault(f.entry.kind, f)
        kind_cwes.setdefault(f.entry.kind, set()).update(f.entry.cwe or [])
    rules = []
    for kind in sorted(by_kind):
        rel = [
            {
                "target": {"id": cwe, "toolComponent": {"name": "CWE"}},
                "kinds": ["relevant"],
            }
            for cwe in sorted(kind_cwes[kind])
        ]
        rules.append({
            "id": kind,
            "name": "".join(part.capitalize() for part in kind.split("-")),
            "shortDescription": {"text": "Use of a symbol catalogued for %s" % kind},
            "fullDescription": {
                "text": "A call site resolves to a symbol Atropos catalogues under "
                        "the %s kind. This is a lead to review, not a confirmed bug: "
                        "whether tainted data reaches the watched slot is not decided "
                        "here." % kind,
            },
            "helpUri": _INFO_URI,
            "defaultConfiguration": {"level": "warning"},
            "relationships": rel,
        })
    return rules


def _result(f: Finding, rule_index: Dict[str, int]) -> Dict:
    level = _LEVEL_BY_ROLE.get(f.entry.role, "warning")
    focus = f.focus + (" = %s" % f.focus_expr if f.focus_expr else "")
    text = "%s (%s): %s is catalogued as a %s %s; watch %s. Binding: %s." % (
        f.entry.symbol, f.entry.language, f.site.callee, f.entry.kind, f.entry.role,
        focus, f.match,
    )
    region = {"startLine": max(f.site.line, 1)}
    if f.site.col is not None:
        region["startColumn"] = f.site.col + 1
    if f.site.snippet:
        region["snippet"] = {"text": f.site.snippet}
    return {
        "ruleId": f.entry.kind,
        "ruleIndex": rule_index[f.entry.kind],
        "level": level,
        "message": {"text": text},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.site.file},
                "region": region,
            },
        }],
        "partialFingerprints": {"atroposMatch/v1": _fingerprint(f)},
        "properties": {
            "atroposId": f.entry.id,
            "match": f.match,
            "role": f.entry.role,
            "cwe": list(f.entry.cwe or []),
            "confidence": f.entry.confidence,
        },
    }


def to_sarif(report: AuditReport) -> Dict:
    """Return the SARIF 2.1.0 log for ``report`` as a JSON-serialisable dict."""
    findings = report.sorted()
    rules = _rules(findings)
    rule_index = {r["id"]: i for i, r in enumerate(rules)}
    taxa = _cwe_taxa(findings)

    driver = {
        "name": "Atropos",
        "informationUri": _INFO_URI,
        "version": __version__,
        "rules": rules,
    }
    tool = {"driver": driver}
    if taxa:
        tool["driver"]["supportedTaxonomies"] = [{"name": "CWE"}]

    run = {
        "tool": tool,
        "results": [_result(f, rule_index) for f in findings],
        "columnKind": "utf16CodeUnits",
    }
    if taxa:
        run["taxonomies"] = [{
            "name": "CWE",
            "organization": "MITRE",
            "shortDescription": {"text": "Common Weakness Enumeration"},
            "informationUri": "https://cwe.mitre.org/",
            "taxa": taxa,
        }]
    if report.errors:
        run["invocations"] = [{
            "executionSuccessful": True,
            "toolExecutionNotifications": [
                {"level": "warning", "message": {"text": e}} for e in report.errors
            ],
        }]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
