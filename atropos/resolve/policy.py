"""Project the catalog into a portable enforcement policy: a watch-list other tools
can bind without Atropos.

The audit/coverage/diff/surface modes all consume a *target*. This one consumes only
the catalog and emits the rules themselves -- one enforceable row per catalogued
symbol, shaped for a linter or a CI banned-API check: the symbol to match, the slot
to watch, the vulnerability kind and CWE, a severity tier, and a ready-to-show
message. A team that cannot run Atropos in CI can still load this JSON and enforce it
with whatever gate they already have.

Severity is a faithful function of the catalog, not a new judgment. A sink with high
catalog confidence is an ``error`` (a hard banned-API candidate); a lower-confidence
sink is a ``warning``; sources and sanitizers are ``note`` -- they are context a
review needs, not APIs to ban.
"""
from __future__ import annotations

from typing import Dict, List

from ..catalog import Catalog, Entry


def _severity(entry: Entry) -> str:
    if entry.role == "sink":
        return "error" if entry.confidence == "high" else "warning"
    return "note"


def _message(entry: Entry) -> str:
    return "%s: %s is a catalogued %s (%s); review the %s." % (
        entry.kind, entry.symbol, entry.role, entry.kind, entry.access_path,
    )


def _rule(entry: Entry) -> Dict:
    return {
        "id": entry.id,
        "language": entry.language,
        "symbol": entry.symbol,
        "method": entry.method,
        "package": entry.package,
        "type": entry.type,
        "access_path": entry.access_path,
        "role": entry.role,
        "kind": entry.kind,
        "cwe": list(entry.cwe or []),
        "severity": _severity(entry),
        "message": _message(entry),
    }


def build(catalog: Catalog, language: str = None, role: str = None,
          banned_only: bool = False) -> Dict:
    """Return the enforcement policy as a JSON-serialisable dict.

    ``banned_only`` keeps just the hard-ban tier (severity ``error``)."""
    rules: List[Dict] = []
    for entry in catalog.entries:
        if language and entry.language != language:
            continue
        if role and entry.role != role:
            continue
        if entry.role == "summary" or "->" in entry.access_path:
            continue
        rule = _rule(entry)
        if banned_only and rule["severity"] != "error":
            continue
        rules.append(rule)
    rules.sort(key=lambda r: (r["language"], r["severity"] != "error",
                              r["kind"], r["symbol"], r["access_path"]))
    by_sev: Dict[str, int] = {}
    for r in rules:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
    return {
        "policy": "atropos-watchlist/v1",
        "rule_count": len(rules),
        "by_severity": by_sev,
        "rules": rules,
    }


def render_text(policy: Dict) -> "List[str]":
    out: List[str] = []
    sev = policy["by_severity"]
    out.append("Enforcement policy: %d rules (%s)" % (
        policy["rule_count"],
        ", ".join("%d %s" % (sev[s], s) for s in ("error", "warning", "note") if sev.get(s)),
    ))
    cols = ("SEVERITY", "LANG", "SYMBOL", "ACCESS", "KIND")
    rows = [[r["severity"], r["language"], r["symbol"], r["access_path"], r["kind"]]
            for r in policy["rules"]]
    if not rows:
        out.append("(no rules)")
        return out
    widths = [len(c) for c in cols]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    out.append("  ".join(cols[i].ljust(widths[i]) for i in range(len(cols))))
    out.append("  ".join("-" * widths[i] for i in range(len(cols))))
    for row in rows:
        out.append("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return out
