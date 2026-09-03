"""Grounding layer: use the curated catalog as retrieval context and as a validation
oracle for a language model reasoning about taint.

A model asked "is this a SQL-injection sink?" or "what sanitizes CWE-79?" will answer
fluently whether or not it is right. This layer gives it, and lets it be checked
against, a curated set of facts instead of its own recall:

* :func:`retrieve` pulls the catalog facts relevant to a query (a CWE, a kind, a
  symbol, or free text) and formats them as a compact, quotable grounding block --
  the sinks with the exact slot to watch, plus the sanitizers and sources catalogued
  for the same kind -- suitable to drop into a prompt as ground truth.
* :func:`validate` takes a fact a model *proposed* (a symbol, an access path, a role)
  and adjudicates it against the catalog: confirmed, a partial match at a different
  watchpoint, a role conflict, or unknown. This is how a proposed sink is grounded
  before it is trusted, and how a hallucinated one is caught.

No taint reasoning and no verdict about a *program*: this grounds claims about the
*catalog's* knowledge, nothing more.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from .catalog import Catalog, Entry


def _norm_cwe(cwe: str) -> str:
    s = str(cwe).strip().upper()
    if s.startswith("CWE-"):
        return s
    if s.isdigit():
        return "CWE-" + s
    return s


def _entries_for(catalog: Catalog, cwe: Optional[str], kind: Optional[str],
                 language: Optional[str], text: Optional[str]) -> "List[Entry]":
    if cwe:
        want = _norm_cwe(cwe)
        out = [e for e in catalog.entries if want in (e.cwe or [])]
    elif kind:
        out = [e for e in catalog.entries if e.kind == kind]
    elif text:
        out = catalog.search(text)
    else:
        out = list(catalog.entries)
    if language:
        out = [e for e in out if e.language == language]
    return out


def retrieve(catalog: Catalog, text: Optional[str] = None, cwe: Optional[str] = None,
             kind: Optional[str] = None, language: Optional[str] = None,
             limit: int = 40) -> Dict:
    """Return catalog facts relevant to a query, grouped by kind, as grounding
    context for a language model."""
    entries = _entries_for(catalog, cwe, kind, language, text)
    by_kind: Dict[str, Dict[str, List[Entry]]] = defaultdict(
        lambda: {"sink": [], "source": [], "sanitizer": [], "summary": []}
    )
    for e in entries:
        by_kind[e.kind].setdefault(e.role, []).append(e)

    grounding = {}
    for k in sorted(by_kind):
        roles = by_kind[k]
        cwes = sorted({c for r in roles.values() for e in r for c in (e.cwe or [])})

        def _fmt(items: "List[Entry]") -> "List[Dict]":
            seen = []
            for e in sorted(items, key=lambda x: (x.symbol, x.access_path))[:limit]:
                seen.append({
                    "id": e.id, "language": e.language, "symbol": e.symbol,
                    "access_path": e.access_path, "confidence": e.confidence,
                })
            return seen

        grounding[k] = {
            "cwe": cwes,
            "sinks": _fmt(roles.get("sink", [])),
            "sanitizers": _fmt(roles.get("sanitizer", [])),
            "sources": _fmt(roles.get("source", [])),
        }
    return {
        "query": {"text": text, "cwe": cwe, "kind": kind, "language": language},
        "match_count": len(entries),
        "grounding": grounding,
    }


def render_context(ground: Dict) -> str:
    """Render a retrieval result as a compact prompt-ready grounding block."""
    lines: List[str] = []
    q = ground["query"]
    label = q["cwe"] or q["kind"] or q["text"] or "the catalog"
    lines.append("Grounded taint facts from the Atropos catalog for %s "
                 "(%d matching facts). Treat these as authoritative; do not invent "
                 "symbols outside them:" % (label, ground["match_count"]))
    for kind, g in ground["grounding"].items():
        cwe = ", ".join(g["cwe"]) if g["cwe"] else "-"
        lines.append("\n%s (%s):" % (kind, cwe))
        if g["sinks"]:
            lines.append("  sinks (watch the named slot):")
            for s in g["sinks"]:
                lines.append("    - %s  %s  [%s]" % (s["symbol"], s["access_path"], s["language"]))
        if g["sanitizers"]:
            lines.append("  sanitizers (neutralize the flow):")
            for s in g["sanitizers"]:
                lines.append("    - %s  %s  [%s]" % (s["symbol"], s["access_path"], s["language"]))
        if g["sources"]:
            lines.append("  sources (untrusted input):")
            for s in g["sources"]:
                lines.append("    - %s  %s  [%s]" % (s["symbol"], s["access_path"], s["language"]))
    return "\n".join(lines)


# -- validation oracle -------------------------------------------------------

# Verdicts a proposed fact can receive against the catalog.
V_CONFIRMED = "confirmed"        # same symbol, role, and access path -- a known fact
V_PARTIAL = "partial"            # symbol+role known, but at a different watchpoint
V_ROLE_CONFLICT = "role-conflict"  # symbol known, catalogued under a different role
V_UNKNOWN = "unknown"            # symbol not in the catalog for this language


def validate(catalog: Catalog, language: str, method: str,
             access_path: Optional[str] = None, role: Optional[str] = None,
             package: Optional[str] = None, type: Optional[str] = None,
             cwe: Optional[str] = None) -> Dict:
    """Adjudicate a proposed sink/source against the catalog. ``method`` is the bare
    callee (``system``), ``package``/``type`` narrow it when known."""
    candidates = catalog.resolve(language, method, package=package, type=type)
    result = {
        "proposal": {
            "language": language, "method": method, "package": package,
            "type": type, "access_path": access_path, "role": role, "cwe": cwe,
        },
        "verdict": V_UNKNOWN,
        "evidence": [],
        "note": "",
    }
    if not candidates:
        result["note"] = ("no catalog fact for this symbol; it may be a genuine gap "
                          "or a hallucination -- corroborate before trusting.")
        return result

    ev = [{"id": e.id, "symbol": e.symbol, "role": e.role,
           "access_path": e.access_path, "kind": e.kind, "cwe": list(e.cwe or [])}
          for e in candidates]
    result["evidence"] = ev

    same_role = [e for e in candidates if role is None or e.role == role]
    exact = [e for e in same_role if access_path is None or e.access_path == access_path]
    if exact:
        result["verdict"] = V_CONFIRMED
        result["note"] = "matches catalogued fact %s." % exact[0].id
        if cwe and _norm_cwe(cwe) not in (exact[0].cwe or []):
            have = ", ".join(exact[0].cwe or []) or "none"
            result["note"] += " CWE differs: catalog has %s." % have
        return result
    if same_role:
        result["verdict"] = V_PARTIAL
        aps = sorted({e.access_path for e in same_role})
        result["note"] = ("symbol and role are catalogued, but at %s, not %r."
                          % (", ".join(aps), access_path))
        return result
    # symbol exists but under other roles only
    result["verdict"] = V_ROLE_CONFLICT
    roles = sorted({e.role for e in candidates})
    result["note"] = ("symbol is catalogued as %s, not %r."
                      % (", ".join(roles), role))
    return result
