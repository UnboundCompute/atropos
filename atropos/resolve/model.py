"""The data the resolver produces: a call site found in source, and a finding that
joins that site to a catalog fact.

These are deliberately small, immutable records. A :class:`CallSite` is what a
language scanner emits -- a callee name, an optional receiver, the argument texts,
and a location -- with no catalog knowledge. A :class:`Finding` is the join: one
catalog :class:`~atropos.catalog.Entry` matched to one site, plus *how* confident
the match is and *which* slot (argument / receiver / return) the fact points at.

Nothing here makes a verdict. A finding says "the catalog says this call's argument
is a sink"; whether tainted data actually reaches it is the reviewer's call. The
resolver is an enumerator, not a taint engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from ..catalog import Entry

# How sure we are that a found call site is the catalogued symbol, independent of
# the catalog's own per-fact confidence:
#   exact      - the binding is pinned (a resolved module import, or a flat builtin)
#   heuristic  - the name matches and the shape is right, but the receiver type or
#                module could not be confirmed without type inference
#   name-only  - only the callee name matched; weakest, reported but easy to filter
MATCH_EXACT = "exact"
MATCH_HEURISTIC = "heuristic"
MATCH_NAME_ONLY = "name-only"

_MATCH_RANK = {MATCH_EXACT: 0, MATCH_HEURISTIC: 1, MATCH_NAME_ONLY: 2}


@dataclass(frozen=True)
class CallSite:
    """One call expression found in source, before any catalog knowledge is applied.

    ``receiver`` is the source text of the object a member call is invoked on
    (``os`` in ``os.system(...)``, ``cur`` in ``cur.execute(...)``); it is ``None``
    for a bare call. ``module`` is set only when a scanner could resolve the receiver
    (or a bare name) to an imported module -- that is what lets a module-function
    fact bind exactly rather than heuristically. ``args`` holds best-effort source
    snippets for each positional argument, so a finding can quote the dangerous one.
    """

    file: str
    line: int
    col: int
    callee: str
    receiver: Optional[str] = None
    module: Optional[str] = None
    args: Tuple[str, ...] = ()
    is_method: bool = False
    snippet: str = ""

    @property
    def arg_count(self) -> int:
        return len(self.args)


@dataclass(frozen=True)
class Finding:
    """A catalog fact matched to a concrete call site.

    ``match`` is the binding confidence (see the ``MATCH_*`` constants). ``focus`` is
    a human phrase for the slot the fact watches ("argument 0", "receiver", "return
    value"); ``focus_expr`` is that slot's source text when the scanner could recover
    it. ``entry`` is the untouched catalog row, so every field (kind, cwe, notes) is
    available to a renderer.
    """

    entry: Entry
    site: CallSite
    match: str
    focus: str
    focus_expr: Optional[str] = None

    @property
    def sort_key(self) -> tuple:
        # Group a report sensibly: by file, then position, then binding strength.
        return (
            self.site.file,
            self.site.line,
            self.site.col,
            _MATCH_RANK.get(self.match, 9),
            self.entry.id,
        )

    def to_dict(self) -> dict:
        """A flat, JSON-serialisable view suitable for --json output and pipelines."""
        return {
            "id": self.entry.id,
            "language": self.entry.language,
            "role": self.entry.role,
            "kind": self.entry.kind,
            "cwe": list(self.entry.cwe or []),
            "symbol": self.entry.symbol,
            "access_path": self.entry.access_path,
            "match": self.match,
            "focus": self.focus,
            "focus_expr": self.focus_expr,
            "file": self.site.file,
            "line": self.site.line,
            "col": self.site.col,
            "callee": self.site.callee,
            "receiver": self.site.receiver,
            "snippet": self.site.snippet,
            "confidence": self.entry.confidence,
            "notes": self.entry.notes,
        }


@dataclass
class AuditReport:
    """The result of auditing a target: the findings plus what was scanned."""

    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: List[str] = field(default_factory=list)

    def sorted(self) -> "List[Finding]":
        return sorted(self.findings, key=lambda f: f.sort_key)
