"""The Auditor: walk a target codebase, extract call sites, and join each one to
the catalog facts that attach to it.

This is the join half of the resolver. It owns no taint reasoning -- it decides,
per candidate fact, whether a found call site *is* the catalogued symbol and how
sure it is (see the ``MATCH_*`` spectrum), then points the fact at the concrete
argument / receiver / return slot named by its access path. Whether tainted data
actually reaches that slot is left to the engine and the reviewer; the Auditor
only enumerates where the catalogued symbols are used.

Matching, in one paragraph. The catalog has three shapes of entry: *flat* ones
(no package, no type: C builtins, language globals like ``eval``), *package*-typed
ones (module functions like ``os.system``), and *type*-typed ones (receiver methods
like ``Cursor.execute``). A call site is one of: *module-resolved* (a scanner tied
the receiver or a bare name to an imported module), a *method* call on an
unresolved receiver, or a *bare* call. The confidence is the honest strength of the
weakest confirmed thing: a module-resolved site against a matching package entry is
``exact``; a bare call against a flat entry is ``exact``; a method call against a
type entry is ``heuristic`` (the name and shape fit but the receiver type is
unconfirmed); anything that matches on name alone with the shape unconfirmed is
``name-only`` -- reported so nothing is silently dropped, but easy to filter.
"""
from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional

from ..catalog import Catalog, Entry
from . import generic_scanner, python_scanner
from .model import (
    AuditReport,
    CallSite,
    Finding,
    MATCH_EXACT,
    MATCH_HEURISTIC,
    MATCH_NAME_ONLY,
    _MATCH_RANK,
)

# File extension -> catalog language. Only these are scanned.
_EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".c": "c", ".h": "c",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
}

# Directories never worth walking: vendored code, VCS metadata, build output.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".tox", "vendor",
    "site-packages", ".idea", ".vscode",
}

_ARG_RE = re.compile(r"Argument\[(\d+)\]")


def _focus(entry: Entry, site: CallSite):
    """Return (focus phrase, focused source text) for an entry's access path."""
    ap = entry.access_path
    m = _ARG_RE.fullmatch(ap)
    if m:
        n = int(m.group(1))
        expr = site.args[n] if 0 <= n < len(site.args) else None
        return "argument %d" % n, expr
    if ap == "Receiver":
        return "receiver", site.receiver
    if ap == "ReturnValue":
        return "return value", None
    return ap, None  # unusual/summary-shaped path: surface it verbatim


def _classify(entry: Entry, site: CallSite) -> Optional[str]:
    """Decide whether ``entry`` matches ``site`` and at what confidence, or ``None``
    if it does not apply to this call's shape at all."""
    # Flat = nameable with no receiver: a C builtin, a language global. Python
    # builtins carry package "builtins" but are equally in scope without import,
    # so a bare call to one binds exactly, not by name alone.
    flat = (entry.package is None and entry.type is None) or entry.package == "builtins"

    if site.module is not None:
        # The scanner pinned the receiver/name to a module. Only a package entry for
        # that exact module applies, and it binds exactly.
        if entry.package is not None:
            return MATCH_EXACT if entry.package == site.module else None
        return None  # flat/type entries don't describe a resolved module call

    if site.is_method:
        # recv.method() with an unresolved receiver type.
        if entry.type is not None:
            return MATCH_HEURISTIC  # right name and member shape, type unconfirmed
        if entry.package is not None:
            return MATCH_NAME_ONLY  # could be an unresolved module import
        return MATCH_NAME_ONLY      # flat name on an unexpected receiver: weak

    # A bare call: name(...).
    if flat:
        return MATCH_EXACT          # exactly the flat-builtin / global shape
    return MATCH_NAME_ONLY          # a module/receiver symbol called bare: unconfirmed


class Auditor:
    """Joins scanned call sites to catalog facts. Reusable across many targets."""

    def __init__(
        self,
        catalog: Catalog,
        roles: Optional[Iterable[str]] = None,
        min_match: str = MATCH_NAME_ONLY,
        include_summaries: bool = False,
    ):
        self.catalog = catalog
        self.roles = set(roles) if roles else None
        self._max_rank = _MATCH_RANK.get(min_match, 2)
        # By default a summary-shaped access path (``in -> out``) is skipped: it
        # names a propagation, not a watchpoint. A presence check (e.g. sanitizer
        # conformance) wants the call recorded regardless, so it opts in here.
        self._include_summaries = include_summaries

    # -- per-site join -------------------------------------------------------

    def match_site(self, site: CallSite, language: str) -> "List[Finding]":
        out: List[Finding] = []
        for entry in self.catalog.resolve(language, site.callee):
            if self.roles is not None and entry.role not in self.roles:
                continue
            if entry.role == "summary":
                continue  # the summary role is propagation modelling, never a site
            if "->" in entry.access_path and not self._include_summaries:
                continue  # a summary-shaped path is propagation, not a watchpoint
            match = _classify(entry, site)
            if match is None or _MATCH_RANK[match] > self._max_rank:
                continue
            focus, expr = _focus(entry, site)
            out.append(Finding(entry=entry, site=site, match=match,
                               focus=focus, focus_expr=expr))
        return out

    # -- scanning ------------------------------------------------------------

    def _scan_source(self, path: str, language: str, source: str) -> "List[CallSite]":
        if language == "python":
            return python_scanner.scan(path, source)
        return generic_scanner.scan(path, source, language)

    def audit_source(self, path: str, language: str, source: str,
                     report: AuditReport) -> None:
        try:
            sites = self._scan_source(path, language, source)
        except SyntaxError as exc:
            report.files_skipped += 1
            report.errors.append("%s: parse error: %s" % (path, exc))
            return
        report.files_scanned += 1
        for site in sites:
            report.findings.extend(self.match_site(site, language))

    def audit_file(self, path: str, report: AuditReport,
                   language: Optional[str] = None) -> None:
        if language is None:
            language = _EXT_LANG.get(os.path.splitext(path)[1].lower())
        if language is None:
            report.files_skipped += 1
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError as exc:
            report.files_skipped += 1
            report.errors.append("%s: %s" % (path, exc))
            return
        self.audit_source(path, language, source, report)

    def audit_path(self, root: str) -> AuditReport:
        """Audit a single file or a directory tree, returning one report."""
        report = AuditReport()
        if os.path.isfile(root):
            self.audit_file(root, report)
            return report
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext in _EXT_LANG:
                    self.audit_file(os.path.join(dirpath, name), report)
        return report
