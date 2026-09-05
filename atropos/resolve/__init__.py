"""Resolver / enumerator: join the catalog's symbol facts to concrete call sites
in a target codebase.

This subpackage is the reader half of Atropos in action. Language scanners turn
source into :class:`~atropos.resolve.model.CallSite` records with no catalog
knowledge; the :class:`~atropos.resolve.engine.Auditor` joins each site to the
catalog via :meth:`~atropos.catalog.Catalog.resolve` and emits
:class:`~atropos.resolve.model.Finding` records. It enumerates where catalogued
symbols are *used* -- it does not decide whether tainted data reaches them.
"""
from __future__ import annotations

from .model import (
    AuditReport,
    CallSite,
    Finding,
    MATCH_EXACT,
    MATCH_HEURISTIC,
    MATCH_NAME_ONLY,
)

__all__ = [
    "AuditReport",
    "CallSite",
    "Finding",
    "MATCH_EXACT",
    "MATCH_HEURISTIC",
    "MATCH_NAME_ONLY",
]
