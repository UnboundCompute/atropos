"""Atropos -- a taint-model knowledge base you can query directly.

Atropos is pure, declarative data: a curated catalog of taint facts keyed by symbol
and access path. Each fact says where untrusted data *enters* (a source), where it
*must not land* (a sink), and what makes it *safe again* (a sanitizer), and exactly
which argument or return value to watch. There is no analysis engine here -- an entry
tells a consumer "watch this," never "this is a bug."

Quick start::

    import atropos

    cat = atropos.load()                       # discover and read the catalog
    print(len(cat), "facts across", cat.languages())

    for s in cat.find(language="python", kind="command-injection"):
        print(s.symbol, s.access_path, s.cwe)

    # what does a concrete call map to?
    for e in cat.resolve("javascript", "exec", package="child_process"):
        print(e.role, e.kind, e.access_path)

The command-line tool exposes the same queries: ``atropos --help``.
"""
from __future__ import annotations

from ._version import __version__
from .catalog import Catalog, Entry, load
from .detection import load_detection
from .loader import CatalogNotFound, find_catalog_root, pack_version

__all__ = [
    "__version__",
    "Catalog",
    "Entry",
    "load",
    "load_detection",
    "find_catalog_root",
    "pack_version",
    "CatalogNotFound",
]
