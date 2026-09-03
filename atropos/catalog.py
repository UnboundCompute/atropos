"""The in-memory catalog: typed entries and the queries a consumer actually asks.

``Entry`` is one row of taint knowledge. ``Catalog`` is the whole set with the lookups
that make it useful standalone: filter by language/role/kind/package/cwe, resolve a
concrete call site to the facts that attach to it, free-text search, and a coverage
summary. Everything here is pure data over the JSON the loader reads -- no engine, no
verdicts, no dependencies beyond the standard library.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import loader


@dataclass(frozen=True)
class Entry:
    """One taint fact: a resolvable symbol, an access path, and a role.

    Fields mirror the catalog schema. ``source_file`` is added at load time so a
    consumer can trace a fact back to the file it came from; it is not part of the row.
    """

    id: str
    language: str
    method: str
    access_path: str
    role: str
    kind: str
    cwe: "List[str]" = field(default_factory=list)
    confidence: Optional[str] = None
    corroboration: Optional[int] = None
    package: Optional[str] = None
    type: Optional[str] = None
    signature: Optional[str] = None
    arity: Optional[int] = None
    element_count_arg: Optional[int] = None
    notes: Optional[str] = None
    source_file: Optional[str] = None

    @property
    def symbol(self) -> str:
        """A readable ``package::type::method`` spelling of the bound symbol."""
        owner = self.package or self.type
        return f"{owner}.{self.method}" if owner else self.method

    def to_dict(self, include_source: bool = False) -> dict:
        """Round-trippable dict of the schema fields (source_file optional)."""
        out = {}
        for f in fields(self):
            if f.name == "source_file" and not include_source:
                continue
            value = getattr(self, f.name)
            out[f.name] = value
        return out


_ENTRY_FIELDS = {f.name for f in fields(Entry)}


def _entry_from_row(row: dict, source_file: str) -> Entry:
    data = {k: v for k, v in row.items() if k in _ENTRY_FIELDS}
    data["source_file"] = source_file
    return Entry(**data)


class Catalog:
    """The loaded set of taint facts, with the queries a consumer needs.

    Construct via :func:`load` (or :meth:`from_root`); then filter with :meth:`find`,
    map a call site with :meth:`resolve`, or search free text with :meth:`search`.
    """

    def __init__(self, entries: "List[Entry]", root: Optional[Path] = None):
        self.entries: List[Entry] = entries
        self.root = root
        # method-name index for fast resolve(); a method can map to several entries.
        self._by_method: Dict[str, List[Entry]] = {}
        for e in entries:
            self._by_method.setdefault(e.method, []).append(e)

    # -- construction --------------------------------------------------------

    @classmethod
    def from_root(cls, root: Path) -> "Catalog":
        entries: List[Entry] = []
        for path, doc in loader.iter_model_docs(root):
            rel = str(path.relative_to(root))
            for row in doc["entries"]:
                if not isinstance(row, dict):
                    raise ValueError(f"invalid entry in {path}")
                entries.append(_entry_from_row(row, rel))
        return cls(entries, root=root)

    # -- queries -------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def find(
        self,
        language: Optional[str] = None,
        role: Optional[str] = None,
        kind: Optional[str] = None,
        package: Optional[str] = None,
        type: Optional[str] = None,
        method: Optional[str] = None,
        cwe: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> "List[Entry]":
        """Return entries matching every non-None filter (exact match per field)."""
        out = self.entries
        if language is not None:
            out = [e for e in out if e.language == language]
        if role is not None:
            out = [e for e in out if e.role == role]
        if kind is not None:
            out = [e for e in out if e.kind == kind]
        if package is not None:
            out = [e for e in out if e.package == package]
        if type is not None:
            out = [e for e in out if e.type == type]
        if method is not None:
            out = [e for e in out if e.method == method]
        if confidence is not None:
            out = [e for e in out if e.confidence == confidence]
        if cwe is not None:
            want = cwe if cwe.upper().startswith("CWE-") else f"CWE-{cwe}"
            out = [e for e in out if want in (e.cwe or [])]
        return list(out)

    @property
    def sinks(self) -> "List[Entry]":
        return [e for e in self.entries if e.role == "sink"]

    @property
    def sources(self) -> "List[Entry]":
        return [e for e in self.entries if e.role == "source"]

    @property
    def sanitizers(self) -> "List[Entry]":
        return [e for e in self.entries if e.role == "sanitizer"]

    @property
    def summaries(self) -> "List[Entry]":
        return [e for e in self.entries if e.role == "summary"]

    def get(self, entry_id: str) -> Optional[Entry]:
        """Return the single entry with this id, or None."""
        for e in self.entries:
            if e.id == entry_id:
                return e
        return None

    def resolve(
        self,
        language: str,
        method: str,
        package: Optional[str] = None,
        type: Optional[str] = None,
    ) -> "List[Entry]":
        """Map a concrete call to the facts that attach to it.

        Matches on ``method`` and ``language`` first, then narrows by ``package`` and
        ``type`` *only when the caller supplies them* -- an entry with a receiver-typed
        ``type`` still matches a bare method query, so a consumer that has only the
        callee spelling gets every candidate, and one that also knows the receiver or
        module gets the precise subset.
        """
        cands = [e for e in self._by_method.get(method, []) if e.language == language]
        if package is not None:
            cands = [e for e in cands if e.package == package]
        if type is not None:
            cands = [e for e in cands if e.type == type]
        return cands

    def search(self, text: str) -> "List[Entry]":
        """Case-insensitive substring search over id, symbol, kind, and notes."""
        pat = re.compile(re.escape(text), re.IGNORECASE)
        out = []
        for e in self.entries:
            hay = " ".join(
                filter(None, [e.id, e.symbol, e.kind, e.method, e.package, e.type, e.notes])
            )
            if pat.search(hay):
                out.append(e)
        return out

    # -- introspection -------------------------------------------------------

    def languages(self) -> "List[str]":
        return sorted({e.language for e in self.entries})

    def roles(self) -> "List[str]":
        return sorted({e.role for e in self.entries})

    def kinds(self, language: Optional[str] = None) -> "List[str]":
        src = self.entries if language is None else self.find(language=language)
        return sorted({e.kind for e in src})

    def cwes(self) -> "List[str]":
        out = set()
        for e in self.entries:
            out.update(e.cwe or [])
        return sorted(out, key=lambda c: int(c.split("-")[1]) if "-" in c else 0)

    def packages(self, language: Optional[str] = None) -> "List[str]":
        src = self.entries if language is None else self.find(language=language)
        return sorted({e.package for e in src if e.package})

    def stats(self) -> dict:
        """A machine-readable coverage snapshot: totals by language/role and by kind."""
        by_lang_role = Counter((e.language, e.role) for e in self.entries)
        by_kind = Counter(e.kind for e in self.entries)
        return {
            "total": len(self.entries),
            "by_language_role": {
                f"{lang}:{role}": n for (lang, role), n in sorted(by_lang_role.items())
            },
            "by_kind": dict(sorted(by_kind.items(), key=lambda kv: (-kv[1], kv[0]))),
            "languages": self.languages(),
            "kinds": len(by_kind),
        }


def load(root: Optional[str] = None) -> Catalog:
    """Load the catalog. Discovers the data root unless ``root`` is given.

    This is the one call most consumers need::

        import atropos
        cat = atropos.load()
        for s in cat.find(language="python", kind="command-injection"):
            print(s.symbol, s.access_path)
    """
    resolved = loader.find_catalog_root(root)
    return Catalog.from_root(resolved)
