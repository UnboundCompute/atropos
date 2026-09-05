"""Locate and read the Atropos catalog data. Standard library only.

The catalog is pure JSON that ships in three ways, and this module finds whichever
one is present, in priority order:

1. ``ATROPOS_ROOT`` in the environment -- an explicit override, always wins. It names
   a directory that contains ``pack.json`` and a ``models/`` tree. This is the same
   variable the analysis engine honours, so a consumer that has already pinned a pack
   gets the same data here.
2. A source checkout / editable install -- discovered by walking up from this file to
   the first ancestor that holds both ``pack.json`` and ``models/``. This makes edits
   to the live tree show up immediately, which is what a contributor wants.
3. Data bundled inside an installed wheel at ``atropos/_bundle/`` -- the self-contained
   case, used when the package was ``pip install``ed with no surrounding repo.

The result is a plain :class:`pathlib.Path` to the catalog root; every other module
reads files beneath it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator, List, Optional


class CatalogNotFound(RuntimeError):
    """Raised when no catalog root can be located by any discovery strategy."""


def _looks_like_root(path: Path) -> bool:
    return (path / "pack.json").is_file() and (path / "models").is_dir()


def _from_env() -> Optional[Path]:
    raw = os.environ.get("ATROPOS_ROOT")
    if not raw:
        return None
    root = Path(raw).expanduser()
    if not _looks_like_root(root):
        raise CatalogNotFound(
            f"ATROPOS_ROOT={raw!r} does not contain pack.json and models/"
        )
    return root


def _from_walk_up() -> Optional[Path]:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if _looks_like_root(parent):
            return parent
    return None


def _from_bundle() -> Optional[Path]:
    bundle = Path(__file__).resolve().parent / "_bundle"
    if _looks_like_root(bundle):
        return bundle
    return None


def find_catalog_root(explicit: Optional[os.PathLike] = None) -> Path:
    """Return the catalog root directory, or raise :class:`CatalogNotFound`.

    Pass ``explicit`` to bypass discovery entirely (it must itself be a valid root).
    Otherwise the env override, then a source checkout, then a bundled copy are tried.
    """
    if explicit is not None:
        root = Path(explicit).expanduser()
        if not _looks_like_root(root):
            raise CatalogNotFound(f"{root} is not an Atropos catalog root")
        return root
    for strategy in (_from_env, _from_walk_up, _from_bundle):
        root = strategy()
        if root is not None:
            return root
    raise CatalogNotFound(
        "no Atropos catalog found: set ATROPOS_ROOT, run from a checkout, "
        "or install a self-contained build"
    )


def read_json(path: Path) -> dict:
    """Read one JSON document with an actionable error on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise CatalogNotFound(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error


def iter_model_files(root: Path) -> Iterator[Path]:
    """Yield every model JSON file under ``models/`` in a stable order."""
    yield from sorted((root / "models").rglob("*.json"))


def iter_model_docs(root: Path) -> Iterator["tuple[Path, dict]"]:
    """Yield ``(path, document)`` for each model file, validating the outer shape."""
    for path in iter_model_files(root):
        doc = read_json(path)
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
            raise ValueError(f"invalid model document shape: {path}")
        yield path, doc


def load_pack(root: Path) -> dict:
    """Return the parsed ``pack.json`` manifest for a catalog root."""
    return read_json(root / "pack.json")


def pack_version(root: Path) -> str:
    """Return the catalog-content version (``VERSION`` file, else ``pack.json``)."""
    version_file = root / "VERSION"
    if version_file.is_file():
        return version_file.read_text(encoding="utf-8").strip()
    return str(load_pack(root).get("version", "unknown"))


def list_roots_searched() -> List[str]:
    """Human-readable description of where discovery looks, for diagnostics."""
    env = os.environ.get("ATROPOS_ROOT") or "(unset)"
    return [
        f"ATROPOS_ROOT={env}",
        f"walk-up from {Path(__file__).resolve().parent}",
        f"bundle at {Path(__file__).resolve().parent / '_bundle'}",
    ]
