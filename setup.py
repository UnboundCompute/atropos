"""Build shim: bundle the catalog data into the wheel so an install is self-contained.

All package metadata lives in ``pyproject.toml``. The one thing that needs code is
making the wheel carry the catalog. The canonical data lives at the repository root
(``models/``, ``detection/``, ``profiles/``, ``schema/``, ``pack.json``, ``VERSION``,
the license files) and is read from there by the tooling and tests. Rather than
duplicate it in the tree, a custom ``build_py`` copies it into ``atropos/_bundle/``
just before the package is assembled, and ``pyproject.toml`` ships that directory as
package data. The source of truth stays single; ``atropos/_bundle/`` is a build
artifact (gitignored) and is never committed.

At runtime the loader prefers ``ATROPOS_ROOT`` and then a source checkout, so an
editable install or a run from the repo uses the live data; the bundle is the fallback
for a plain wheel install with no surrounding repository.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

HERE = Path(__file__).resolve().parent
BUNDLE = HERE / "atropos" / "_bundle"

# Directories copied wholesale, and single files copied as-is.
_DATA_DIRS = ("models", "detection", "profiles", "schema")
_DATA_FILES = ("pack.json", "VERSION", "LICENSE", "LICENSE-CODE")


def _populate_bundle() -> None:
    if BUNDLE.exists():
        shutil.rmtree(BUNDLE)
    BUNDLE.mkdir(parents=True)
    for name in _DATA_DIRS:
        src = HERE / name
        if src.is_dir():
            shutil.copytree(src, BUNDLE / name)
    for name in _DATA_FILES:
        src = HERE / name
        if src.is_file():
            shutil.copy2(src, BUNDLE / name)


class build_py(_build_py):
    def run(self):
        _populate_bundle()
        super().run()


setup(cmdclass={"build_py": build_py})
