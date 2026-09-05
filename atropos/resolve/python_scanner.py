"""Precise call-site extraction for Python using the standard-library ``ast``.

This is the high-fidelity scanner: it parses the file, tracks ``import`` bindings,
and resolves each call's receiver to a module when it can. That resolution is what
lets a module-function fact (``os.system``) bind *exactly* rather than by name
alone, and it correctly follows aliases (``import os as o``) and direct imports
(``from os import system`` makes a bare ``system(...)`` an ``os.system`` call).

No dependency beyond the standard library; a syntactically invalid file is reported
as a skip, never a crash.
"""
from __future__ import annotations

import ast
from typing import Dict, List, Optional, Tuple

from .model import CallSite


class _Imports:
    """Name bindings introduced by import statements in one module."""

    def __init__(self) -> None:
        # alias name -> module dotted path  (import os / import os as o)
        self.modules: Dict[str, str] = {}
        # bound name -> (module, original name)  (from os import system as s)
        self.from_names: Dict[str, Tuple[str, str]] = {}
        self.star_modules: List[str] = []  # from x import *  (unresolved wildcard)

    def visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                bound = a.asname or a.name.split(".")[0]
                # `import os.path` binds `os`; `import os.path as p` binds `p`->os.path
                self.modules[bound] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.level:  # relative import: module unknown
                return
            for a in node.names:
                if a.name == "*":
                    self.star_modules.append(node.module)
                    continue
                bound = a.asname or a.name
                self.from_names[bound] = (node.module, a.name)


def _line_starts(source: str) -> List[int]:
    """Byte offset of the start of each 1-indexed line (index 0 unused)."""
    starts = [0, 0]
    for i, ch in enumerate(source):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _segment(source: str, starts: List[int], node: ast.AST) -> str:
    """Exact source text of ``node`` using precomputed line starts -- O(1) per node,
    where ``ast.get_source_segment`` re-scans the whole file each call (quadratic)."""
    lineno = getattr(node, "lineno", None)
    end_lineno = getattr(node, "end_lineno", None)
    if lineno is None or end_lineno is None or end_lineno >= len(starts):
        return ""
    start = starts[lineno] + node.col_offset
    end = starts[end_lineno] + node.end_col_offset
    return source[start:end]


def scan(file: str, source: str) -> "List[CallSite]":
    """Return every call site in ``source``. ``file`` is used only for labelling."""
    tree = ast.parse(source)  # may raise SyntaxError; caller handles it
    lines = source.splitlines()
    starts = _line_starts(source)
    imports = _Imports()
    for node in ast.walk(tree):
        imports.visit(node)

    sites: List[CallSite] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        args = tuple(_segment(source, starts, a) for a in node.args)
        line = getattr(func, "lineno", node.lineno)
        col = getattr(func, "col_offset", node.col_offset)
        snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""

        if isinstance(func, ast.Name):
            name = func.id
            if name in imports.from_names:
                mod, orig = imports.from_names[name]
                sites.append(CallSite(
                    file=file, line=line, col=col, callee=orig,
                    receiver=None, module=mod, args=args,
                    is_method=False, snippet=snippet,
                ))
            else:
                sites.append(CallSite(
                    file=file, line=line, col=col, callee=name,
                    receiver=None, module=None, args=args,
                    is_method=False, snippet=snippet,
                ))
        elif isinstance(func, ast.Attribute):
            callee = func.attr
            value = func.value
            if isinstance(value, ast.Name) and value.id in imports.modules:
                # module.function(...)  -> a resolved module call, not a method.
                sites.append(CallSite(
                    file=file, line=line, col=col, callee=callee,
                    receiver=value.id, module=imports.modules[value.id], args=args,
                    is_method=False, snippet=snippet,
                ))
            else:
                # receiver.method(...) with an unresolved receiver type.
                sites.append(CallSite(
                    file=file, line=line, col=col, callee=callee,
                    receiver=_segment(source, starts, value) or None, module=None,
                    args=args, is_method=True, snippet=snippet,
                ))
        # a call of a call, subscript, lambda, etc. carries no stable symbol name.
    return sites
