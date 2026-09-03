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


def _source_segment(source: str, node: ast.AST) -> str:
    seg = ast.get_source_segment(source, node)
    return seg if seg is not None else ""


def _receiver_text(source: str, node: ast.AST) -> Optional[str]:
    return _source_segment(source, node) or None


def scan(file: str, source: str) -> "List[CallSite]":
    """Return every call site in ``source``. ``file`` is used only for labelling."""
    tree = ast.parse(source)  # may raise SyntaxError; caller handles it
    lines = source.splitlines()
    imports = _Imports()
    for node in ast.walk(tree):
        imports.visit(node)

    sites: List[CallSite] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        args = tuple(_source_segment(source, a) for a in node.args)
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
                    receiver=_receiver_text(source, value), module=None, args=args,
                    is_method=True, snippet=snippet,
                ))
        # a call of a call, subscript, lambda, etc. carries no stable symbol name.
    return sites
