"""Call-site extraction for languages without a bundled standard-library parser:
C, JavaScript, and TypeScript.

There is no zero-dependency AST for these on the standard library, so this scanner
is deliberately lexical. It first *masks* strings and comments -- overwriting their
interior with spaces while preserving every newline and offset -- so a call spelled
inside a string or comment can never match, and reported line/column numbers stay
exact. It then finds ``name(`` and ``recv.name(`` shapes over the masked text and
recovers argument spans by balancing parentheses.

For JavaScript and TypeScript it also does a light import/``require`` binding pass,
so ``exec`` from ``const { exec } = require('child_process')`` is reported as the
resolved module function ``child_process.exec`` rather than a bare name. This is
best effort by design: it recovers the common, unambiguous binding forms and leaves
anything dynamic as an unresolved (heuristic-strength) name. It is a scanner, not a
type system.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .model import CallSite

# A dotted callee chain ending in `(` -- `memcpy(`, `child_process.exec(`,
# `cur.execute(`. The receiver is the part before the final `.`.
_CALL_RE = re.compile(
    r"([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\("
)
_IDENT_TAIL = re.compile(r"[A-Za-z_$][\w$]*\s*$")


def _mask(source: str, language: str) -> str:
    """Return a copy of ``source`` with string and comment interiors turned to
    spaces. Newlines are preserved so line/column arithmetic stays correct."""
    out = list(source)
    i, n = 0, len(source)
    backtick = language in ("javascript", "typescript")
    while i < n:
        c = source[i]
        two = source[i:i + 2]
        if two == "//":
            j = i
            while j < n and source[j] != "\n":
                out[j] = " "
                j += 1
            i = j
        elif two == "/*":
            j = i
            while j < n and source[j:j + 2] != "*/":
                if source[j] != "\n":
                    out[j] = " "
                j += 1
            if j < n:  # blank the closing */
                out[j] = out[j + 1] = " "
                j += 2
            i = j
        elif c in "\"'" or (backtick and c == "`"):
            quote = c
            out[i] = " "
            j = i + 1
            while j < n:
                if source[j] == "\\" and j + 1 < n:  # skip escaped char
                    if source[j] != "\n":
                        out[j] = " "
                    if source[j + 1] != "\n":
                        out[j + 1] = " "
                    j += 2
                    continue
                if source[j] == quote:
                    out[j] = " "
                    j += 1
                    break
                if source[j] != "\n":
                    out[j] = " "
                j += 1
            i = j
        else:
            i += 1
    return "".join(out)


def _split_args(masked: str, source: str, open_paren: int) -> Tuple[Tuple[str, ...], int]:
    """Given the index of a call's ``(`` in the masked text, return the top-level
    argument source snippets and the index just past the matching ``)``. Depth is
    tracked over the masked text so commas inside strings never split an argument."""
    depth = 0
    start = open_paren + 1
    args: List[str] = []
    i, n = open_paren, len(masked)
    while i < n:
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                seg = source[start:i].strip()
                if seg or args:
                    args.append(seg)
                return tuple(args), i + 1
        elif ch == "," and depth == 1:
            args.append(source[start:i].strip())
            start = i + 1
        i += 1
    return tuple(args), n  # unbalanced: best effort


def _js_imports(masked: str, source: str) -> Tuple[Dict[str, str], Dict[str, Tuple[str, str]]]:
    """Recover common JS/TS import bindings. Returns (module aliases, from-names)."""
    modules: Dict[str, str] = {}
    from_names: Dict[str, Tuple[str, str]] = {}

    def _add_named(spec: str, module: str) -> None:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            m = re.match(r"([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$", part)
            if m:
                orig, alias = m.group(1), m.group(2)
                from_names[alias or orig] = (module, orig)

    # const x = require('mod')  /  const { a, b as c } = require('mod')
    for m in re.finditer(
        r"(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)",
        source,
    ):
        bound, module = m.group(1), m.group(2)
        if bound.startswith("{"):
            _add_named(bound[1:-1], module)
        else:
            modules[bound] = module
    # import ... from 'mod'
    for m in re.finditer(
        r"import\s+(.+?)\s+from\s*['\"]([^'\"]+)['\"]", source, re.DOTALL
    ):
        clause, module = m.group(1).strip(), m.group(2)
        nm = re.search(r"\{([^}]*)\}", clause)
        if nm:
            _add_named(nm.group(1), module)
        star = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", clause)
        if star:
            modules[star.group(1)] = module
        default = re.match(r"([A-Za-z_$][\w$]*)", clause)
        if default and not clause.startswith("{") and not clause.startswith("*"):
            modules[default.group(1)] = module
    return modules, from_names


def _line_col(source: str, offset: int) -> Tuple[int, int]:
    prefix = source[:offset]
    line = prefix.count("\n") + 1
    col = offset - (prefix.rfind("\n") + 1)
    return line, col


def scan(file: str, source: str, language: str) -> "List[CallSite]":
    """Return every call site found in ``source`` for a C/JS/TS file."""
    masked = _mask(source, language)
    lines = source.splitlines()
    modules: Dict[str, str] = {}
    from_names: Dict[str, Tuple[str, str]] = {}
    if language in ("javascript", "typescript"):
        modules, from_names = _js_imports(masked, source)

    sites: List[CallSite] = []
    for m in _CALL_RE.finditer(masked):
        chain = re.sub(r"\s+", "", m.group(1))
        # A call immediately preceded by an identifier char is a false split
        # (e.g. the `def` in a keyword); guard by checking the char before.
        start = m.start(1)
        if start > 0 and (masked[start - 1].isalnum() or masked[start - 1] in "_$."):
            continue
        parts = chain.split(".")
        callee = parts[-1]
        receiver = ".".join(parts[:-1]) or None
        open_paren = m.end() - 1
        args, _ = _split_args(masked, source, open_paren)
        line, col = _line_col(source, start)
        snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""

        module: Optional[str] = None
        is_method = receiver is not None
        if receiver is None and callee in from_names:
            module, callee = from_names[callee][0], from_names[callee][1]
            is_method = False
        elif receiver is not None and parts[0] in modules:
            module = modules[parts[0]]
            is_method = False  # resolved module call, not a member method

        sites.append(CallSite(
            file=file, line=line, col=col, callee=callee,
            receiver=receiver, module=module, args=args,
            is_method=is_method, snippet=snippet,
        ))
    return sites
