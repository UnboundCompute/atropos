"""Compare an audit against a recorded baseline: the engine behind a CI gate.

A pull-request gate does not want the whole finding list -- it wants the *new* ones
this change introduced. This module fingerprints findings and diffs two sets as
multisets, so adding a second identical call still registers as one new finding while
merely moving code does not.

The fingerprint deliberately excludes line and column. A finding is identified by its
catalog id, file, callee spelling, and the focused expression -- so reformatting or
inserting lines above a call does not make it look new, which is what turns a gate
from useful into ignored. A consumer that wants strict line-level identity can diff
the raw ``audit --json`` output instead.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Tuple

from .model import Finding, _MATCH_RANK


def fingerprint(d: Dict) -> str:
    """Stable, line-independent identity for a finding dict (from ``Finding.to_dict``
    or a loaded baseline)."""
    return "|".join(str(d.get(k) or "") for k in
                    ("id", "file", "callee", "focus", "focus_expr"))


def _counter(dicts: "List[Dict]") -> "Counter":
    return Counter(fingerprint(d) for d in dicts)


def diff(current: "List[Finding]", baseline: "List[Dict]",
         min_match: str = "name-only") -> Tuple["List[Finding]", int]:
    """Return (new findings, count of baseline findings now gone).

    ``current`` is live :class:`Finding` objects; ``baseline`` is the ``findings``
    list from a prior ``audit --json``. A finding counts as new when the current
    multiset has more of its fingerprint than the baseline did. ``min_match`` drops
    new findings weaker than the given binding strength from the returned list."""
    max_rank = _MATCH_RANK.get(min_match, 2)
    cur_dicts = [f.to_dict() for f in current]
    base = _counter(baseline)
    seen: "Counter" = Counter()
    new: List[Finding] = []
    for f, d in zip(current, cur_dicts):
        fp = fingerprint(d)
        seen[fp] += 1
        if seen[fp] > base.get(fp, 0):
            if _MATCH_RANK.get(f.match, 2) <= max_rank:
                new.append(f)
    # findings whose fingerprint was in the baseline but is now absent/reduced
    cur = _counter(cur_dicts)
    fixed = sum(max(0, n - cur.get(fp, 0)) for fp, n in base.items())
    return new, fixed
