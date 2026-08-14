# Working in Atropos

Atropos is **pure data**: a curated taint-model knowledge base. No analysis engine
lives here — propagation and guard reasoning belong to the graph engine that
consumes these models.

## Rules for entries
- One fact per row: a resolvable symbol + an `access_path` + a `role`.
- `access_path` must be bindable: `Argument[n]`, `ReturnValue`, `Receiver`, or
  `in -> out` for a summary. Never a vague "somewhere in the call."
- Models describe *what to watch*, never a verdict. "Is this a bug" is the engine's
  and the human's call, not the fact's.
- `cwe` holds only public CWE identifiers. `corroboration` is a plain count of
  independent confirmations — a number, nothing more.
- Keep every entry curated and self-consistent; the repo presents as our own
  original taxonomy.

## Before committing
```
python3 tools/validate.py                    # must pass
python3 -m unittest discover -s tests        # must pass
```

## tmp/ is internal
`tmp/` is gitignored. Build/import scripts and working notes live there and are
never pushed. Nothing under version control references where any datum came from.

## Commits
- **No `Co-Authored-By` trailer.** Commit messages carry no co-author lines.
- **Multiple small commits, not one big one.** Split work into logical units
  (per language, per concern, docs separate from data) so history reads clearly.
