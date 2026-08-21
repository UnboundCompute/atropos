# Contributing to Atropos

Thanks for helping grow the catalog. Atropos is **pure data**, a curated
taint-model knowledge base, so contributing is mostly a matter of writing one clean
JSON entry and proving it binds. There's no engine to build and nothing to
`python -m pip install`. The tooling is stdlib-only Python 3.

The most useful contribution is **a new model**: a sink, source, sanitizer, or
summary that the catalog is missing. A missing sink is a whole class of bug a
consumer can never flag, so new entries are always welcome.

## Quick start

```bash
git clone https://github.com/UnboundCompute/atropos.git
cd atropos
python3 tools/validate.py                    # the gate, must pass
python3 -m unittest discover -s tests        # must pass
python3 tools/stats.py                        # coverage snapshot
```

No virtualenv, no dependencies. If `python3 tools/validate.py` prints `OK`, you're
set up.

## Where entries live

```
models/
  c/        memory.json  injection.json  sources.json
  python/   sinks.json   sources.json    sanitizers.json
```

There's one file per `(language, role)`. Each file is
`{ "role_group": <role>, "entries": [...] }`, and every entry in it carries that
same `role`. Adding a model for a new language/role pair? Create
`models/<language>/<role>s.json` with a matching `role_group`.

## What an entry looks like

Every entry is one row of data: a resolvable symbol, an access path, and a role.
Here's a complete one:

```json
{
  "id": "c.mem.memcpy.n",
  "language": "c", "package": null, "type": null, "method": "memcpy",
  "signature": "void *memcpy(void *dest, const void *src, size_t n)",
  "access_path": "Argument[2]", "role": "sink", "kind": "buffer-size",
  "cwe": ["CWE-787", "CWE-120", "CWE-190"], "confidence": "high", "corroboration": 3,
  "notes": null
}
```

### Field reference

| Field | Required | What it is |
| --- | --- | --- |
| `id` | yes | Stable, unique, dotted lowercase key. Convention: `<lang>.<group>.<method>.<qualifier>`, for example `py.os.system.cmd` or `c.mem.memcpy.n`. Never reuse an id. |
| `language` | yes | One of `c`, `python`, `javascript`, `typescript`. |
| `package` | no | Module or package that owns the symbol (`"os"`, `"subprocess"`). Use `null` for a C standard-library or builtin name. |
| `type` | no | Owning type for a method (a DB cursor, say). Use `null` for a free function. |
| `method` | yes | Function or method name as the frontend resolves it. |
| `signature` | no | Human-readable signature. This is documentation only. Binding keys on the symbol plus `access_path`, never on this string. |
| `access_path` | yes | Where the role attaches. Must be bindable, see below. |
| `role` | yes | `sink`, `source`, `sanitizer`, or `summary`. Must equal the file's `role_group`. |
| `kind` | yes | Vulnerability-class subtype, for example `buffer-size`, `command-injection`, `sql-injection`, `deserialization`, `format-string`, `path-traversal`, `network-input`. |
| `cwe` | yes | Array of public CWE ids in `CWE-<n>` form. Standard identifiers only, never invented. |
| `confidence` | yes | `high`, `medium`, or `low`. Your confidence that this is a true positive *when a flow actually reaches it*. |
| `corroboration` | no | Integer of at least 1: how many independent confirmations back the entry. It's a count, nothing more. |
| `notes` | no | Free text, or `null`. |

### Access-path grammar

`access_path` is one bindable term, or a summary of two terms joined by `->`:

- `Argument[n]`: zero-indexed positional argument. `Argument[0]` is the first arg.
- `Argument[*]`: every argument (for example a variadic `printf`-family format sink).
- `ReturnValue`: the value the call returns.
- `Receiver`: the object the method is called on.
- `<term> -> <term>`: a summary, meaning taint flows from the left term to the right,
  for example `Argument[0] -> ReturnValue`.

A vague "somewhere in the call" is never acceptable. If you can't name the exact
argument, the entry isn't ready yet.

## What makes an entry a fact, not an opinion

These are the house rules (they're also in [`CLAUDE.md`](CLAUDE.md)):

- **One fact per row.** A resolvable symbol, plus an `access_path`, plus a `role`.
- **Describe what to watch, not a verdict.** "Is this call a bug?" is the engine's
  question (does tainted data reach it?) and the human's question (is the length
  actually bounded upstream?). The model only says "watch this."
- **`cwe` holds public CWE identifiers only.** `corroboration` is a plain count of
  independent confirmations, a number, not a citation.
- **Keep every entry curated and self-consistent.** The catalog should read as one
  coherent taxonomy.

## Submitting a change

1. Fork the repo and create a branch.
2. Add or edit the entry in the right `models/<language>/<role>s.json`.
3. Run the gate. Both commands must pass:
   ```bash
   make check
   ```
   `validate.py` checks schema conformance, id uniqueness, access-path grammar, CWE
   format, and that each file's `role_group` matches every entry's `role`.
4. Open a pull request describing the symbols you added and why they belong in the
   class you assigned. CI runs the same gate on every push.

## Reporting a gap

Not ready to write JSON? Open an issue with the symbol, its language and package,
the argument that matters, and the CWE class you think it belongs to. That's plenty
for someone else to turn it into an entry.
