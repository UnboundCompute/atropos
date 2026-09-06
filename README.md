# Atropos

**Atropos is a list of security facts about code. It says which functions are dangerous, which ones bring in untrusted data, and which ones clean it. It's just data. It doesn't run any analysis itself.**

Each fact points at one thing: a function, and the exact argument or return value to watch. Here's what one looks like:

```json
{
  "id": "c.std.memcpy.a2",
  "language": "c", "package": null, "type": null, "method": "memcpy",
  "access_path": "Argument[2]", "role": "sink", "kind": "buffer-size",
  "cwe": ["CWE-787", "CWE-120"], "confidence": "high", "corroboration": 3
}
```

This says: in C, the third argument to `memcpy` is a **sink**, a place where a bad value can cause a buffer overflow.

Atropos is the data. [Lachesis](https://github.com/UnboundCompute/lachesis) is the engine that uses it. Lachesis works out how code connects and whether tainted data actually reaches a sink. Atropos just tells it which spots to watch and why.

> **Status: v1.10.0, actively curated.** 1618 verified facts (plus 7 candidates under review). The data is checked on every change. See [Contributing](#contributing).

## The four kinds of fact

- **Source:** where untrusted data comes in (a request body, a form field).
- **Sink:** where a bad value does damage (a SQL query, a `memcpy` size).
- **Sanitizer:** something that makes data safe (an escaper, a validator).
- **Summary:** how data flows through a function (this input reaches that return value).

`access_path` says where on the call to watch: `Argument[n]` (starting at 0), `ReturnValue`, `Receiver`, or `in -> out` for a summary. The full schema is in [`schema/model.schema.json`](schema/model.schema.json).

The facts never say "this is a bug." That call belongs to the engine (does tainted data reach it?) and the human (is the length actually checked upstream?). A fact only says "watch this."

## Install the package

The catalog ships as a small Python package with the data built in. Python 3.9+, no dependencies.

```bash
pip install atropos
```

Command line:

```bash
atropos stats                              # coverage snapshot
atropos sinks -l python --kind sql-injection
atropos sources -l javascript
atropos resolve python execute --type Cursor   # what is this symbol?
atropos audit ./path/to/code               # find catalogued symbols in your code
atropos search deserialize                 # free-text over symbols and notes
atropos show c.std.memcpy.a2               # one fact by id
atropos export -l c --role sink -f csv     # json | jsonl | csv for pipelines
```

`atropos audit` walks a file or folder, finds every call, and reports the ones a known symbol attaches to. It points each fact at the exact argument, receiver, or return value to watch. Every match carries a confidence: `exact`, `heuristic`, or `name-only`, so you can filter by how sure the match is.

```bash
atropos audit ./src --min-match exact          # only pinned matches
atropos audit ./src -k sql-injection --json    # one kind, machine-readable
atropos audit app.py --role sink --role source # more than just sinks
```

Audit tells you where a known symbol is *used* and how sure the match is. It never says whether tainted data actually reaches it. That's the engine's job and the reviewer's.

The audit feeds a few other commands, each a different way to spend the same matches:

```bash
atropos audit ./src -f sarif > out.sarif    # GitHub code scanning / CI / IDE
atropos coverage ./src                      # counts by kind and language, hot files, gaps
atropos surface ./src                       # files that hold both a source and a sink
atropos conformance ./src                   # sink kinds used with no sanitizer present
atropos diff ./src -b baseline.json         # CI gate: fail on new findings only
atropos rules -l python -o policy.json      # a banned-API watch-list for other tools
atropos ground --cwe 89 -l python           # catalog facts as grounding for an LLM
atropos validate python system -a 'Argument[0]' --role sink -p os
```

`ground` and `validate` put the catalog under a language model. `ground` gathers the facts for a bug class into a compact block you drop into a prompt, so the model uses real facts instead of its own guesses. `validate` checks a fact the model *proposed* against the catalog and says `confirmed`, `partial`, `role-conflict`, or `unknown`, so a made-up sink gets caught before it's trusted.

Library:

```python
import atropos

cat = atropos.load()                       # finds the built-in catalog
for e in cat.find(language="python", role="sink", kind="command-injection"):
    print(e.id, e.symbol, e.access_path, e.cwe)

cat.resolve("javascript", "exec", package="child_process")  # match a call site
cat.stats()                                # counts by language, role, kind
```

Point the loader at a specific catalog with the `ATROPOS_ROOT` environment variable or `atropos.load(root=...)`.

## What's in it

1618 verified facts across the four languages Lachesis reads (C, Python, JavaScript, TypeScript), covering 23 sink kinds: buffer overflow, command / code / SQL / LDAP / XPath / NoSQL / template injection, path traversal, deserialization, unsafe reflection, SSRF, XXE, XSS, open redirect, prototype pollution, ReDoS, format string, weak crypto and randomness, insecure TLS, and more. Plus the sources, sanitizers, and summaries that go with them.

```
models/
  c/            memory string scanf format alloc exec path tempfile sources random summaries
  python/       sinks sources sanitizers random summaries
  javascript/   sinks sources sanitizers summaries
  typescript/   sinks sources sanitizers summaries
candidates/     dangerous symbols not yet precisely bindable (never loaded by consumers)
schema/         model.schema.json  symbol-index.schema.json
atropos/        the installable Python package: loader, query API, and CLI
tools/          validate.py  bind.py  stats.py   (stdlib only, no deps)
fixtures/       tiny symbol-index exports with verified node handles
tests/          test_models.py  test_binding.py  test_package.py
```

## Why it's a separate repo

Facts and engines change at different speeds. The fact that `memcpy`'s size argument is dangerous doesn't change when the engine gets rewritten, and it's useful to anything that can look up a symbol, not just one tool. Keeping the facts in their own repo means the engine stays easy to test, the list can grow on its own schedule, and there's one clean point of contact: match a symbol against the graph, then stamp the role and access path onto that node.

## How the data is used

Reading the data is just reading JSON, with no import and no dependency. An engine walks `models/**/*.json`, matches each `(language, package, type, method)` against its own symbol list, and stamps `(role, kind, access_path, cwe)` onto the matching node.

The binding is a defined contract. The binder reports one status per fact: `bound`, `symbol-not-found`, `ambiguous`, `arity-mismatch`, or `unsupported-path`. It never drops a fact silently. See [`docs/binding.md`](docs/binding.md). A symbol that's dangerous but not yet precisely bindable waits in [`candidates/`](candidates/) instead of posing as a fact.

To check the data locally:

```bash
python3 tools/validate.py                 # schema shape, unique ids, valid access paths
python3 -m unittest discover -s tests      # binding fixtures + schema
```

For the full local gate that CI runs, use `make check`. Release, pinning, and pack-building steps are in [`RELEASING.md`](RELEASING.md). Pin a git tag or an installed pack so data updates stay explicit. The current version is in [`VERSION`](VERSION).

## Scope

Atropos is sinks-first and goes for depth over breadth, across all four languages. The C set leads with memory-safety and injection sinks, the class a call graph alone misses, because `memcpy` and friends are built-ins, not ordinary calls. Python, JavaScript, and TypeScript add command / code / SQL injection, deserialization, SSRF, XXE, XSS, path traversal, template injection, and prototype pollution, plus sources and sanitizers.

Binding differs a little by language. A flat C built-in binds on the name at the call (`memcpy`). A JS/TS member call is spelled in full (`child_process.exec`), so it binds on the method name and narrows using the entry's `package`/`type`. That's why those fields matter.

## Contributing

New facts are the most valuable thing you can add. A missing sink is a whole class of bug a consumer can never catch. A good entry is a real symbol, a bindable access path, and a role, backed by public CWE references.

1. Add or edit the JSON entry under `models/<language>/`.
2. Run the gate and make sure it passes:
   ```bash
   python3 tools/validate.py
   python3 -m unittest discover -s tests
   ```
3. Open a pull request. CI runs the same gate.

The full walkthrough is in [`CONTRIBUTING.md`](CONTRIBUTING.md). Short house rules are in [`CLAUDE.md`](CLAUDE.md). Security reporting is in [`SECURITY.md`](SECURITY.md).

## License

Data is licensed **CC BY 4.0**, see [`LICENSE`](LICENSE). Use it, adapt it, ship it, including commercially. Just keep the attribution notice.
