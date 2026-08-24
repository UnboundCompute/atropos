# Atropos

**A taint-model knowledge base: where untrusted data enters, where it must not land, and what makes it safe again.**

Atropos is the model layer of the Unbound Compute analysis stack. It is pure,
declarative data: a curated catalog of taint facts keyed by symbol and access
path, with no analysis engine of its own. The engine
([Lachesis](https://github.com/UnboundCompute/lachesis)) owns propagation,
reachability, and guard reasoning. Atropos just tells it which symbols are
**sources**, **sinks**, **sanitizers**, and flow **summaries**, and exactly which
argument or return value to watch.

Put plainly: Lachesis figures out how code connects. Atropos is the lookup table
that says "this specific argument is dangerous, and here is why."

> **Status: v1.7.1, actively curated.** 1121 verified facts (plus 7 candidates under review). The data is
> validated on every change. Contributions are welcome, see
> [Contributing](#contributing).

Release and pinning guidance is in [`RELEASING.md`](RELEASING.md), and user-visible
catalog changes are tracked in [`CHANGELOG.md`](CHANGELOG.md). Consumers should pin a
tag or commit so model updates are explicit and reproducible. The current catalog
version is recorded in [`VERSION`](VERSION), and release tags must match it.
Security reporting guidance is in [`SECURITY.md`](SECURITY.md).

The catalog tooling supports Python 3.10 through 3.12 and uses only the standard
library. The validation workflow exercises all three supported versions.

## Why it's a separate repo

Knowledge and reasoning change at different speeds. The fact that `memcpy`'s size
argument is dangerous does not change when the graph engine gets rewritten, and it
is useful to anything that can resolve a symbol, not just one tool. Keeping the
models in their own permissively licensed repo means:

- the engine stays decoupled and testable against a stable set of models,
- the taxonomy can be versioned, reviewed, and grown on its own schedule,
- there is exactly one point of coupling: resolve a model's symbol against the
  graph's symbol index, then stamp the role and access path onto that node.

## What a fact looks like

Each entry is one row of data: a resolvable symbol, an access path, and a role.

```json
{
  "id": "c.mem.memcpy.n",
  "language": "c", "package": null, "type": null, "method": "memcpy",
  "signature": "void *memcpy(void *dest, const void *src, size_t n)",
  "access_path": "Argument[2]", "role": "sink", "kind": "buffer-size",
  "cwe": ["CWE-787", "CWE-120", "CWE-190"], "confidence": "high", "corroboration": 3
}
```

`access_path` is how the fact attaches to a call: `Argument[n]` (zero-indexed),
`ReturnValue`, `Receiver`, or `in -> out` for a summary. The full schema lives in
[`schema/model.schema.json`](schema/model.schema.json).

The models never make a security *verdict*. `memcpy`'s size argument is a sink, but
whether a given call is an actual bug is up to the engine (does tainted data reach
it?) and the human (is the length actually bounded upstream?). The models only say
"watch this."

## Layout

```
models/
  c/            memory string scanf format alloc exec path tempfile sources random summaries
  python/       sinks sources sanitizers random summaries
  javascript/   sinks sources sanitizers summaries
  typescript/   sinks sources sanitizers summaries
candidates/     known-dangerous symbols not yet precisely bindable (never loaded by consumers)
schema/         model.schema.json  symbol-index.schema.json
tools/          validate.py  bind.py  stats.py   # stdlib only, zero deps
fixtures/       tiny symbol-index exports with verified node handles
tests/          test_models.py  test_binding.py
docs/           binding.md
```

1121 verified facts at the time of writing, covering all four languages Lachesis parses
(C, Python, JavaScript, TypeScript) across 27 taint kinds: buffer overflow,
command / code / SQL / LDAP / XPath / NoSQL / template injection, path traversal,
deserialization, SSRF, XXE, XSS, open redirect, prototype pollution, weak crypto
and randomness, insecure TLS, and more. Sinks, sources, sanitizers, and
flow summaries (documented src->dest / input->return behavior that lets the
engine drop its conservative every-argument-flows-to-return default).

## Using the data

```bash
python3 tools/validate.py     # gate 1: schema shape, unique ids, grammatical access paths
python3 tools/bind.py fixtures/c_buffer.index.json   # resolve models to exact graph nodes
python3 tools/stats.py        # human-readable coverage snapshot
python3 tools/stats.py --json # machine-readable coverage for release/docs automation
python3 -m unittest discover -s tests   # gate 2: binding fixtures + schema
```

For the complete local gate used by CI and release verification, run `make check`.

Consuming the data is just reading JSON, with no import and no dependency. A binder
in the engine walks `models/**/*.json`, resolves each
`(language, package, type, method)` against its symbol index, and stamps
`(role, kind, access_path, cwe)` onto the matching node.

The binding itself is a defined contract, not a convention. An engine exports
its symbols into a neutral format
([`schema/symbol-index.schema.json`](schema/symbol-index.schema.json)); the
in-repo binder ([`tools/bind.py`](tools/bind.py)) resolves each model against it
and reports one status per model — `bound`, `symbol-not-found`, `ambiguous`,
`arity-mismatch`, or `unsupported-path` — never a silent drop. This is what
turns an entry from a valid-looking name into a verified fact: it binds to the
exact node a reviewer confirmed. See [`docs/binding.md`](docs/binding.md). A symbol
that is dangerous but not yet precisely bindable waits in
[`candidates/`](candidates/) rather than posing as a fact.

## Scope, honestly

Atropos is sinks-first and favors depth over breadth, now across all four
languages. The C set leads with memory-safety and injection sinks, the class a
call graph alone misses, because `memcpy` and friends are builtins rather than
ordinary call edges. Python, JavaScript, and TypeScript add command / code / SQL /
injection, deserialization, SSRF, XXE, XSS, path-traversal, template-injection, and
prototype-pollution sinks, plus sources and sanitizers.

A note on binding, since it differs by language. A flat C builtin binds on the
callee spelling at the call site (`memcpy`). A JS/TS member call is spelled in full
(`child_process.exec`), so it binds on the method name and narrows with the entry's
`package`/`type` as a receiver hint, which is why those fields matter. Framework-
and domain-specific sources (a packet buffer, say) are seeded by the engine, not
this catalog.

## Contributing

New models are the most valuable contribution. A missing sink is a class of bug a
consumer can never catch. A good entry is a resolvable symbol, a bindable access
path, and a role, backed by public CWE references.

1. Add or edit the JSON entry in the right file under `models/<language>/`.
2. Run the gate locally, and make sure it passes:
   ```bash
   python3 tools/validate.py
   python3 -m unittest discover -s tests
   ```
3. Open a pull request. CI runs the same gate on every push.

The full walkthrough (a field-by-field reference, id and access-path conventions,
and what makes an entry a fact rather than an opinion) is in
[`CONTRIBUTING.md`](CONTRIBUTING.md). The short house rules for entries are in
[`CLAUDE.md`](CLAUDE.md).

## License

Data is licensed **CC BY 4.0**, see [`LICENSE`](LICENSE). Use it, adapt it, ship it,
including commercially. Just keep the attribution notice.
