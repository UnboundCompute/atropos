# Atropos

**A taint-model knowledge base: where untrusted data enters, where it must not land, and what makes it safe again.**

Atropos is the model layer of the Unbound Compute analysis stack. It is pure,
declarative data — a curated catalog of taint facts keyed by symbol and access
path — with no analysis engine of its own. The engine ([Lachesis](https://github.com/UnboundCompute/lachesis))
owns propagation, reachability, and guard/dominance reasoning; Atropos tells it
which symbols are **sources**, **sinks**, **sanitizers**, and flow **summaries**,
and at exactly which argument or return value.

In the Moirai the thread of a life is spun, measured, and cut. Lachesis measures
how code hangs together; Atropos names the cut — the point where a dangerous flow
lands.

## Why it's separate

Knowledge and reasoning have different lifecycles. Facts about `memcpy` or
`pickle.loads` do not change when the graph engine does, and they are useful to
anything that can resolve a symbol — not just one tool. Keeping the models in
their own permissively-licensed repository means:

- the engine stays decoupled and testable against a stable model set,
- the taxonomy can be versioned, reviewed, and grown on its own cadence,
- one binding seam — resolve a model's symbol against the graph's symbol index,
  stamp the role and access path onto the node — is the *only* coupling.

## The shape of a fact

Each entry is one row of the models-as-data form: a resolvable symbol, an access
path, and a role.

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
`ReturnValue`, `Receiver`, or `in -> out` for a summary. The schema lives in
[`schema/model.schema.json`](schema/model.schema.json).

The models make no security *verdict*. `memcpy`'s size argument is a sink; whether
a given call is a bug is for the engine (does tainted data reach it?) and the human
(is the length actually bounded upstream?). The models say only "watch this."

## Layout

```
models/
  c/        memory  string  scanf  format  alloc  exec  path  tempfile  sources  random
  python/   sinks   sources  sanitizers  random
schema/     model.schema.json
tools/      validate.py  stats.py         # stdlib only, zero deps
tests/      test_models.py
```

187 entries at time of writing: C memory-safety / injection / path / format / alloc
sinks plus network/io/env sources; Python command / code / deserialization / SQL /
path / SSRF / XXE / template / crypto sinks, sources, and sanitizers.

## Use it

```bash
python3 tools/validate.py     # gate: schema, unique ids, bindable access paths
python3 tools/stats.py        # coverage snapshot by language / role / kind
python3 -m unittest discover -s tests
```

Consuming the data is just reading JSON — no import, no dependency. A binder in the
engine walks `models/**/*.json`, resolves each `(language, package, type, method)`
against its symbol index, and stamps `(role, kind, access_path, cwe)` onto the
matching node.

## Scope, honestly

v1 is **sinks-first, depth over breadth**: C memory-safety and injection sinks
(the class a call graph alone misses, because `memcpy` and friends are builtins,
not ordinary call edges), plus the core Python sink/source/sanitizer set. Sources
and sanitizers grow from here; framework-specific and domain-specific sources
(e.g. a packet buffer) are seeded by the engine, not this catalog.

## License

Data licensed **CC BY 4.0** — see [`LICENSE`](LICENSE). Use it, adapt it, ship it,
including commercially; keep the attribution notice.
