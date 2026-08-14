# The binding contract

Atropos is a catalog of facts. What makes an entry a *fact* rather than a
plausible-looking guess is that it **binds**: its symbol resolves to a real
node in a code graph, and its `access_path` lands on the exact value it names.
An entry that cannot bind to the right node is not knowledge — it is an opinion
with a CWE attached. This document defines how binding works and what Atropos
guarantees about it.

Atropos owns the *fact* and the *acceptance test*. The engine
([Lachesis](https://github.com/UnboundCompute/lachesis)) owns propagation,
reachability, and guard reasoning. The two meet at exactly one place: the
**neutral symbol index**.

## The seam

Atropos never imports an engine. Instead the engine exports the symbols and
callsites of a codebase into a small, engine-agnostic JSON shape
([`schema/symbol-index.schema.json`](../schema/symbol-index.schema.json)), and
the Atropos binder ([`tools/bind.py`](../tools/bind.py)) resolves models against
that. Node ids are opaque handles the exporter owns; Atropos only passes them
back in its report.

A callsite record carries exactly what an access path needs to resolve:

```json
{
  "id": "cs_memcpy",
  "callee": {"name": "memcpy", "module": null, "receiver_type": null, "arity": 3},
  "call_value_id": "v_mc_ret",
  "receiver_value_id": null,
  "arg_value_ids": ["v_mc_dst", "v_mc_src", "v_mc_len"]
}
```

## Access path → node

| Access path                | Attaches to                                   |
|----------------------------|-----------------------------------------------|
| `Argument[n]`              | `arg_value_ids[n]` at the matched callsite     |
| `ReturnValue`             | `call_value_id`                                |
| `Receiver`                | `receiver_value_id`                            |
| `Argument[i] -> Argument[j]` / `... -> ReturnValue` | a semantic-flow **edge** between the two resolved nodes (a summary) |

This is the point of precise binding. An engine that connects *every* argument
to the call result throws away Atropos's most valuable information: exactly
which argument is dangerous. `memcpy`'s length is `Argument[2]`; its source
pointer `Argument[1]` is read-from, not a write target. The binder attaches to
`v_mc_len` and `v_mc_dst`, and leaves `v_mc_src` alone.

## Matching

A model matches a callsite when the method names are equal. `package` and
`type` are disambiguating hints: each constrains **only** when the model
supplies it *and* the callsite carries a value to check it against. This keeps
flat C builtins (which have no module/receiver) matching on the callee spelling,
while a member call like `child_process.exec` narrows on its module.

## No model is ever silently ignored

Every applicable model resolves to exactly one status:

| Status              | Meaning                                                        |
|---------------------|----------------------------------------------------------------|
| `bound`             | resolved to a concrete node (or edge, for a summary)           |
| `symbol-not-found`  | no callsite in this index matches the model's symbol           |
| `ambiguous`         | matched more than one distinct symbol; the model did not pin it |
| `arity-mismatch`    | `Argument[n]` is out of range for the matched callsite          |
| `unsupported-path`  | an access path the binder cannot resolve (e.g. a richer path, or a required receiver the callsite lacks) |

`ambiguous` is the guard against binding to a same-named *application* symbol.
If an app defines its own `system`, a name-only model matches both it and the
libc one; the binder reports `ambiguous` with the candidates rather than
attaching to the wrong node. Resolving that ambiguity (a receiver type, a
module, a compiler-resolved target) is how the model earns a clean bind.

## Why this is the acceptance test, not the schema

[`tools/validate.py`](../tools/validate.py) proves an entry is *well-formed*:
right fields, valid enums, a grammatical access path. It cannot prove the entry
is *true* — that `read`'s buffer is `Argument[1]` and not `Argument[0]` (the
fd). Only binding against a graph can. So the gate has two layers:

- **schema validation** — shape, on every entry, zero-dependency;
- **binding fixtures** ([`fixtures/`](../fixtures), run by
  [`tests/test_binding.py`](../tests/test_binding.py)) — tiny committed
  symbol-index exports with hand-verified expected nodes, proving that sinks
  land on exactly the named argument, that innocent neighbours are not sinks,
  that a summary yields the right edge, and that same-named symbols are flagged
  ambiguous rather than mis-bound.

An entry is accepted when it is well-formed **and** it binds to the node a
reviewer verified is the true attachment. A valid-looking name is not enough.

## Running it

```bash
python3 tools/bind.py fixtures/c_buffer.index.json   # binding report for one index
python3 -m unittest discover -s tests                # schema + binding gate
```

## Validated against real graphs

The fixtures prove the contract in miniature; the same binder has been run
against full symbol-index exports of real projects to confirm it holds at scale.
Two frontend facts surfaced and are worth recording for any engine writing an
exporter:

- **Argument linkage is frontend-specific.** A C export attaches arguments one
  way; a Python/TypeScript export attaches them another. An exporter must emit
  the neutral index's `arg_value_ids` in positional order regardless of how its
  own graph spells arguments — order them by source position when in doubt.
- **Precision needs receiver typing.** With `module` and `receiver_type` left
  null, the binder can only disambiguate by arity, so a bare `.get()` or
  `.request()` that appears at several receivers is reported `ambiguous` rather
  than mis-bound. Populating those two fields is what turns an ambiguous match
  into a precise one. The binder failing safe here is the design working, not a
  gap in the models.

Every `arity-mismatch` observed traced to a real callsite that passed fewer
positional arguments (the rest keyword or defaulted), never to a wrong index in
the catalog — which is exactly the honest per-callsite reporting the contract
promises.
