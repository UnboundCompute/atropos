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

> **Status: v1.10.0, actively curated.** 1618 verified facts (plus 7 candidates under review). The data is
> validated on every change. Contributions are welcome, see
> [Contributing](#contributing).

The catalog is also installable as a zero-dependency Python package with a query
API and a `atropos` command line — see [Install the package](#install-the-package).

Release and pinning guidance is in [`RELEASING.md`](RELEASING.md), and user-visible
catalog changes are tracked in [`CHANGELOG.md`](CHANGELOG.md). Consumers should pin a
tag or commit so model updates are explicit and reproducible. The current catalog
version is recorded in [`VERSION`](VERSION), and release tags must match it.
Security reporting guidance is in [`SECURITY.md`](SECURITY.md).

The catalog tooling and the installable package support Python 3.9 through 3.12
and use only the standard library. The validation workflow exercises all four
supported versions.

## Install the package

The catalog ships as a self-contained Python package (Python 3.9+, no
dependencies) that bundles the data, so you can query sinks, sources, sanitizers,
and flow summaries without cloning this repo.

```bash
pip install atropos
```

Command line:

```bash
atropos stats                              # coverage snapshot
atropos sinks -l python --kind sql-injection
atropos sources -l javascript
atropos resolve python execute --type Cursor   # what is this symbol?
atropos audit ./path/to/code               # enumerate catalogued symbol uses
atropos search deserialize                 # free-text over symbols and notes
atropos show c.std.memcpy.a2               # one fact by id
atropos export -l c --role sink -f csv     # json | jsonl | csv for pipelines
```

`atropos audit` walks a file or directory, finds every call site, and reports the
ones a catalogued symbol attaches to — pointing each fact at the concrete argument,
receiver, or return value to watch. Python is parsed with the standard-library
`ast` (with import resolution, so `os.system` binds exactly); C, JavaScript, and
TypeScript use a lexical scanner that masks strings and comments. Each finding
carries a binding confidence — `exact`, `heuristic`, or `name-only` — kept separate
from the catalog's own per-fact confidence, so you can filter by how sure the match
is:

```bash
atropos audit ./src --min-match exact          # only pinned bindings
atropos audit ./src -k sql-injection --json    # one kind, machine-readable
atropos audit app.py --role sink --role source # enumerate more than sinks
```

It is an enumerator, not an engine: it says where a catalogued symbol is *used* and
how sure the binding is, never whether tainted data actually reaches it. That
verdict stays with the graph engine and the reviewer.

The audit feeds several consumption modes, each a different way to spend the same
findings:

```bash
atropos audit ./src -f sarif > out.sarif    # GitHub code scanning / CI / IDE
atropos coverage ./src                      # counts by kind/lang, hot files, gaps
atropos surface ./src                       # files with both a source and a sink
atropos conformance ./src                   # sink kinds used with no sanitizer present
atropos diff ./src -b baseline.json         # CI gate: fail on new findings only
atropos rules -l python -o policy.json      # portable lint / banned-API watch-list
atropos ground --cwe 89 -l python           # catalog facts as LLM grounding context
atropos validate python system -a 'Argument[0]' --role sink -p os   # adjudicate a claim
```

`coverage` rolls findings up into the shape of a codebase's attack surface and names
the kinds the catalog covers but the target never used. `surface` ranks the files
that hold both a catalogued source and a sink — where the shortest flow could live —
into a review worklist. `conformance` asks, per sink kind the code exercises, whether
a sanitizer the catalog models for that kind appears anywhere in the code — flagging
the kinds used with none present, without claiming any particular sink is guarded.
`diff` re-audits against a recorded baseline and exits
non-zero only on findings new since it, with line-independent fingerprints so moved
code does not read as new. `rules` projects the catalog itself into an enforceable
policy other tools can bind without Atropos. None of them makes a verdict.

`ground` and `validate` put the catalog underneath a language model. `ground`
gathers the facts for a taint class (by `--cwe`, `--kind`, or free text) into a
compact block — sinks with the slot to watch, plus sanitizers and sources — to drop
into a prompt as ground truth instead of the model's own recall. `validate`
adjudicates a fact the model *proposed* against the catalog — `confirmed`, `partial`
(right symbol, wrong watchpoint), `role-conflict`, or `unknown` — exiting non-zero
when a claim is uncorroborated, so a hallucinated sink is caught before it is
trusted. Both ground claims about the catalog's knowledge; neither reasons about a
program.

Library:

```python
import atropos

cat = atropos.load()                       # discovers the bundled catalog
for e in cat.find(language="python", role="sink", kind="command-injection"):
    print(e.id, e.symbol, e.access_path, e.cwe)

cat.resolve("javascript", "exec", package="child_process")  # bind a call site
cat.stats()                                # counts by language/role/kind
```

Every fact is an `Entry` with the schema fields (`id`, `language`, `package`,
`type`, `method`, `access_path`, `role`, `kind`, `cwe`, …). By default the loader
discovers the data bundled in the wheel; point it at a specific catalog with the
`ATROPOS_ROOT` environment variable or `atropos.load(root=...)` to run against a
checkout or an installed pack.

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
  "id": "c.std.memcpy.a2",
  "language": "c", "package": null, "type": null, "method": "memcpy",
  "signature": null,
  "access_path": "Argument[2]", "role": "sink", "kind": "buffer-size",
  "cwe": ["CWE-787", "CWE-120"], "confidence": "high", "corroboration": 3
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
pack.json       versioned core-pack metadata and provenance policy
atropos/        installable Python package: loader, Catalog query API, and CLI
tools/          validate.py  bind.py  stats.py   # stdlib only, zero deps
fixtures/       tiny symbol-index exports with verified node handles
tests/          test_models.py  test_binding.py  test_package.py
docs/           binding.md
```

1618 verified facts at the time of writing, covering all four languages Lachesis parses
(C, Python, JavaScript, TypeScript) across 23 sink kinds: buffer overflow,
command / code / SQL / LDAP / XPath / NoSQL / template injection, path traversal,
deserialization, unsafe reflection, SSRF, XXE, XSS, open redirect, prototype
pollution, ReDoS, format string, weak crypto and randomness, insecure TLS, and
more. Sinks, sources, sanitizers, and
flow summaries (documented src->dest / input->return behavior that lets the
engine drop its conservative every-argument-flows-to-return default).

## Using the data

```bash
python3 tools/validate.py     # gate 1: schema shape, unique ids, grammatical access paths
python3 tools/validate_pack.py # pack metadata, version authority, and coverage
python3 tools/build_pack.py --output /tmp/atropos-core-$(cat VERSION).zip \
  --checksums /tmp/atropos-core.sha256 \
  --provenance /tmp/atropos-core.provenance.json # deterministic archive + evidence
python3 tools/bind.py fixtures/c_buffer.index.json   # resolve local models to exact graph nodes
python3 tools/bind.py fixtures/c_buffer.index.json --models-root /tmp/unpacked-pack/models
python3 tools/stats.py        # human-readable coverage snapshot
python3 tools/stats.py --json # machine-readable coverage for release/docs automation
python3 -m unittest discover -s tests   # gate 2: binding fixtures + schema

# scaffold a new entry, then validate and add a binding fixture
python3 tools/new_model.py python.demo.exec.arg0 --language python --role sink \
  --method exec --package demo --access-path 'Argument[0]' \
  --kind command-injection --cwe CWE-78
# then generate a neutral binding fixture for the new model
python3 tools/new_fixture.py python.demo.exec.arg0 --output-dir fixtures
```

For the complete local gate used by CI and release verification, run `make check`.

`pack.json` is the machine-readable boundary for the current core catalog. It
records supported languages, model coverage, license, source repository, and
whether consumers must bind facts before use. `tools/validate_pack.py` checks it
against `VERSION` and the files in `models/`; future independently distributed
framework packs can use the same contract.

To create a portable artifact, run `make pack` or invoke `build_pack.py` with an
output path. The archive uses stable file ordering and timestamps, then prints a
SHA-256 digest suitable for release checksums. Pack archives contain metadata,
verified model files, runtime profiles/detection catalogs, license, and optional
package documentation; candidates remain outside the consumer glob. The runtime
catalogs are included because Lachesis reads them for normalization, dispatch, and
evaluator behavior, so an installed pack is self-contained rather than just a
model-row snapshot. The
optional checksum and provenance sidecars record the artifact digest, pack
identity/version, source revision when available, and exact archive file list.

Download the consumer-ready pack from the [Atropos GitHub Releases](https://github.com/UnboundCompute/atropos/releases),
then verify the publisher's checksum and install it without manually extracting it:

```bash
python3 tools/install_pack.py /path/to/atropos-core-1.10.0.zip \
  --sha256 "<64-character digest>"
# then point a consumer at the printed directory:
ATROPOS_ROOT="$HOME/.atropos/packs/atropos.core/1.10.0" lachesis scan ./repository
```

The installer rejects unsafe archive paths, special files, checksum mismatches, and
packs that fail the manifest/license/coverage validator. It installs atomically under
`~/.atropos/packs/<pack-id>/<version>` and never replaces an existing version.

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
