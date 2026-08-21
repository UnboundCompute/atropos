# Releasing Atropos

Atropos is a versioned data catalog, not an executable package. A release is the exact
set of model files, schema, and validation tooling that a Lachesis consumer can bind
deterministically.

## Release gate

From a clean checkout, run:

```bash
make check
python3 tools/stats.py
```

The validator must pass with no warnings that change model status, and the binding
fixtures must report only the documented `bound`, `ambiguous`, `symbol-not-found`,
`arity-mismatch`, or `unsupported-path` outcomes. Never remove an unbound model to make
the gate green; move it to `candidates/` if it is not yet a verified fact.

The `release catalog` workflow repeats this gate for every `v*` tag and publishes a
deterministic, content-addressed source archive plus `SHA256SUMS` as workflow artifacts.
The archive is built with the tag commit timestamp and a normalized gzip header, so
rebuilding the same tag produces the same bytes. It does not silently publish mutable
catalog data.

Verify a downloaded archive before unpacking it:

```bash
sha256sum -c SHA256SUMS --ignore-missing       # Linux
shasum -a 256 -c SHA256SUMS                   # macOS
```

## Versioning and publication

Update the version in `README.md` and `CHANGELOG.md`, commit the model changes, then
create an annotated tag (`vMAJOR.MINOR.PATCH`). Consumers should pin a tag or commit,
not fetch `main`, so a catalog update cannot silently change a scan result.

The catalog is distributed as source data. Preserve `LICENSE`/CC BY attribution and
include the tag and content hash in downstream scan metadata.

## Review checklist

- Every new fact has a public reference and a precise access path.
- CWE identifiers and role/kind taxonomy validate.
- A fixture proves the intended symbol binding where practical.
- Candidates under review remain excluded from consumer model loads.
- The changelog explains additions, corrections, and removals.
