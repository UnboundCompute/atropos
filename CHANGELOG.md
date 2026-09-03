# Changelog

## Unreleased

- Add a resolver/enumerator and the `atropos audit <path>` command: walk a file
  or directory, extract call sites (Python via the stdlib `ast` with import
  resolution; C/JS/TS via a lexical scanner that masks strings and comments), and
  join each site to the catalog facts that attach to it, pointing every fact at the
  concrete argument/receiver/return slot. Each finding carries a binding confidence
  — `exact`, `heuristic`, or `name-only` — separate from the catalog's own
  per-fact confidence. Still no engine and no verdict: it enumerates where
  catalogued symbols are used, not whether tainted data reaches them.
- Add SARIF 2.1.0 output to `atropos audit` (`-f sarif`): a full log with one
  reporting rule per kind, a CWE taxonomy, per-result regions, and stable
  partial fingerprints, for GitHub code scanning / CI / IDE ingestion.
- Add `atropos coverage <path>`: roll the audit up into counts by kind, language,
  role, and binding confidence, the top symbols and hottest files, and the gap —
  catalogued sink kinds (for the languages present) that the target never
  exercised, so a genuinely clean class is distinguishable from an unmodelled one.
- Add `atropos diff <path> --baseline <audit.json>`: a CI gate that re-audits and
  reports only findings new since a recorded baseline, exiting non-zero when any
  appear (`--exit-zero` to report without failing). Fingerprints exclude line and
  column so moving or reformatting code does not read as new, while adding a second
  identical call still does.
- Add `atropos surface <path>`: a threat-surface worklist that ranks files holding
  both a catalogued source (where untrusted input enters) and a catalogued sink,
  listing each file's sources and sink kinds. No flow is claimed — same-file
  co-location is the precondition for the shortest flow, i.e. where a reviewer or a
  real taint engine should look first.

## 1.10.0

- Grow the catalog from 1139 to 1618 verified facts across all four languages,
  filling the largest coverage gaps found in an ecosystem audit.
- C: add weak-crypto primitives (MD5/SHA1/DES/RC4/Blowfish), insecure-TLS method
  selectors, SQL/LDAP/XPath injection sinks, format-string and path-traversal
  sinks, predictable-seed sinks, untrusted-input sources, and SQL-escaper
  sanitizers.
- Python: add pandas/numexpr/sympy code execution, pathlib file I/O and Zip-Slip
  archive extraction, SSRF clients, ML deserialization loaders, reflection sinks
  (getattr/setattr/pydoc.locate/importlib), framework request sources
  (Flask/Django/FastAPI/aiohttp/Tornado), and coercion/normalization sanitizers.
- JavaScript: add SQL drivers, Mongoose NoSQL, synchronous fs traversal, HTTP
  client SSRF/redirect, jQuery/DOM XSS, template engines, and deserializers, plus
  process.env/req.params/document.cookie sources and escaping sanitizers.
- TypeScript: mirror the JavaScript library surfaces and add framework-specific
  sinks — Angular DomSanitizer/Renderer2 (XSS), Router (open redirect), HttpClient
  (SSRF), TypeORM/Sequelize/Knex/Drizzle raw SQL, Deno command/file APIs,
  class-transformer, and NestJS parameter-decorator sources.
- Add the `unsafe-reflection` sink kind (CWE-470/CWE-915), routed to the
  reachability detection recipe.
- Ship an installable, zero-dependency `atropos` Python package: a catalog loader
  with `ATROPOS_ROOT`/checkout/bundle discovery, a `Catalog` query API, and an
  `atropos` command line (sinks/sources/resolve/search/show/export/stats).

## 1.9.0

- Add receiver-access regex sinks for JavaScript and TypeScript (`match`/`search`
  on the receiver, `test`/`exec` on the argument) so subject-tainted regular
  expression evaluation is watchable — the shape behind catastrophic-backtracking
  denial of service.
- Add DOM write sinks for `innerHTML` and `outerHTML` (assignment argument) in
  JavaScript and TypeScript, the markup path behind DOM-based cross-site scripting.
- Add a computed property-write sink for prototype-pollution watchpoints in
  JavaScript and TypeScript.

## 1.8.0

- Add `pack.json` core-pack metadata and `tools/validate_pack.py` coverage/version
  gate for distributable catalog provenance.
- Add `tools/new_model.py` to scaffold role-grouped entries and reject duplicate IDs
  across verified models and candidates.
- Add `tools/new_fixture.py` to generate a minimal source reference and neutral
  symbol-index fixture from an existing model ID.
- Add deterministic `tools/build_pack.py` archives with printed SHA-256 digests,
  plus external-root validation for framework-pack development.
- Add optional checksum and JSON provenance sidecars to pack builds.
- Allow `tools/bind.py` to consume an extracted pack through `--models-root`.
- Require and include the declared license file in distributable pack archives.

## 1.7.1

- Release the production-readiness and release-reference fixes from `main`.

- Align contributor documentation with the Python 3.10–3.12 compatibility window
  exercised by CI and release verification.
- Added a machine-readable `VERSION` file; release CI now rejects tags that do not
  match the catalog version declared by the checkout.
- The local model test gate now checks that `VERSION`, the README status, and the
  changelog release heading remain synchronized.

- The catalog validation workflow now exercises the supported Python 3.10, 3.11, and
  3.12 interpreters instead of relying on an unbounded `3.x` runner.

- Release verification now smoke-tests the extracted source archive with `make check`,
  catching incomplete or malformed uploaded artifacts before publication.

- Contributor installation guidance now uses `python -m pip` to bind the
  command to the selected interpreter.
- `make check` now includes the coverage/stats integrity check, so local, CI,
  and release gates run the same catalog verification set.
- `tools/stats.py` now reports malformed, unreadable, or structurally invalid
  model files as actionable CLI errors instead of exposing a traceback.
- `tools/bind.py` now rejects malformed symbol-index and catalog inputs before
  binding, with actionable diagnostics instead of partial reports or tracebacks.
- `tools/bind.py` now validates nested symbol-index field types and unknown fields
  before binding, so malformed node handles cannot produce partial or misleading
  attachments.
- Fixed the release workflow's catalog validation step so `make check` and the
  coverage snapshot run as two commands instead of one folded shell command.
- The validator now reports missing, corrupt, or malformed schema files as
  actionable gate failures instead of exposing a traceback.
- Added a dependency-free `make check` target and made CI/release verification use
  the same catalog validation and binding-test command developers run locally.
- The dependency-free `validate.py`, `stats.py`, and `bind.py` tools now expose
  consistent `--help` output and reject unknown options instead of doing surprising
  work or treating flags as file paths.
- Added release guidance for deterministic catalog pinning, validation, and attribution.
- Release archives are rebuilt and hash-compared in CI before checksums are published.
- Validator and binder CLIs now report malformed, unreadable, or missing inputs without
  traceback-only failures.

## 1.7.0

- 1,121 verified facts and 7 candidates under review, as recorded in the catalog README.
