# Changelog

## Unreleased

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
