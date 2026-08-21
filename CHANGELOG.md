# Changelog

## Unreleased

- `tools/stats.py` now reports malformed, unreadable, or structurally invalid
  model files as actionable CLI errors instead of exposing a traceback.
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
