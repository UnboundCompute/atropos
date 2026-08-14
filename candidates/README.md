# Candidates — not facts yet

Entries here are **not** part of the catalog a consumer loads. `models/` holds
verified facts; `candidates/` holds symbols we know are security-relevant but
cannot yet state as a precise, bindable fact.

An entry lands here when its danger is real but its attachment is not
expressible under the current access-path grammar — for example a weak-crypto
primitive selected by a no-argument constructor (`cryptography.hazmat`'s
`MD5()`, `modes.ECB()`), or a class whose dangerous input arrives through a
later method call rather than the constructor (`urllib.request.URLopener`).
Attaching `Argument[0]` to these would be a guess, and a guess is exactly what
`models/` must not contain.

Rules:

- The binder and any consumer walk `models/**` only. Nothing here is loaded by
  default.
- These files are still schema-validated (`tools/validate.py` gates them and
  shares the id namespace, so a candidate can never collide with a fact).
- An entry graduates to `models/` when it earns a precise, verified access path
  — a richer path the grammar grows to support, or a banned-API check the engine
  learns to express — and a reviewer confirms the attachment against a graph.

Keeping them visible but separate means a known-dangerous API is never silently
dropped, and never silently promoted to a fact it hasn't earned.
