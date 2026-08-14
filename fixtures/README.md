# Binding fixtures

Each family has two files:

- `*.c` (or `.py`, `.js`, `.ts`) — a **human reference**: the tiny source the
  index stands for. Not used by the binder.
- `*.index.json` — a **neutral symbol-index export**
  ([schema](../schema/symbol-index.schema.json)): the callsites and their
  per-argument value-node handles, as an engine would export them. Node ids
  are hand-authored and stable so the tests can assert exact attachments.

[`tests/test_binding.py`](../tests/test_binding.py) runs the binder over these
and asserts the node each model lands on. This is where a model proves it is a
fact — see [`docs/binding.md`](../docs/binding.md).
