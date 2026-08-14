<!-- Thanks for contributing to Atropos! -->

## What this adds

<!-- Which symbol(s), and why they belong in the role/kind you assigned. -->

## Checklist

- [ ] Entry lives in the right `models/<language>/<role>s.json`, and `role` matches the file's `role_group`
- [ ] `access_path` is bindable (`Argument[n]`, `Argument[*]`, `ReturnValue`, `Receiver`, or `a -> b`)
- [ ] `cwe` uses public `CWE-<n>` identifiers only
- [ ] `python3 tools/validate.py` passes
- [ ] `python3 -m unittest discover -s tests` passes
