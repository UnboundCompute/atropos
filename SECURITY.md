# Security Policy

Please report catalog or tooling vulnerabilities privately through GitHub Private
Vulnerability Reporting rather than a public issue or pull request.

Include the affected tag or commit, model/tool path, a minimal reproducer, and the
impact. Atropos is declarative data, but its validators and binders process files
that may come from untrusted repositories; parser, path-traversal, and resource
exhaustion issues are in scope. Keep downstream scan data out of the report.

Security fixes are made against the latest supported tag. Consumers should pin a
reviewed catalog tag or commit and upgrade deliberately.
