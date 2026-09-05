"""Single source of truth for the distributed package version.

This is the version of the *installable atropos package* (the loader + CLI), which
is distinct from the versioned data pack it carries (see ``pack.json`` / ``VERSION``
for the catalog-content version). The package tracks the library/CLI surface; the
pack version tracks the taint facts. They move on independent schedules.
"""

__version__ = "1.0.0"
