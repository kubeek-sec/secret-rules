"""Importing this package populates ``core.VERIFIERS`` as a side effect.

Each submodule registers its providers via the ``@register`` decorator /
``http_check`` factory.  Add a new module here to extend coverage.
"""

from . import custom, generic, offline, providers  # noqa: F401  (registration side effects)
