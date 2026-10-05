"""Credential verification & rotation helpers for the secret-rules referential.

- ``check``   proves a detected secret is live, using read-only API calls only.
- ``rotate``  verifies, then prints a remediation runbook (optionally self-revokes).
- ``update``  verifies a new value and installs it into a sink.

See ``verify/README.md``.  Importing this package registers all verifiers and
rotators as a side effect.
"""

from __future__ import annotations

from . import rotators, verifiers  # noqa: F401  (registration side effects)

__all__ = ["rotators", "verifiers"]
