"""Append-only audit ledger of secret changes (rotate / update).

Each change is one JSON object on its own line (JSONL) in a file that is **git
-ignored** and written mode ``0600`` — it can hold sensitive material.

By default the ledger records *fingerprints* of the old and new values (enough
to correlate "which secret changed to which"), never the raw secrets.  Pass
``record_secret=True`` (CLI: ``--record-secret``) to also store the new value in
plaintext, for teams who use the ledger as the source of the value to deploy.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path

from .core import fingerprint

# repo-root / secret-rotations.jsonl by default
_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LEDGER = _REPO_ROOT / "secret-rotations.jsonl"


def record(
    path: Path,
    *,
    action: str,
    topic: str,
    uid: str | None = None,
    old_secret: str | None = None,
    new_secret: str | None = None,
    generated: bool = False,
    new_entropy_bits: float | None = None,
    verified: str | None = None,
    revoked: str | None = None,
    sink: str | None = None,
    record_secret: bool = False,
) -> dict:
    """Append one entry and return it (without any plaintext secret)."""
    entry: dict = {
        "time": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "action": action,
        "topic": topic,
        "operator": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
    }
    if uid:
        entry["uid"] = uid
    if old_secret is not None:
        entry["old_fingerprint"] = fingerprint(old_secret)
    if new_secret is not None:
        entry["new_fingerprint"] = fingerprint(new_secret)
    if generated:
        entry["generated"] = True
    if new_entropy_bits is not None:
        entry["new_entropy_bits"] = round(new_entropy_bits, 1)
    if verified:
        entry["verified"] = verified
    if revoked:
        entry["revoked"] = revoked
    if sink:
        entry["sink"] = sink

    on_disk = dict(entry)
    if record_secret and new_secret is not None:
        on_disk["new_secret"] = new_secret  # sensitive — only on explicit opt-in

    path = Path(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(on_disk, ensure_ascii=False) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return entry  # caller-facing copy never carries the plaintext
