"""Destinations for the rotated secret's new value (used by ``update``).

A sink is where the freshly minted secret gets written once rotation produced
it.  Supported sink specs:

    stdout                 print the value to stdout (explicit opt-in via --show)
    file:PATH              write the raw value to PATH (created mode 0600)
    dotenv:PATH#VAR        upsert `VAR=value` in a .env-style file
    exec:COMMAND           run COMMAND, piping the value on stdin
                           (e.g. a Vault / AWS Secrets Manager write wrapper)

Keeping the write behind an explicit sink means this tool never silently
persists a credential anywhere.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


class SinkError(Exception):
    pass


def write_sink(spec: str, value: str, *, show: bool = False) -> str:
    """Write ``value`` to the destination described by ``spec``.

    Returns a human-readable description of what was written (never the value).
    """
    if spec == "stdout":
        if not show:
            raise SinkError("refusing to print the secret; pass --show to confirm stdout output")
        print(value)
        return "wrote new value to stdout"

    kind, _, rest = spec.partition(":")
    if kind == "file":
        path = Path(rest).expanduser()
        path.write_text(value)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return f"wrote new value to {path} (mode 0600)"

    if kind == "dotenv":
        file_part, _, var = rest.partition("#")
        if not var:
            raise SinkError("dotenv sink needs a variable: dotenv:/path/.env#VAR_NAME")
        return _dotenv_upsert(Path(file_part).expanduser(), var, value)

    if kind == "exec":
        if not rest:
            raise SinkError("exec sink needs a command: exec:'vault kv put ...'")
        proc = subprocess.run(
            rest, shell=True, input=value, text=True, capture_output=True
        )
        if proc.returncode != 0:
            raise SinkError(f"exec command failed (exit {proc.returncode}): {proc.stderr.strip()}")
        return f"piped new value to `{rest}` (exit 0)"

    raise SinkError(f"unknown sink spec: {spec!r}")


def _dotenv_upsert(path: Path, var: str, value: str) -> str:
    lines: list[str] = []
    if path.exists():
        lines = path.read_text().splitlines()
    prefix = f"{var}="
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            lines[i] = f"{var}={value}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{var}={value}")
    path.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    action = "updated" if replaced else "added"
    return f"{action} {var} in {path} (mode 0600)"
