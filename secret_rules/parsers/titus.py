"""Parser for titus YAML rule files (noseyparker fork with scores)."""

from __future__ import annotations

from pathlib import Path

from secret_rules.model import Rule

from . import noseyparker


def parse(path: Path) -> list[Rule]:
    return noseyparker.parse(path, scanner="titus")
