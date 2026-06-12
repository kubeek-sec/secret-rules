"""Parsers turning each scanner's native ruleset into a list of `Rule`."""

from __future__ import annotations

from pathlib import Path

from secret_rules.model import Rule

from . import betterleaks, gitleaks, kingfisher, noseyparker, titus

_PARSERS = {
    "betterleaks": betterleaks.parse,
    "gitleaks": gitleaks.parse,
    "kingfisher": kingfisher.parse,
    "noseyparker": noseyparker.parse,
    "titus": titus.parse,
}


def discover_sources(rules_dir: Path) -> dict[str, Path]:
    """Map scanner name -> ruleset directory, from dirs named `<scanner>-v<ver>`."""
    found: dict[str, Path] = {}
    for child in sorted(rules_dir.iterdir()):
        if not child.is_dir():
            continue
        scanner = child.name.split("-v")[0]
        if scanner in _PARSERS:
            found[scanner] = child
    return found


def parse_all(rules_dir: Path) -> dict[str, list[Rule]]:
    """Parse every discovered ruleset; returns scanner -> rules."""
    out: dict[str, list[Rule]] = {}
    for scanner, path in discover_sources(rules_dir).items():
        out[scanner] = _PARSERS[scanner](path)
    return out
