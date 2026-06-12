"""Config generators: referential rules -> native scanner config files."""

from __future__ import annotations

from . import betterleaks, gitleaks, kingfisher, noseyparker, titus, trufflehog, yara

TARGETS = {
    "betterleaks": betterleaks,
    "gitleaks": gitleaks,
    "kingfisher": kingfisher,
    "noseyparker": noseyparker,
    "titus": titus,
    "trufflehog": trufflehog,
    "yara": yara,
}
