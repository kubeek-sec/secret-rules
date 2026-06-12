"""Generate a trufflehog custom-detectors config from the referential.

trufflehog requires every custom detector to declare keywords (used as a
prefilter: a chunk must contain one of them before the regex runs).  When
the referential has no reliable keywords for a rule we fall back to broader
literal extraction; rules where even that fails are skipped, since a
detector with a wrong keyword would silently never match.
"""

from __future__ import annotations

import yaml

from secret_rules.model import Rule
from secret_rules.referential import extract_keywords

from ._common import header, re2_compatible

FILENAME = "trufflehog.yml"


def generate(rules: list[Rule]) -> str:
    detectors = []
    skipped: list[str] = []
    for rule in rules:
        if not re2_compatible(rule.pattern):
            skipped.append(rule.uid)
            continue
        keywords = rule.keywords or extract_keywords(rule.pattern, max_keywords=10)
        if not keywords:
            skipped.append(rule.uid)
            continue
        group_name = (rule.secret_group_name or "secret") if rule.secret_group else "secret"
        detectors.append(
            {
                "name": rule.uid,
                "keywords": sorted(k.lower() for k in keywords),
                "regex": {group_name: rule.pattern},
            }
        )
    body = yaml.safe_dump({"detectors": detectors}, sort_keys=False, allow_unicode=True, width=100000)
    return header("trufflehog", len(detectors), skipped) + body
