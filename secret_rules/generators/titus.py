"""Generate a titus YAML ruleset (noseyparker format + scores + named groups)."""

from __future__ import annotations

import yaml

from secret_rules.model import Rule
from secret_rules.normalize import capture_groups, insert_group_name

from . import noseyparker
from ._common import header

FILENAME = "titus.yml"

_SCORES = {"high": 85, "medium": 60, "low": 40}


def generate(rules: list[Rule]) -> str:
    out_rules = noseyparker.build_rules(rules, id_prefix="sr")
    for rule, entry in zip(rules, out_rules):
        entry["base_score"] = _SCORES.get(rule.confidence or "", 50)
        if rule.secret_group and len(capture_groups(entry["pattern"])) >= rule.secret_group:
            entry["pattern"] = insert_group_name(
                entry["pattern"], rule.secret_group, rule.secret_group_name or "secret"
            )
        if rule.entropy is not None:
            entry["min_entropy"] = float(rule.entropy)
    body = yaml.safe_dump({"rules": out_rules}, sort_keys=False, allow_unicode=True, width=100000)
    return header("titus", len(out_rules), []) + body
