"""Generate a kingfisher YAML ruleset from the referential."""

from __future__ import annotations

import yaml

from secret_rules.model import Rule

from ._common import header, id_segment

FILENAME = "kingfisher.yml"


def generate(rules: list[Rule]) -> str:
    out_rules = []
    counters: dict[str, int] = {}
    for rule in rules:
        counters[rule.topic] = counters.get(rule.topic, 0) + 1
        entry: dict = {
            "name": rule.name,
            "id": f"secretrules.{id_segment(rule.topic)}.{counters[rule.topic]}",
            "pattern": rule.pattern,
            "confidence": rule.confidence or "medium",
        }
        if rule.entropy is not None:
            entry["min_entropy"] = float(rule.entropy)
        if rule.ignore_if_contains:
            entry["pattern_requirements"] = {"ignore_if_contains": rule.ignore_if_contains}
        if rule.references:
            entry["references"] = rule.references
        if rule.examples:
            entry["examples"] = rule.examples
        if rule.negative_examples:
            entry["negative_examples"] = rule.negative_examples
        out_rules.append(entry)

    body = yaml.safe_dump({"rules": out_rules}, sort_keys=False, allow_unicode=True, width=100000)
    return header("kingfisher", len(out_rules), []) + body
