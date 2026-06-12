"""Generate a noseyparker YAML ruleset from the referential."""

from __future__ import annotations

import yaml

from secret_rules.model import Rule

from ._common import ensure_capture_group, header, id_segment

FILENAME = "noseyparker.yml"


def build_rules(rules: list[Rule], id_prefix: str = "sr") -> list[dict]:
    out_rules = []
    counters: dict[str, int] = {}
    for rule in rules:
        counters[rule.topic] = counters.get(rule.topic, 0) + 1
        entry: dict = {
            "name": rule.name,
            "id": f"{id_prefix}.{id_segment(rule.topic)}.{counters[rule.topic]}",
            "pattern": ensure_capture_group(rule.pattern),
        }
        if rule.description:
            entry["description"] = rule.description
        if rule.categories:
            entry["categories"] = rule.categories
        if rule.references:
            entry["references"] = rule.references
        if rule.examples:
            entry["examples"] = rule.examples
        if rule.negative_examples:
            entry["negative_examples"] = rule.negative_examples
        out_rules.append(entry)
    return out_rules


def generate(rules: list[Rule]) -> str:
    out_rules = build_rules(rules)
    body = yaml.safe_dump({"rules": out_rules}, sort_keys=False, allow_unicode=True, width=100000)
    return header("noseyparker", len(out_rules), []) + body
