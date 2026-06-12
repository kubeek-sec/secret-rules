"""Parser for noseyparker YAML rule files."""

from __future__ import annotations

from pathlib import Path

import yaml

from secret_rules.model import Rule

from ._common import make_rule, str_list


def parse(path: Path, scanner: str = "noseyparker") -> list[Rule]:
    rules: list[Rule] = []
    for f in sorted(path.glob("*.yml")):
        data = yaml.safe_load(f.read_text())
        if not data or "rules" not in data:
            continue
        for raw in data["rules"]:
            pattern = raw.get("pattern")
            if not pattern or not raw.get("id"):
                continue
            reqs = raw.get("pattern_requirements") or {}
            confidence = raw.get("confidence")
            if confidence is None and raw.get("base_score") is not None:
                # titus scores roughly map onto confidence buckets
                score = raw["base_score"]
                confidence = "high" if score >= 75 else "medium" if score >= 50 else "low"
            rules.append(
                make_rule(
                    scanner=scanner,
                    source_id=raw["id"],
                    name=raw.get("name") or raw["id"],
                    topic=f.stem,
                    pattern=pattern,
                    group1_is_secret=True,
                    description=raw.get("description"),
                    entropy=raw.get("min_entropy"),
                    confidence=confidence,
                    categories=str_list(raw.get("categories")),
                    references=str_list(raw.get("references")),
                    examples=str_list(raw.get("examples")),
                    negative_examples=str_list(raw.get("negative_examples")),
                    ignore_if_contains=str_list(reqs.get("ignore_if_contains")),
                )
            )
    return rules
