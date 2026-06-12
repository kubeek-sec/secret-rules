"""Parser for the gitleaks TOML ruleset."""

from __future__ import annotations

import tomllib
from pathlib import Path

from secret_rules.model import Rule

from ._common import make_rule, str_list, topic_from_id


def parse(path: Path) -> list[Rule]:
    toml_file = next(path.glob("*.toml"))
    data = tomllib.loads(toml_file.read_text())

    rules: list[Rule] = []
    for raw in data.get("rules", []):
        regex = raw.get("regex")
        if not regex:
            # path-only rules have no content regex; nothing portable to keep
            continue
        allow_regexes: list[str] = []
        ignore: list[str] = []
        for allow in raw.get("allowlists", []):
            allow_regexes.extend(str_list(allow.get("regexes")))
            ignore.extend(str_list(allow.get("stopwords")))
        rule_id = raw["id"]
        rules.append(
            make_rule(
                scanner="gitleaks",
                source_id=rule_id,
                name=rule_id.replace("-", " ").title(),
                topic=topic_from_id(rule_id),
                pattern=regex,
                secret_group_hint=raw.get("secretGroup"),
                description=raw.get("description"),
                keywords=str_list(raw.get("keywords")),
                entropy=raw.get("entropy"),
                allowlist_regexes=allow_regexes,
                ignore_if_contains=ignore,
            )
        )
    return rules
