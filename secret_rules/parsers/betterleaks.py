"""Parser for the betterleaks TOML ruleset (gitleaks-like rules + CEL filters)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from secret_rules.model import Rule

from ._common import make_rule, str_list, topic_from_id

# betterleaks expresses the entropy threshold inside a CEL filter, e.g.:
#   entropy(finding["secret"]) <= 4.0
_ENTROPY_CEL = re.compile(r'entropy\(finding\["secret"\]\)\s*<=?\s*([0-9.]+)')


def parse(path: Path) -> list[Rule]:
    toml_file = next(path.glob("*.toml"))
    data = tomllib.loads(toml_file.read_text())

    rules: list[Rule] = []
    for raw in data.get("rules", []):
        regex = raw.get("regex")
        if not regex:
            continue
        entropy = None
        if raw.get("filter"):
            m = _ENTROPY_CEL.search(raw["filter"])
            if m:
                entropy = float(m.group(1))
        rule_id = raw["id"]
        rules.append(
            make_rule(
                scanner="betterleaks",
                source_id=rule_id,
                name=rule_id.replace("-", " ").title(),
                topic=topic_from_id(rule_id),
                pattern=regex,
                secret_group_hint=raw.get("secretGroup"),
                description=raw.get("description"),
                keywords=str_list(raw.get("keywords")),
                entropy=entropy,
            )
        )
    return rules
