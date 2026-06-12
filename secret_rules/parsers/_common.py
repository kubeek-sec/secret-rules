"""Helpers shared by the source parsers."""

from __future__ import annotations

import re

from secret_rules.model import Rule, SourceRef
from secret_rules.normalize import canonicalize

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")


def topic_from_id(rule_id: str) -> str:
    """Heuristic topic for flat rulesets (gitleaks/betterleaks): id prefix."""
    return slugify(rule_id).split("-")[0]


def make_rule(
    *,
    scanner: str,
    source_id: str,
    name: str,
    topic: str,
    pattern: str,
    secret_group_hint: int | None = None,
    group1_is_secret: bool = False,
    **kw,
) -> Rule:
    """Canonicalize the pattern and infer the secret capture group."""
    canon = canonicalize(pattern)
    n_groups = max(canon.group_names.keys(), default=0)
    # count *all* groups, not just named ones
    from secret_rules.normalize import capture_groups

    all_groups = capture_groups(canon.pattern)
    n_groups = len(all_groups)

    secret_group = 0
    secret_group_name = None
    if canon.group_names:
        # prefer a group whose name suggests it holds the secret
        ranked = sorted(
            canon.group_names.items(),
            key=lambda kv: (0 if re.search(r"secret|token|key|password|credential", kv[1], re.I) else 1, kv[0]),
        )
        secret_group, secret_group_name = ranked[0]
    elif secret_group_hint:
        secret_group = secret_group_hint
    elif n_groups == 1 or (group1_is_secret and n_groups >= 1):
        secret_group = 1

    return Rule(
        uid=slugify(source_id),
        name=name,
        topic=topic,
        pattern=canon.pattern,
        secret_group=secret_group,
        secret_group_name=secret_group_name,
        sources=[SourceRef(scanner=scanner, id=source_id)],
        **kw,
    )


def str_list(value) -> list[str]:
    """Coerce a YAML list field to a clean list of strings."""
    if not value:
        return []
    return [str(v) for v in value if isinstance(v, (str, int, float))]
