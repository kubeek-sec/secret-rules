"""Build the deduplicated referential from all parsed rulesets.

Two artifacts are produced:

- ``referential/rules.yaml``  — every rule, deduplicated by canonical regex,
  with merged metadata and full provenance (which scanners ship the pattern).
- ``referential/topics.yaml`` — index of rules grouped by topic (provider /
  service / secret family), used to generate topic-scoped configs.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .model import Rule
from .parsers import parse_all

# metadata preference when merging duplicates: earlier wins
SCANNER_PRIORITY = ["gitleaks", "noseyparker", "titus", "kingfisher", "betterleaks"]
# scanners whose topic comes from the rule filename (more reliable than id prefixes)
_FILE_TOPIC_SCANNERS = {"kingfisher", "noseyparker", "titus"}

_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}

_LITERAL_CHARS = re.compile(r"[A-Za-z0-9_/.-]")


def extract_keywords(pattern: str, max_keywords: int = 3) -> list[str]:
    """Pull literal substrings out of a regex, for scanners that prefilter
    on keywords (gitleaks, trufflehog).  Conservative: a literal run is cut
    short when followed by an optional/repeat quantifier."""
    runs: list[str] = []
    cur: list[str] = []
    i, n = 0, len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\":
            if cur:
                runs.append("".join(cur))
                cur = []
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            if cur:
                runs.append("".join(cur))
                cur = []
            i += 1
            continue
        if _LITERAL_CHARS.match(c):
            # a quantifier right after a literal makes that char unreliable
            if i + 1 < n and pattern[i + 1] in "?*{":
                if cur:
                    runs.append("".join(cur))
                    cur = []
                i += 1
                continue
            cur.append(c)
            i += 1
            continue
        if cur:
            runs.append("".join(cur))
            cur = []
        i += 1
    if cur:
        runs.append("".join(cur))
    candidates = sorted(
        {r.lower() for r in runs if len(r) >= 3 and r.strip("0123456789./-") != ""},
        key=len,
        reverse=True,
    )
    return candidates[:max_keywords]


def _merge(into: Rule, other: Rule) -> None:
    """Merge `other` (same canonical pattern) into `into`."""
    into.sources.extend(other.sources)
    for attr in ("keywords", "categories", "references", "examples",
                 "negative_examples", "ignore_if_contains", "allowlist_regexes"):
        seen = set(getattr(into, attr))
        for v in getattr(other, attr):
            if v not in seen:
                getattr(into, attr).append(v)
                seen.add(v)
    if into.description is None:
        into.description = other.description
    # favor recall: keep the lowest entropy threshold any scanner uses
    if other.entropy is not None:
        into.entropy = other.entropy if into.entropy is None else min(into.entropy, other.entropy)
    if other.confidence and (
        into.confidence is None
        or _CONFIDENCE_ORDER.get(other.confidence, 0) > _CONFIDENCE_ORDER.get(into.confidence, 0)
    ):
        into.confidence = other.confidence
    if into.secret_group == 0 and other.secret_group:
        into.secret_group = other.secret_group
    if into.secret_group_name is None and other.secret_group_name:
        into.secret_group_name = other.secret_group_name
    # filename-derived topics beat id-prefix heuristics
    if (
        other.sources
        and other.sources[-1].scanner in _FILE_TOPIC_SCANNERS
        and into.sources[0].scanner not in _FILE_TOPIC_SCANNERS
    ):
        into.topic = other.topic


def _unique_uid(rule: Rule, taken: set[str]) -> str:
    base = rule.uid
    # prefer human-readable uid derived from the rule name when the source id
    # is scanner-namespaced (np-aws-1, kingfisher-aws-1, ...)
    if re.match(r"^(np|kingfisher|titus)-", base):
        from .parsers._common import slugify

        candidate = slugify(rule.name)
        if candidate:
            base = candidate
    uid = base
    n = 2
    while uid in taken:
        uid = f"{base}-{n}"
        n += 1
    return uid


def build_rules(rules_dir: Path) -> list[Rule]:
    """Parse all sources and deduplicate by canonical pattern."""
    parsed = parse_all(rules_dir)
    by_pattern: dict[str, Rule] = {}
    for scanner in SCANNER_PRIORITY:
        for rule in parsed.get(scanner, []):
            existing = by_pattern.get(rule.pattern)
            if existing is None:
                by_pattern[rule.pattern] = rule
            else:
                _merge(existing, rule)

    merged = list(by_pattern.values())
    merged.sort(key=lambda r: (r.topic, r.uid))

    taken: set[str] = set()
    for rule in merged:
        rule.uid = _unique_uid(rule, taken)
        taken.add(rule.uid)
        # Keywords act as a prefilter (gitleaks/trufflehog): a finding is only
        # checked when a keyword is present. Deriving them is only safe when
        # the pattern has no alternation — otherwise a branch without the
        # keyword would silently never match.
        if not rule.keywords and "|" not in rule.pattern:
            rule.keywords = extract_keywords(rule.pattern)
    return merged


def build_topics(rules: list[Rule]) -> dict[str, dict]:
    topics: dict[str, dict] = {}
    for rule in rules:
        entry = topics.setdefault(rule.topic, {"rules": []})
        entry["rules"].append(rule.uid)
    for topic, entry in topics.items():
        entry["rule_count"] = len(entry["rules"])
    return dict(sorted(topics.items()))


_HEADER = """\
# This file is generated by `secret-rules build` from the source rulesets in
# rules/.  Do not edit by hand — regenerate instead.
"""


def write_referential(rules: list[Rule], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rules_path = out_dir / "rules.yaml"
    topics_path = out_dir / "topics.yaml"

    rules_doc = {
        "version": 1,
        "rule_count": len(rules),
        "rules": [r.to_dict() for r in rules],
    }
    rules_path.write_text(
        _HEADER + yaml.safe_dump(rules_doc, sort_keys=False, allow_unicode=True, width=100000)
    )

    topics_doc = {"version": 1, "topics": build_topics(rules)}
    topics_path.write_text(
        _HEADER + yaml.safe_dump(topics_doc, sort_keys=False, allow_unicode=True, width=100000)
    )
    return rules_path, topics_path


def load_referential(path: Path) -> list[Rule]:
    data = yaml.safe_load(path.read_text())
    return [Rule.from_dict(d) for d in data["rules"]]
