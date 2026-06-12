import re

import yaml

from secret_rules.referential import build_topics, extract_keywords, write_referential


def test_dedup_merges_identical_patterns(referential_rules):
    multi = [r for r in referential_rules if len(r.sources) > 1]
    assert len(multi) > 300, "noseyparker/titus/kingfisher lineage should overlap heavily"
    # a known shared rule: adafruit io key ships in noseyparker and titus
    adafruit = [
        r
        for r in referential_rules
        if {s.scanner for s in r.sources} >= {"noseyparker", "titus"} and r.topic == "adafruitio"
    ]
    assert adafruit


def test_no_duplicate_patterns(referential_rules):
    patterns = [r.pattern for r in referential_rules]
    assert len(patterns) == len(set(patterns))


def test_uids_unique(referential_rules):
    uids = [r.uid for r in referential_rules]
    assert len(uids) == len(set(uids))


def test_topics_index_consistent(referential_rules):
    topics = build_topics(referential_rules)
    indexed = [uid for entry in topics.values() for uid in entry["rules"]]
    assert sorted(indexed) == sorted(r.uid for r in referential_rules)
    assert all(entry["rule_count"] == len(entry["rules"]) for entry in topics.values())


def test_patterns_compile_in_python(referential_rules):
    """Canonical patterns should be valid in a mainstream regex engine.

    The sources target RE2/Rust which Python's `re` largely covers; a small
    failure budget absorbs genuinely engine-specific syntax."""
    failures = []
    for rule in referential_rules:
        try:
            re.compile(rule.pattern)
        except re.error as exc:
            failures.append((rule.uid, str(exc)))
    assert len(failures) <= len(referential_rules) * 0.02, failures[:20]


def test_examples_match_their_pattern(referential_rules):
    """Functional check: each rule's positive examples should be caught by
    its canonicalized pattern — this would catch any flattening corruption."""
    checked = matched = 0
    misses = []
    for rule in referential_rules:
        if not rule.examples:
            continue
        try:
            compiled = re.compile(rule.pattern)
        except re.error:
            continue
        checked += 1
        if any(compiled.search(ex) for ex in rule.examples):
            matched += 1
        else:
            misses.append(rule.uid)
    assert checked > 800
    assert matched / checked >= 0.95, f"{len(misses)} rules match none of their examples: {misses[:20]}"


def test_referential_roundtrip(tmp_path, referential_rules):
    from secret_rules.referential import load_referential

    rules_path, topics_path = write_referential(referential_rules, tmp_path)
    loaded = load_referential(rules_path)
    assert len(loaded) == len(referential_rules)
    assert loaded[0].to_dict() == referential_rules[0].to_dict()
    topics = yaml.safe_load(topics_path.read_text())
    assert topics["version"] == 1
    assert "aws" in topics["topics"]


def test_extract_keywords():
    assert extract_keywords(r"\b(aio_[a-zA-Z0-9]{28})\b") == ["aio_"]
    # runs cut short before a quantifier; numeric-only runs dropped
    assert "sk-ant-api" in extract_keywords(r"sk-ant-api\d{2}-[\w-]{93}AA")
