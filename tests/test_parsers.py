import pytest

EXPECTED_MIN = {
    "gitleaks": 200,
    "betterleaks": 280,
    "kingfisher": 900,
    "noseyparker": 180,
    "titus": 220,
}


def test_all_sources_discovered(parsed):
    assert set(parsed) == set(EXPECTED_MIN)


@pytest.mark.parametrize("scanner", sorted(EXPECTED_MIN))
def test_rule_counts(parsed, scanner):
    assert len(parsed[scanner]) >= EXPECTED_MIN[scanner]


@pytest.mark.parametrize("scanner", sorted(EXPECTED_MIN))
def test_rules_have_required_fields(parsed, scanner):
    for rule in parsed[scanner]:
        assert rule.uid, f"{scanner} rule without uid"
        assert rule.name
        assert rule.topic
        assert rule.pattern.strip()
        assert rule.sources and rule.sources[0].scanner == scanner


@pytest.mark.parametrize("scanner", sorted(EXPECTED_MIN))
def test_patterns_are_single_line(parsed, scanner):
    """Canonicalization must flatten (?x) patterns to one line."""
    for rule in parsed[scanner]:
        assert "\n" not in rule.pattern, rule.uid


def test_gitleaks_secret_group_preserved(parsed):
    by_id = {r.sources[0].id: r for r in parsed["gitleaks"]}
    aws = by_id["aws-access-token"]
    assert aws.entropy == 3
    assert "akia" in aws.keywords
    assert aws.allowlist_regexes  # the .+EXAMPLE$ allowlist


def test_titus_named_groups_recorded(parsed):
    named = [r for r in parsed["titus"] if r.secret_group_name]
    assert named, "titus rules use named capture groups"
    assert all(r.secret_group >= 1 for r in named)


def test_betterleaks_entropy_extracted_from_cel(parsed):
    with_entropy = [r for r in parsed["betterleaks"] if r.entropy is not None]
    assert len(with_entropy) > 50
