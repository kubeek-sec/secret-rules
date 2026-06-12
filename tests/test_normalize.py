import re

from secret_rules.normalize import (
    canonicalize,
    capture_groups,
    insert_group_name,
    strip_group_names,
)


def test_flatten_extended_basic():
    res = canonicalize("(?x)\n\\b\n(\n  AKIA [A-Z0-9]{16}\n)\n\\b\n")
    assert res.pattern == r"\b(AKIA[A-Z0-9]{16})\b"
    assert res.flags == ""


def test_flatten_removes_comments():
    res = canonicalize("(?x) foo # trailing comment\n bar")
    assert res.pattern == "foobar"


def test_flatten_whitespace_in_class_rust_semantics():
    # the Rust regex crate ignores whitespace inside character classes in
    # verbose mode; our sources target that engine
    res = canonicalize("(?x) [a b] +")
    assert res.pattern == "[ab]+"


def test_flatten_escaped_space_is_literal():
    res = canonicalize(r"(?x) foo\ bar")
    assert res.pattern == "foo bar"


def test_flags_merged_and_x_dropped():
    res = canonicalize("(?xi)\n abc")
    assert res.pattern == "(?i)abc"
    assert res.flags == "i"
    res2 = canonicalize("(?x)(?i) abc")
    assert res2.pattern == "(?i)abc"


def test_named_groups_stripped_and_recorded():
    res = canonicalize(r"\b(?P<key_id>AKIA[A-Z0-9]{16})\b")
    assert res.pattern == r"\b(AKIA[A-Z0-9]{16})\b"
    assert res.group_names == {1: "key_id"}


def test_rust_style_named_group():
    res = canonicalize(r"(?<token>x+)")
    assert res.pattern == "(x+)"
    assert res.group_names == {1: "token"}


def test_lookbehind_not_treated_as_named_group():
    pattern = r"(?<=foo)(bar)"
    stripped, names = strip_group_names(pattern)
    assert stripped == pattern
    assert names == {}


def test_capture_groups_counts_only_captures():
    groups = capture_groups(r"(?i)(?:ab)(c)(?P<d>e)[f(g]")
    assert groups == [(1, None), (2, "d")]


def test_insert_group_name():
    pattern = r"\b(?:AWS)(secret)([0-9]+)\b"
    named = insert_group_name(pattern, 1, "secret")
    assert named == r"\b(?:AWS)(?P<secret>secret)([0-9]+)\b"
    assert re.search(named, "AWSsecret123").group("secret") == "secret"


def test_canonical_pattern_equivalence():
    """Flattened verbose pattern must match the same strings as the original."""
    verbose = "(?x)(?i)\n\\b\n(\n  sk-ant-api \\d{2}\n  - [a-z]{4}\n)\n\\b"
    flat = canonicalize(verbose).pattern
    for sample, expect in [("sk-ant-api03-abcd", True), ("sk-ant-api3-abcd", False)]:
        assert bool(re.search(flat, sample)) is expect
