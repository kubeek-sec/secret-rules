import re
import shutil
import subprocess
import tomllib

import pytest
import yaml

from secret_rules.generators import TARGETS, gitleaks, kingfisher, noseyparker, titus, trufflehog
from secret_rules.generators import yara as yara_gen
from secret_rules.normalize import capture_groups


@pytest.fixture(scope="module")
def outputs(referential_rules):
    return {name: module.generate(referential_rules) for name, module in TARGETS.items()}


def test_all_targets_generate(outputs):
    assert set(outputs) == {
        "betterleaks",
        "gitleaks",
        "kingfisher",
        "noseyparker",
        "titus",
        "trufflehog",
        "yara",
    }
    assert all(out.strip() for out in outputs.values())


# ---------------------------------------------------------------- gitleaks


def test_gitleaks_is_valid_toml(outputs, referential_rules):
    doc = tomllib.loads(outputs["gitleaks"])
    rules = doc["rules"]
    assert len(rules) >= len(referential_rules) - 20  # few RE2-incompatible skips
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    for rule in rules:
        assert rule["regex"]
        assert rule["description"]
        if "secretGroup" in rule:
            assert rule["secretGroup"] <= len(capture_groups(rule["regex"]))
        for kw in rule.get("keywords", []):
            assert kw == kw.lower(), "gitleaks keywords must be lowercase"


def test_gitleaks_no_lookarounds(outputs):
    doc = tomllib.loads(outputs["gitleaks"])
    for rule in doc["rules"]:
        assert not re.search(r"\(\?<?[=!]", rule["regex"]), rule["id"]


# -------------------------------------------------------------- betterleaks


def test_betterleaks_is_valid_toml(outputs):
    doc = tomllib.loads(outputs["betterleaks"])
    assert len(doc["rules"]) > 1500
    with_filter = [r for r in doc["rules"] if "filter" in r]
    assert with_filter, "entropy thresholds should become CEL filters"
    assert any("entropy(finding" in r["filter"] for r in with_filter)


# --------------------------------------------------------------- kingfisher


def test_kingfisher_is_valid_yaml(outputs, referential_rules):
    doc = yaml.safe_load(outputs["kingfisher"])
    rules = doc["rules"]
    assert len(rules) == len(referential_rules)
    for rule in rules:
        assert re.fullmatch(r"secretrules\.[a-z0-9_]+\.\d+", rule["id"]), rule["id"]
        assert rule["confidence"] in ("low", "medium", "high")
        assert rule["pattern"]


# ------------------------------------------------------- noseyparker / titus


def test_noseyparker_patterns_have_capture_group(outputs, referential_rules):
    doc = yaml.safe_load(outputs["noseyparker"])
    assert len(doc["rules"]) == len(referential_rules)
    for rule in doc["rules"]:
        assert capture_groups(rule["pattern"]), f"{rule['id']} has no capture group"


def test_titus_scores_and_named_groups(outputs):
    doc = yaml.safe_load(outputs["titus"])
    for rule in doc["rules"]:
        assert isinstance(rule["base_score"], int)
        assert 0 <= rule["base_score"] <= 100
    named = [r for r in doc["rules"] if "(?P<" in r["pattern"]]
    assert len(named) > 1000, "secret groups should be re-inserted as named groups"


# --------------------------------------------------------------- trufflehog


def test_trufflehog_detectors_shape(outputs):
    doc = yaml.safe_load(outputs["trufflehog"])
    detectors = doc["detectors"]
    assert len(detectors) > 1400
    names = [d["name"] for d in detectors]
    assert len(names) == len(set(names))
    for det in detectors:
        assert det["keywords"], f"{det['name']}: trufflehog requires keywords"
        assert all(k == k.lower() for k in det["keywords"])
        assert len(det["regex"]) == 1
        assert next(iter(det["regex"].values()))


# --------------------------------------------------------------------- yara


def test_yara_header_and_rule_count(outputs):
    out = outputs["yara"]
    assert out.startswith("//")
    assert "#" not in out.split("\n")[0]
    assert out.count("\nrule ") + out.startswith("rule ") > 1300


def test_yara_no_unsupported_constructs(outputs):
    for line in outputs["yara"].splitlines():
        if line.strip().startswith("$re = /"):
            body = line.strip()[len("$re = /") :]
            assert "(?" not in body, line


@pytest.mark.skipif(shutil.which("yara") is None, reason="yara binary not installed")
def test_yara_compiles_and_matches(outputs, tmp_path):
    rules_file = tmp_path / "rules.yar"
    rules_file.write_text(outputs["yara"])
    sample = tmp_path / "sample.txt"
    sample.write_text("config:\n  aws_key = AKIADEADBEEFDEADBEEF\n")
    proc = subprocess.run(
        ["yara", "-w", str(rules_file), str(sample)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    assert "error" not in proc.stderr.lower(), proc.stderr
    matches = proc.stdout.splitlines()
    assert any("aws" in m for m in matches), f"expected an AWS rule to fire, got: {matches[:10]}"


# ----------------------------------------------------- cross-target sanity


def test_skipped_rules_are_reported(referential_rules):
    out = yara_gen.generate(referential_rules)
    header = out.split("\nrule ", 1)[0]
    n_rules = len(re.findall(r"(?m)^rule ", out))
    m = re.search(r"skipped \(incompatible with yara\): (\d+)", header)
    assert m, "yara header must report skipped rules"
    assert n_rules + int(m.group(1)) == len(referential_rules)
