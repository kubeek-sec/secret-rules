import tomllib

import yaml

from secret_rules.cli import main
from tests.conftest import RULES_DIR


def test_build_and_generate_roundtrip(tmp_path, capsys):
    ref_dir = tmp_path / "referential"
    out_dir = tmp_path / "configs"

    assert main(["build", "--rules-dir", str(RULES_DIR), "--out", str(ref_dir)]) == 0
    assert (ref_dir / "rules.yaml").exists()
    assert (ref_dir / "topics.yaml").exists()

    assert (
        main(
            [
                "generate",
                "--target",
                "all",
                "--referential",
                str(ref_dir / "rules.yaml"),
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    produced = {p.name for p in out_dir.iterdir()}
    assert produced == {
        "gitleaks.toml",
        "betterleaks.toml",
        "kingfisher.yml",
        "noseyparker.yml",
        "titus.yml",
        "trufflehog.yml",
        "secret_rules.yar",
    }


def test_generate_topic_filter(tmp_path):
    ref_dir = tmp_path / "referential"
    out_dir = tmp_path / "configs"
    main(["build", "--rules-dir", str(RULES_DIR), "--out", str(ref_dir)])

    assert (
        main(
            [
                "generate",
                "--target",
                "gitleaks,noseyparker",
                "--topics",
                "aws,github",
                "--referential",
                str(ref_dir / "rules.yaml"),
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    doc = tomllib.loads((out_dir / "gitleaks.toml").read_text())
    assert 0 < len(doc["rules"]) < 100
    np = yaml.safe_load((out_dir / "noseyparker.yml").read_text())
    topics = {r["id"].split(".")[1] for r in np["rules"]}
    assert topics == {"aws", "github"}


def test_generate_unknown_topic_fails(tmp_path, capsys):
    ref_dir = tmp_path / "referential"
    main(["build", "--rules-dir", str(RULES_DIR), "--out", str(ref_dir)])
    rc = main(
        [
            "generate",
            "--topics",
            "definitely-not-a-topic",
            "--referential",
            str(ref_dir / "rules.yaml"),
            "--out-dir",
            str(tmp_path / "x"),
        ]
    )
    assert rc == 2
    assert "unknown topics" in capsys.readouterr().err


def test_topics_command(tmp_path, capsys):
    ref_dir = tmp_path / "referential"
    main(["build", "--rules-dir", str(RULES_DIR), "--out", str(ref_dir)])
    capsys.readouterr()
    assert main(["topics", "--referential", str(ref_dir / "rules.yaml")]) == 0
    out = capsys.readouterr().out
    assert "aws\t" in out
