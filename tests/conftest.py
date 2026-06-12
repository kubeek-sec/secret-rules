from pathlib import Path

import pytest

from secret_rules.parsers import parse_all
from secret_rules.referential import build_rules

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"


@pytest.fixture(scope="session")
def parsed():
    return parse_all(RULES_DIR)


@pytest.fixture(scope="session")
def referential_rules(parsed):
    # build_rules re-parses; accept the cost once per session
    return build_rules(RULES_DIR)
