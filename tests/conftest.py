from pathlib import Path

import pytest

from franking.parse import EmailDoc
from franking.rules import run_all

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def phish() -> EmailDoc:
    return EmailDoc.from_path(FIXTURES / "phish.eml")


@pytest.fixture
def clean() -> EmailDoc:
    return EmailDoc.from_path(FIXTURES / "clean.eml")


@pytest.fixture
def phish_findings(phish):
    return run_all(phish)


@pytest.fixture
def clean_findings(clean):
    return run_all(clean)


def fired(findings) -> set[str]:
    """The set of rule ids present in a findings list."""
    return {f.id for f in findings}
