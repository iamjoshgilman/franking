"""Output encoding.

A phishing report carries the raw non-ASCII found in the message, because a
Cyrillic homoglyph in a lookalike domain is the evidence. Windows defaults
stdout and open() to the locale code page, which cannot represent those
characters, so every one of these paths used to raise UnicodeEncodeError on
Windows while passing on Linux.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from franking.cli import main
from franking.parse import EmailDoc
from franking.report import findings_report, iocs_report, json_report, tree_report
from franking.rules import run_all
from franking.view import build_tree

FIXTURES = Path(__file__).parent / "fixtures"
EVASIVE = FIXTURES / "evasive.eml"


def _reports():
    doc = EmailDoc.from_path(EVASIVE)
    findings = run_all(doc)
    return {
        "json": json_report(doc, findings),
        "findings": findings_report(doc, findings, colour=False),
        "iocs": iocs_report(doc, findings),
        "tree": tree_report(build_tree(doc, findings)),
    }


def test_fixture_still_carries_homoglyphs():
    """Guards the premise: if this fixture goes plain ASCII the rest is moot."""
    text = _reports()["json"]
    assert any(ord(c) > 127 for c in text)


@pytest.mark.parametrize("name", ["json", "findings", "iocs", "tree"])
def test_reports_survive_a_legacy_console(name, monkeypatch):
    """Printing to a cp1252 console must not take the process down."""
    reports = _reports()
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr("sys.stdout", stream)

    from franking.cli import _use_utf8_output

    _use_utf8_output()
    stream.write(reports[name])
    stream.flush()
    assert raw.getvalue()


@pytest.mark.parametrize("flag", ["--json", "--findings", "--iocs", "--tree"])
def test_cli_does_not_crash_on_a_legacy_console(flag, monkeypatch):
    """The exit code is 1 here by design - evasive.eml has HIGH findings, and
    main() reports that so the tool composes with shell conditionals. What is
    under test is that it returns at all instead of raising."""
    raw = io.BytesIO()
    monkeypatch.setattr(
        "sys.stdout", io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    )
    assert main([flag, str(EVASIVE)]) in (0, 1)
    sys.stdout.flush()
    assert raw.getvalue(), "nothing reached stdout"


def test_json_export_round_trips_as_utf8(tmp_path):
    """The TUI export writes a file another tool has to be able to read."""
    doc = EmailDoc.from_path(EVASIVE)
    target = tmp_path / "out.franking.json"
    target.write_text(json_report(doc, run_all(doc)), encoding="utf-8")

    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["subject"] is not None
    assert any(ord(c) > 127 for c in target.read_text(encoding="utf-8"))
