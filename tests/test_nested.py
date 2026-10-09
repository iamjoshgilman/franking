"""Tests for forwarded reports.

A reported phish arrives attached to a covering note. Analysing the note
describes the employee who reported it, which is never the question. These
tests pin the behaviour that was previously producing confidently wrong
answers.
"""

import email
import email.policy
from email.message import EmailMessage

import pytest

from franking.cli import main
from franking.parse import EmailDoc
from franking.rules import run_all
from tests.conftest import FIXTURES, fired


def wrap(inner_path, subject="FW: is this legit?", depth=1):
    """Build a covering message with ``inner_path`` attached."""
    inner = email.message_from_bytes(inner_path.read_bytes(),
                                     policy=email.policy.default)
    for _ in range(depth):
        outer = EmailMessage()
        outer["From"] = '"Dana Whitfield" <dana.whitfield@company.example>'
        outer["To"] = "<abuse@company.example>"
        outer["Subject"] = subject
        outer["Date"] = "Mon, 26 Feb 2025 11:02:11 +0000"
        outer["Message-ID"] = "<fwd-9912@company.example>"
        outer.set_content("Got this, looks off to me. Forwarding.\n\nDana")
        outer.add_attachment(inner, disposition="attachment",
                             filename="suspicious.eml")
        inner = outer
    return outer.as_bytes()


@pytest.fixture
def forwarded():
    return EmailDoc(wrap(FIXTURES / "phish.eml"))


class TestUnwrapping:
    def test_the_covering_message_is_parsed_as_itself(self, forwarded):
        assert forwarded.from_addr == "dana.whitfield@company.example"
        assert forwarded.subject == "FW: is this legit?"

    def test_nested_message_is_found(self, forwarded):
        assert len(forwarded.nested) == 1
        assert forwarded.nested[0].from_addr == "billing@acme-invoices.example"

    def test_innermost_resolves_to_the_reported_message(self, forwarded):
        inner = forwarded.innermost()
        assert inner.from_addr == "billing@acme-invoices.example"
        assert inner.subject.startswith("Urgent")

    def test_a_forward_of_a_forward_still_resolves(self):
        doc = EmailDoc(wrap(FIXTURES / "phish.eml", depth=3))
        assert doc.innermost().from_addr == "billing@acme-invoices.example"

    def test_nesting_is_bounded(self):
        doc = EmailDoc(wrap(FIXTURES / "phish.eml", depth=3))
        depth = 0
        node = doc
        while node.nested:
            node = node.nested[0]
            depth += 1
        assert depth <= 5

    def test_a_plain_message_has_nothing_nested(self, phish, clean):
        assert phish.nested == []
        assert clean.nested == []
        assert phish.innermost() is phish


class TestPartOwnership:
    def test_the_wrapper_does_not_inherit_inner_attachments(self, forwarded):
        """Previously the payload was attributed to the covering note."""
        assert [a.filename for a in forwarded.attachments] == ["suspicious.eml"]

    def test_the_inner_message_keeps_its_own_attachments(self, forwarded):
        inner = forwarded.innermost()
        assert [a.filename for a in inner.attachments] == ["statement_march.zip"]

    def test_the_wrapper_does_not_inherit_inner_urls(self, forwarded):
        assert [u for u in forwarded.urls if u.scheme.startswith("http")] == []

    def test_the_wrapper_does_not_inherit_inner_hops(self, forwarded):
        assert forwarded.hops == []
        assert len(forwarded.innermost().hops) == 2


class TestFindingsAttribution:
    def test_unwrapped_analysis_matches_the_bare_message(self, forwarded,
                                                         phish_findings):
        assert fired(run_all(forwarded.innermost())) == fired(phish_findings)

    def test_analysing_the_wrapper_does_not_accuse_the_reporter(self,
                                                                forwarded):
        """The covering note is internal mail; it should look unremarkable."""
        findings = run_all(forwarded)
        assert "CONT008" not in fired(findings)
        assert "ATT001" not in fired(findings)
        assert "ATT002" not in fired(findings)


class TestCliUnwrapping:
    def test_unwraps_by_default(self, tmp_path, capsys):
        target = tmp_path / "report.eml"
        target.write_bytes(wrap(FIXTURES / "phish.eml"))
        main([str(target), "--findings", "--no-color"])
        captured = capsys.readouterr()
        assert "unwrapped" in captured.err
        assert "billing@acme-invoices.example" in captured.out
        assert "ATT001" in captured.out

    def test_wrapper_flag_analyses_the_covering_message(self, tmp_path,
                                                        capsys):
        target = tmp_path / "report.eml"
        target.write_bytes(wrap(FIXTURES / "phish.eml"))
        main([str(target), "--findings", "--no-color", "--wrapper"])
        captured = capsys.readouterr()
        assert "unwrapped" not in captured.err
        assert "dana.whitfield@company.example" in captured.out

    def test_json_output_is_not_polluted_by_the_notice(self, tmp_path,
                                                       capsys):
        import json
        target = tmp_path / "report.eml"
        target.write_bytes(wrap(FIXTURES / "phish.eml"))
        main([str(target), "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["from"] == "billing@acme-invoices.example"
