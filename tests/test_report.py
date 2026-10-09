"""Output tests: the reports must stay machine-readable and complete."""

import json

from franking.cli import main
from franking.report import findings_report, iocs_report, json_report
from franking.view import build_tree
from tests.conftest import FIXTURES


class TestJsonReport:
    def test_is_valid_json(self, phish, phish_findings):
        json.loads(json_report(phish, phish_findings))

    def test_carries_the_facts_an_analyst_needs(self, phish, phish_findings):
        data = json.loads(json_report(phish, phish_findings))
        assert data["from"] == "billing@acme-invoices.example"
        assert data["reply_to"] == "recovery@secure-acme-portal.example"
        assert data["authentication"]["dkim_signature_present"] is False
        assert len(data["hops"]) == 2
        assert data["attachments"][0]["sha256"]
        assert "T1036.007" in data["mitre"]

    def test_archive_contents_are_included(self, phish, phish_findings):
        data = json.loads(json_report(phish, phish_findings))
        names = [c["name"] for c in data["attachments"][0]["contents"]]
        assert "statement_march.pdf.exe" in names


class TestTextReport:
    def test_plain_mode_emits_no_escape_codes(self, phish, phish_findings):
        text = findings_report(phish, phish_findings, colour=False)
        assert "\033[" not in text

    def test_colour_mode_emits_escape_codes(self, phish, phish_findings):
        assert "\033[" in findings_report(phish, phish_findings, colour=True)

    def test_mentions_every_finding(self, phish, phish_findings):
        text = findings_report(phish, phish_findings, colour=False)
        for finding in phish_findings:
            assert finding.id in text

    def test_clean_message_says_so(self, clean):
        assert "No findings" in findings_report(clean, [], colour=False)


class TestIocReport:
    def test_lists_indicators_one_per_line(self, phish, phish_findings):
        text = iocs_report(phish, phish_findings)
        assert "billing@acme-invoices.example" in text
        assert "secure-acme-portal.example" in text
        assert "statement_march.pdf.exe" in text

    def test_has_no_duplicate_lines(self, phish, phish_findings):
        lines = iocs_report(phish, phish_findings).splitlines()
        assert len(lines) == len(set(lines))


class TestTree:
    def test_expected_sections_exist(self, phish, phish_findings):
        labels = [c.label for c in build_tree(phish, phish_findings).children]
        assert labels[:2] == ["Summary", "Findings"]
        for required in ("Authentication", "Routing", "Attachments", "IOCs"):
            assert required in labels

    def test_every_node_has_a_label(self, phish, phish_findings):
        def walk(node):
            assert node.label
            for child in node.children:
                walk(child)
        walk(build_tree(phish, phish_findings))


class TestCli:
    def test_findings_mode_exits_nonzero_on_a_phish(self, capsys):
        code = main([str(FIXTURES / "phish.eml"), "--findings", "--no-color"])
        assert code == 1
        assert "ATT001" in capsys.readouterr().out

    def test_clean_message_exits_zero(self, capsys):
        code = main([str(FIXTURES / "clean.eml"), "--findings", "--no-color"])
        assert code == 0

    def test_json_mode(self, capsys):
        main([str(FIXTURES / "phish.eml"), "--json"])
        json.loads(capsys.readouterr().out)

    def test_min_severity_filters(self, capsys):
        main([str(FIXTURES / "phish.eml"), "--findings", "--no-color",
              "--min-severity", "critical"])
        out = capsys.readouterr().out
        assert "ATT001" in out
        assert "ROUTE005" not in out

    def test_missing_file_is_reported(self, capsys):
        assert main(["/nonexistent/nope.eml", "--json"]) == 2
        assert "no such file" in capsys.readouterr().err
