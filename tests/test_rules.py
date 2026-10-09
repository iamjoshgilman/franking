"""Rule tests.

Each rule gets two assertions where it matters: it fires on the phishing
fixture, and it stays quiet on the legitimate one. A rule that cannot stay
quiet is noise.
"""

import pytest

from franking.model import Severity
from franking.parse import EmailDoc
from franking.rules import registered_ids, run_all
from tests.conftest import fired


class TestAuthRules:
    def test_dkim_pass_without_signature(self, phish_findings):
        assert "AUTH001" in fired(phish_findings)

    def test_quiet_when_signature_present(self, clean_findings):
        assert "AUTH001" not in fired(clean_findings)

    def test_missing_authserv_id(self, phish_findings, clean_findings):
        assert "AUTH002" in fired(phish_findings)
        assert "AUTH002" not in fired(clean_findings)

    def test_arc_first_seal_must_be_cv_none(self, phish_findings):
        assert "AUTH003" in fired(phish_findings)

    def test_arc_signature_without_body(self, phish_findings):
        assert "AUTH004" in fired(phish_findings)

    def test_self_asserted_antispam(self, phish_findings, clean_findings):
        assert "AUTH007" in fired(phish_findings)
        assert "AUTH007" not in fired(clean_findings)


class TestRoutingRules:
    def test_spf_ip_absent_from_chain(self, phish_findings, clean_findings):
        assert "ROUTE001" in fired(phish_findings)
        # The clean message's SPF address really is the connecting host.
        assert "ROUTE001" not in fired(clean_findings)

    def test_received_from_holding_an_address(self, phish_findings):
        assert "ROUTE002" in fired(phish_findings)

    def test_originating_ip_mismatch(self, phish_findings, clean_findings):
        assert "ROUTE004" in fired(phish_findings)
        assert "ROUTE004" not in fired(clean_findings)

    def test_documentation_ips_are_flagged_as_synthetic(self, phish_findings):
        route005 = [f for f in phish_findings if f.id == "ROUTE005"]
        assert route005
        assert all(f.severity is Severity.INFO for f in route005)

    def test_public_chain_is_not_flagged(self, clean_findings):
        assert "ROUTE005" not in fired(clean_findings)

    def test_return_path_matching_from_is_quiet(self, phish_findings,
                                                clean_findings):
        assert "ROUTE006" not in fired(phish_findings)
        assert "ROUTE006" not in fired(clean_findings)


class TestContentRules:
    def test_reply_to_divergence_is_high_across_domains(self, phish_findings):
        finding = next(f for f in phish_findings if f.id == "CONT001")
        assert finding.severity is Severity.HIGH

    def test_quiet_without_reply_to(self, clean_findings):
        assert "CONT001" not in fired(clean_findings)

    def test_identifier_mismatch_between_body_and_link(self, phish_findings):
        finding = next(f for f in phish_findings if f.id == "CONT002")
        values = " ".join(e.value for e in finding.evidence)
        assert "INV-2025-0441" in values
        assert "INV-2025-9988" in values

    def test_anchor_text_mismatch(self, phish_findings):
        assert "CONT003" in fired(phish_findings)

    def test_urgency_language(self, phish_findings, clean_findings):
        assert "CONT005" in fired(phish_findings)
        assert "CONT005" not in fired(clean_findings)

    def test_dual_delivery_path(self, phish_findings):
        assert "CONT006" in fired(phish_findings)

    def test_fictional_phone_number(self, phish_findings):
        assert "CONT007" in fired(phish_findings)

    def test_display_name_matching_domain_is_quiet(self, clean_findings):
        assert "CONT008" not in fired(clean_findings)

    def test_a_personal_name_is_not_impersonation(self):
        """The regression that matters: do not accuse ordinary people.

        'Northwind Logistics Billing' at acme-invoices.example may well be
        a lie, but proving it needs a roster of who may legitimately send
        as what. The earlier heuristic flagged every human name in order
        to catch cases like that -- including the employee forwarding a
        phishing report to the security team.
        """
        doc = EmailDoc(
            b'From: "Dana Whitfield" <dana.whitfield@company.example>\r\n'
            b"To: ops@company.example\r\nSubject: lunch\r\n\r\nback at 2\r\n"
        )
        assert "CONT008" not in fired(run_all(doc))

    def test_brand_in_display_name_from_another_domain_fires(self):
        doc = EmailDoc(
            b'From: "PayPal Security" <no-reply@mailer-xyz.example>\r\n'
            b"To: a@b.example\r\nSubject: verify\r\n\r\ncheck your account\r\n"
        )
        findings = [f for f in run_all(doc) if f.id == "CONT008"]
        assert findings
        assert "paypal" in findings[0].detail

    def test_brand_in_display_name_from_its_own_domain_is_quiet(self):
        doc = EmailDoc(
            b'From: "PayPal Security" <no-reply@paypal.com>\r\n'
            b"To: a@b.example\r\nSubject: receipt\r\n\r\nthanks\r\n"
        )
        assert "CONT008" not in fired(run_all(doc))

    def test_address_hidden_in_a_display_name_fires(self):
        doc = EmailDoc(
            b'From: "billing@supplier.example" <attacker@evil.example>\r\n'
            b"To: a@b.example\r\nSubject: invoice\r\n\r\npay up\r\n"
        )
        findings = [f for f in run_all(doc) if f.id == "CONT008"]
        assert findings
        assert "supplier.example" in findings[0].detail


class TestAttachmentRules:
    def test_double_extension(self, phish_findings):
        finding = next(f for f in phish_findings if f.id == "ATT001")
        assert finding.severity is Severity.CRITICAL
        assert "statement_march.pdf.exe" in finding.title
        assert "T1036.007" in finding.mitre

    def test_archive_containing_executable(self, phish_findings):
        assert "ATT002" in fired(phish_findings)

    def test_readme_txt_does_not_trigger(self, phish_findings):
        titles = " ".join(f.title for f in phish_findings)
        assert "readme.txt" not in titles

    def test_intact_archive_not_called_truncated(self, phish_findings):
        assert "ATT005" not in fired(phish_findings)


class TestEngine:
    def test_clean_message_produces_nothing_serious(self, clean_findings):
        serious = [f for f in clean_findings
                   if f.severity.rank >= Severity.MEDIUM.rank]
        assert serious == [], [f.title for f in serious]

    def test_findings_are_sorted_most_severe_first(self, phish_findings):
        ranks = [f.severity.rank for f in phish_findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_every_finding_carries_detail_and_evidence(self, phish_findings):
        for finding in phish_findings:
            assert finding.detail.strip(), finding.id
            assert finding.evidence, finding.id

    def test_rule_ids_are_unique(self):
        assert len(registered_ids()) == len(set(registered_ids()))

    def test_running_twice_is_stable(self, phish):
        assert fired(run_all(phish)) == fired(run_all(phish))


class TestSeverity:
    @pytest.mark.parametrize("lower,higher", [
        (Severity.INFO, Severity.LOW),
        (Severity.LOW, Severity.MEDIUM),
        (Severity.MEDIUM, Severity.HIGH),
        (Severity.HIGH, Severity.CRITICAL),
    ])
    def test_ordering(self, lower, higher):
        assert lower.rank < higher.rank

    def test_serialises_as_its_name(self):
        assert Severity.CRITICAL.value == "critical"
