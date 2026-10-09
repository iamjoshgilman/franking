"""Tests for impersonation rules and the parsing they depend on.

The `evasive.eml` fixture carries one instance of each technique, so a
rule that stops firing shows up immediately.
"""

import pytest

from franking.model import Severity
from franking.parse import (
    EmailDoc,
    decode_punycode,
    edit_distance,
    invisible_chars,
    mixed_scripts,
    org_domain,
    scan_zip_entries,
)
from franking.rules import run_all
from tests.conftest import FIXTURES, fired


@pytest.fixture
def evasive() -> EmailDoc:
    return EmailDoc.from_path(FIXTURES / "evasive.eml")


@pytest.fixture
def evasive_findings(evasive):
    return run_all(evasive)


class TestOrgDomain:
    @pytest.mark.parametrize("host,expected", [
        ("example.com", "example.com"),
        ("mail.example.com", "example.com"),
        ("a.b.c.example.com", "example.com"),
        ("example.co.uk", "example.co.uk"),
        ("mail.example.co.uk", "example.co.uk"),
        ("localhost", "localhost"),
        ("", ""),
    ])
    def test_extracts_the_registrable_domain(self, host, expected):
        assert org_domain(host) == expected


class TestPunycode:
    def test_decodes_an_idna_host(self):
        assert decode_punycode("xn--80ak6aa92e.com") == "аррӏе.com"

    def test_plain_ascii_is_not_punycode(self):
        assert decode_punycode("example.com") is None

    def test_malformed_punycode_does_not_raise(self):
        assert decode_punycode("xn--zzzzzzzzzz!.com") is None

    def test_detects_mixed_scripts(self):
        assert mixed_scripts("pаypal") == {"LATIN", "CYRILLIC"}
        assert mixed_scripts("paypal") == {"LATIN"}


class TestEditDistance:
    @pytest.mark.parametrize("a,b,expected", [
        ("paypal", "paypal", 0),
        ("paypa1", "paypal", 1),
        ("rnicrosoft", "microsoft", 2),
        ("", "abc", 3),
        ("abc", "", 3),
    ])
    def test_distances(self, a, b, expected):
        assert edit_distance(a, b) == expected


class TestInvisibleCharacters:
    def test_finds_a_bidi_override(self):
        found = invisible_chars("invoice‮gnp.exe")
        assert found and "OVERRIDE" in found[0][1]

    def test_finds_zero_width(self):
        assert invisible_chars("pay​pal")

    def test_clean_text_is_clean(self):
        assert invisible_chars("perfectly ordinary text") == []


class TestEncryptedArchiveDetection:
    def test_reads_the_encryption_flag(self, evasive):
        att = evasive.attachments[0]
        assert att.is_encrypted is True
        assert att.archive_entries[0].encrypted is True

    def test_unencrypted_archive_is_not_flagged(self, phish):
        assert phish.attachments[0].is_encrypted is False

    def test_flag_survives_truncation(self):
        import struct
        name = b"secret.doc.exe"
        header = struct.pack(
            "<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0x0001, 0, 0, 0,
            0, 999, 999, len(name), 0) + name
        entries, truncated = scan_zip_entries(header)
        assert truncated is True
        assert entries[0].encrypted is True


class TestAlignmentRule:
    def test_fires_when_auth_domain_differs_from_from_domain(self,
                                                             evasive_findings):
        finding = next(f for f in evasive_findings if f.id == "AUTH009")
        assert finding.severity is Severity.HIGH
        values = " ".join(e.value for e in finding.evidence)
        assert "mailer-relay-7.example" in values
        assert "paypa1-security.example" in values

    def test_quiet_when_aligned(self, clean_findings):
        assert "AUTH009" not in fired(clean_findings)

    def test_quiet_when_nothing_passed(self, phish_findings):
        """The phish fixture forges results; alignment is not the point."""
        finding = [f for f in phish_findings if f.id == "AUTH009"]
        assert finding == []


class TestPunycodeRule:
    def test_fires_and_shows_the_rendered_form(self, evasive_findings):
        finding = next(f for f in evasive_findings if f.id == "IDN001")
        assert finding.severity is Severity.CRITICAL
        assert any("а" in e.value for e in finding.evidence)

    def test_quiet_on_ascii_domains(self, phish_findings, clean_findings):
        assert "IDN001" not in fired(phish_findings)
        assert "IDN001" not in fired(clean_findings)


class TestLookalikeRule:
    def test_catches_a_brand_with_a_substituted_character(self,
                                                          evasive_findings):
        finding = next(f for f in evasive_findings if f.id == "IDN002")
        assert "paypal.com" in finding.title

    def test_quiet_on_unrelated_domains(self, clean_findings, phish_findings):
        assert "IDN002" not in fired(clean_findings)
        assert "IDN002" not in fired(phish_findings)

    def test_the_real_brand_is_not_flagged_as_its_own_lookalike(self):
        doc = EmailDoc(
            b"From: Billing <billing@paypal.com>\r\n"
            b"To: a@b.example\r\nSubject: hi\r\n\r\nbody\r\n"
        )
        assert "IDN002" not in fired(run_all(doc))

    def test_subdomain_of_the_real_brand_is_not_flagged(self):
        doc = EmailDoc(
            b"From: Billing <billing@mail.paypal.com>\r\n"
            b"To: a@b.example\r\nSubject: hi\r\n\r\nbody\r\n"
        )
        assert "IDN002" not in fired(run_all(doc))


class TestInvisibleCharacterRule:
    def test_bidi_override_in_a_filename_is_critical(self):
        raw = (
            b"From: a@b.example\r\nTo: c@d.example\r\nSubject: doc\r\n"
            b"MIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="x"\r\n\r\n'
            b"--x\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
            b"--x\r\nContent-Type: application/octet-stream;\r\n"
            b' name="report\xe2\x80\xaegnp.exe"\r\n'
            b"Content-Disposition: attachment;\r\n"
            b' filename="report\xe2\x80\xaegnp.exe"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n--x--\r\n"
        )
        findings = [f for f in run_all(EmailDoc(raw)) if f.id == "IDN003"]
        assert findings
        assert findings[0].severity is Severity.CRITICAL

    def test_quiet_on_ordinary_messages(self, clean_findings, phish_findings):
        assert "IDN003" not in fired(clean_findings)
        assert "IDN003" not in fired(phish_findings)


class TestThreadHijackRule:
    """The rule only reports what it can actually distinguish.

    "Sender's domain is not in the thread" is the shape of every genuine
    reply -- Message-IDs are minted by the sender's MTA -- so it cannot
    separate a hijack from a conversation. A sender whose domain
    *resembles* one already in the thread can.
    """

    def test_a_lookalike_reply_fires(self):
        doc = EmailDoc(
            b"From: Billing <billing@supp1ier.example>\r\n"
            b"To: ap@company.example\r\nSubject: RE: March invoice\r\n"
            b"References: <a1@supplier.example> <b2@supplier.example>\r\n"
            b"\r\nupdated bank details attached\r\n"
        )
        finding = next(f for f in run_all(doc) if f.id == "IDN004")
        assert finding.severity is Severity.HIGH
        assert "supplier.example" in " ".join(
            e.value for e in finding.evidence)

    def test_an_ordinary_cross_organisation_reply_is_quiet(self):
        """The regression that matters: this is normal business mail."""
        doc = EmailDoc(
            b"From: Pat <pat@supplier.example>\r\n"
            b"To: ops@company.example\r\nSubject: RE: March schedule\r\n"
            b"References: <a1@company.example>\r\n"
            b"\r\nlooks good, thanks\r\n"
        )
        assert "IDN004" not in fired(run_all(doc))

    def test_a_reply_within_one_organisation_is_quiet(self):
        doc = EmailDoc(
            b"From: a@supplier.example\r\nTo: c@d.example\r\n"
            b"Subject: RE: schedule\r\n"
            b"References: <1@supplier.example>\r\n\r\nbody\r\n"
        )
        assert "IDN004" not in fired(run_all(doc))

    def test_reply_subject_with_no_thread_is_medium(self):
        doc = EmailDoc(
            b"From: a@b.example\r\nTo: c@d.example\r\n"
            b"Subject: RE: your invoice\r\n\r\nbody\r\n"
        )
        finding = next(f for f in run_all(doc) if f.id == "IDN004")
        assert finding.severity is Severity.MEDIUM

    def test_a_forward_with_no_thread_is_quiet(self):
        """FW: legitimately starts a new thread; RE: does not."""
        doc = EmailDoc(
            b"From: a@b.example\r\nTo: c@d.example\r\n"
            b"Subject: FW: is this legit?\r\n\r\nbody\r\n"
        )
        assert "IDN004" not in fired(run_all(doc))

    def test_a_list_digest_reply_is_quiet(self):
        doc = EmailDoc(
            b"From: a@b.example\r\nTo: list@c.example\r\n"
            b"Subject: Re: [dev] build failure\r\n"
            b"List-Id: <dev.c.example>\r\n\r\nbody\r\n"
        )
        assert "IDN004" not in fired(run_all(doc))

    def test_quiet_on_a_message_that_is_not_a_reply(self, clean_findings):
        assert "IDN004" not in fired(clean_findings)
