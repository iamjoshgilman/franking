"""Legitimate mail must stay quiet.

An independent audit built a corpus of realistic *innocent* messages and
found 24 of 26 produced findings, three of them CRITICAL. A rule that
cannot stay quiet is worse than no rule: it teaches whoever reads the
output to stop reading it.

Each test here is one shape of ordinary mail that used to trip a rule.
They are deliberately realistic -- the headers are the ones Exchange
Online, Mailman, SendGrid and SpamAssassin actually write.
"""

import pytest

from franking.model import Severity
from franking.parse import EmailDoc
from franking.rules import run_all
from tests.conftest import fired


def analyse(raw: bytes):
    return run_all(EmailDoc(raw))


def loud(findings, floor=Severity.MEDIUM):
    """Findings at or above a severity that would draw an analyst's eye."""
    return [f for f in findings if f.severity.rank >= floor.rank]


class TestMailPlatforms:
    def test_exchange_online_authentication_results(self):
        """EOP omits the authserv-id by design and signals via compauth."""
        findings = analyse(
            b"From: Partner <sales@partner.example>\r\n"
            b"To: buyer@company.example\r\nSubject: Quote\r\n"
            b"Authentication-Results: spf=pass (sender IP is 93.184.216.34)"
            b" smtp.mailfrom=partner.example; dkim=pass (signature was"
            b" verified) header.d=partner.example; dmarc=pass action=none"
            b" header.from=partner.example; compauth=pass reason=100\r\n"
            b"\r\nAttached is the quote.\r\n"
        )
        assert "AUTH002" not in fired(findings)

    def test_exchange_non_delivery_report(self):
        """Every Exchange NDR is sent by "Microsoft Outlook" from a GUID."""
        findings = analyse(
            b'From: "Microsoft Outlook" <MicrosoftExchange329e71ec88ae4615'
            b'bbc36ab6ce41109e@company.example>\r\n'
            b"To: dana@company.example\r\n"
            b"Subject: Undeliverable: Q3 numbers\r\n\r\n"
            b"Your message could not be delivered.\r\n"
        )
        assert "CONT008" not in fired(findings)

    def test_gmail_team_notification(self):
        findings = analyse(
            b'From: "Gmail Team" <mail-noreply@google.com>\r\n'
            b"To: a@b.example\r\nSubject: Welcome\r\n\r\nWelcome.\r\n"
        )
        assert "CONT008" not in fired(findings)

    def test_microsoft_sending_as_outlook_com(self):
        """outlook.com is a Microsoft domain; the brands are one family."""
        findings = analyse(
            b'From: "Microsoft Outlook" <noreply@outlook.com>\r\n'
            b"To: a@b.example\r\nSubject: Your account\r\n\r\nHello.\r\n"
        )
        assert "CONT008" not in fired(findings)

    def test_proofpoint_internal_verifier_name(self):
        findings = analyse(
            b"From: Partner <p@partner.example>\r\nTo: a@company.example\r\n"
            b"Subject: Hello\r\n"
            b"Received: from mx0a-001b2d01.pphosted.example"
            b" ([93.184.216.34]) by mx.company.example;"
            b" Mon, 1 Jan 2024 00:00:00 +0000\r\n"
            b"Received-SPF: pass (pps.local: domain of partner.example"
            b" designates 93.184.216.34 as permitted sender)\r\n"
            b"\r\nHello.\r\n"
        )
        assert "AUTH006" not in fired(findings)

    def test_spamassassin_status_header(self):
        """The real header begins "No," and carries a score and version."""
        findings = analyse(
            b"From: a@b.example\r\nTo: c@d.example\r\nSubject: Notice\r\n"
            b"X-Spam-Status: No, score=-2.6 required=5.0"
            b" tests=BAYES_00,DKIM_SIGNED,DKIM_VALID autolearn=ham"
            b" version=3.4.6\r\n\r\nHello.\r\n"
        )
        assert "AUTH007" not in fired(findings)


class TestListsAndBulkSenders:
    LIST_HEADERS = (
        b"List-Id: <dev.project.example>\r\n"
        b"List-Unsubscribe: <mailto:dev-leave@lists.project.example>\r\n"
    )

    def test_mailing_list_bounce_envelope(self):
        """A distinct bounce address is required practice for lists."""
        findings = analyse(
            b"Return-Path: <dev-bounces@lists.project.example>\r\n"
            b"From: Pat <pat@contributor.example>\r\n"
            b"Reply-To: dev@lists.project.example\r\n"
            b"To: dev@lists.project.example\r\n"
            b"Subject: [dev] release notes\r\n" + self.LIST_HEADERS +
            b"\r\nNotes below.\r\n"
        )
        assert "ROUTE006" not in fired(findings)
        assert "CONT001" not in fired(findings)

    def test_dmarc_from_munging_by_a_list(self):
        """Mailman rewrites From when the author's domain is p=reject.

        The named sender really did write it, so reporting the rewrite as
        impersonation is exactly backwards.
        """
        findings = analyse(
            b'From: "dana@company.example (via dev list)"'
            b" <dev@lists.project.example>\r\n"
            b"To: dev@lists.project.example\r\nSubject: [dev] hi\r\n"
            + self.LIST_HEADERS + b"\r\nHello.\r\n"
        )
        assert "CONT008" not in fired(findings)

    def test_esp_click_tracking(self):
        """Visible text is the destination, href is the redirector."""
        findings = analyse(
            b"From: News <news@news.retailer.example>\r\n"
            b"Reply-To: support@retailer.example\r\n"
            b"To: c@d.example\r\nSubject: Spring offers\r\n"
            b"List-Unsubscribe: <https://click.esp.example/u/1>\r\n"
            b"MIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n"
            b'<html><body><a href="https://click.esp.example/c/9xj">'
            b"www.retailer.example/news</a></body></html>\r\n"
        )
        assert "CONT003" not in fired(findings)

    def test_reply_to_a_sibling_subdomain_is_not_high(self):
        findings = analyse(
            b"From: News <news@news.retailer.example>\r\n"
            b"Reply-To: support@retailer.example\r\n"
            b"To: c@d.example\r\nSubject: Offers\r\n\r\nHello.\r\n"
        )
        assert loud([f for f in findings if f.id == "CONT001"]) == []

    def test_out_of_office_autoreply(self):
        """Absence notices discuss deadlines; they are not pressuring."""
        findings = analyse(
            b"From: Dana <dana@company.example>\r\nTo: a@b.example\r\n"
            b"Subject: Re: Monthly schedule\r\n"
            b"Auto-Submitted: auto-replied\r\n"
            b"X-Auto-Response-Suppress: All\r\n\r\n"
            b"I am out of the office until 24 March. For anything urgent "
            b"contact the operations desk; approval requests will expire "
            b"if left unanswered, and failure to reassign returns them.\r\n"
        )
        assert "CONT005" not in fired(findings)
        assert "IDN004" not in fired(findings)


class TestDeveloperAndVendorMail:
    def test_zip_of_a_web_build_is_not_critical(self):
        """.js inside an archive is what a web build *is*."""
        import base64
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("site/index.html", b"<html></html>")
            archive.writestr("site/js/app.js", b"console.log(1)")
        payload = base64.encodebytes(buf.getvalue())
        findings = analyse(
            b"From: Dev <dev@company.example>\r\nTo: ops@company.example\r\n"
            b"Subject: build\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            b"--b\r\nContent-Type: text/plain\r\n\r\nbuild attached\r\n"
            b'--b\r\nContent-Type: application/zip; name="site-build.zip"\r\n'
            b'Content-Disposition: attachment; filename="site-build.zip"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n" + payload +
            b"\r\n--b--\r\n"
        )
        critical = [f for f in findings if f.severity is Severity.CRITICAL]
        assert critical == [], [f.title for f in critical]

    @pytest.mark.parametrize("name", ["contract.odt", "model.xlsm",
                                      "deck.pptm", "book.epub", "lib.whl"])
    def test_zip_based_document_formats_are_not_type_mismatches(self, name):
        """ODF, OOXML macro formats and wheels are all ZIP containers."""
        import base64
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("content.xml", b"<x/>")
        payload = base64.encodebytes(buf.getvalue())
        findings = analyse(
            b"From: a@b.example\r\nTo: c@d.example\r\nSubject: doc\r\n"
            b"MIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            b"--b\r\nContent-Type: text/plain\r\n\r\nattached\r\n"
            b"--b\r\nContent-Type: application/octet-stream;\r\n"
            b' name="' + name.encode() + b'"\r\n'
            b"Content-Disposition: attachment;\r\n"
            b' filename="' + name.encode() + b'"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n" + payload +
            b"\r\n--b--\r\n"
        )
        assert "ATT003" not in fired(findings)

    def test_ci_notification_with_a_version_as_link_text(self):
        """"v2.1.0" has a dot but is not a hostname."""
        findings = analyse(
            b"From: CI <ci@company.example>\r\nTo: dev@company.example\r\n"
            b"Subject: build passed\r\nMIME-Version: 1.0\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b'<html><body>Released <a href="https://ci.company.example/r/9">'
            b"v2.1.0</a> and <a href=\"https://ci.company.example/a/1\">"
            b"Q1-report.pdf</a></body></html>\r\n"
        )
        assert "CONT003" not in fired(findings)

    def test_security_advisory_citing_a_different_cve_than_it_links(self):
        """A CVE is a public catalogue reference, not a per-message record."""
        findings = analyse(
            b"From: Sec <sec@vendor.example>\r\nTo: ops@company.example\r\n"
            b"Subject: advisory\r\n\r\n"
            b"This advisory concerns CVE-2025-21345. Background on the "
            b"related issue: https://nvd.example/vuln/CVE-2025-21298\r\n"
        )
        assert "CONT002" not in fired(findings)

    def test_encrypted_archive_whose_body_withholds_the_password(self):
        """"we never send the password by email" is the opposite claim."""
        findings = analyse(
            b"From: Payroll <payroll@bureau.example>\r\n"
            b"To: hr@company.example\r\nSubject: March payslips\r\n\r\n"
            b"Payslips attached. We never send the password by email -- "
            b"please use the agreed shared secret from the onboarding "
            b"pack.\r\n"
        )
        att006 = [f for f in findings if f.id == "ATT006"]
        assert all(f.severity is not Severity.CRITICAL for f in att006)


class TestInternationalMail:
    def test_a_cyrillic_domain_under_a_latin_tld(self):
        """кофейня.ru is a Russian coffee shop, not a homoglyph attack."""
        findings = analyse(
            b"From: Zakaz <zakaz@xn--e1aiboc0b6e.ru>\r\n"
            b"To: a@b.example\r\nSubject: order\r\n\r\nSpasibo.\r\n"
        )
        assert loud(findings) == [], [f.title for f in loud(findings)]

    def test_an_accented_latin_domain(self):
        findings = analyse(
            b"From: Reise <info@xn--mnchen-reisebro-zvbm.de>\r\n"
            b"To: a@b.example\r\nSubject: Buchung\r\n\r\nDanke.\r\n"
        )
        assert loud(findings) == [], [f.title for f in loud(findings)]
        assert "IDN002" not in fired(findings)

    def test_emoji_with_a_zero_width_joiner_in_the_subject(self):
        findings = analyse(
            "From: HR <hr@company.example>\r\nTo: a@b.example\r\n"
            "Subject: We are hiring \U0001f469‍\U0001f4bb engineers\r\n"
            "\r\nApply within.\r\n".encode()
        )
        assert "IDN003" not in fired(findings)


class TestInfrastructureNoise:
    def test_small_clock_skew_between_relays(self):
        findings = analyse(
            b"From: a@b.example\r\nTo: c@d.example\r\nSubject: x\r\n"
            b"Received: from r2.example by mx.example;"
            b" Mon, 1 Jan 2024 10:00:00 +0000\r\n"
            b"Received: from r1.example by r2.example;"
            b" Mon, 1 Jan 2024 10:00:01 +0000\r\n\r\nbody\r\n"
        )
        assert "ROUTE003" not in fired(findings)

    def test_timestamps_in_different_zones_are_compared_in_utc(self):
        """10:30:06 +0100 and 09:30:04 +0000 are 2 seconds apart."""
        findings = analyse(
            b"From: a@b.example\r\nTo: c@d.example\r\nSubject: x\r\n"
            b"Received: from r2.example by mx.example;"
            b" Mon, 1 Jan 2024 10:30:06 +0100\r\n"
            b"Received: from r1.example by r2.example;"
            b" Mon, 1 Jan 2024 09:30:04 +0000\r\n\r\nbody\r\n"
        )
        assert "ROUTE003" not in fired(findings)

    def test_internal_private_relays(self):
        findings = analyse(
            b"From: it@company.example\r\nTo: all@company.example\r\n"
            b"Subject: Maintenance\r\n"
            b"Received: from relay2.company.example ([10.20.4.8])"
            b" by mx.company.example; Mon, 1 Jan 2024 10:00:00 +0000\r\n"
            b"Received: from relay1.company.example ([10.20.4.7])"
            b" by relay2.company.example;"
            b" Mon, 1 Jan 2024 09:59:00 +0000\r\n\r\nPlanned work.\r\n"
        )
        route005 = [f for f in findings if f.id == "ROUTE005"]
        assert all(f.severity is Severity.INFO for f in route005)
        # The RFC 5737 reasoning must not be applied to RFC 1918.
        assert all("synthetic" not in f.detail for f in route005)

    def test_webmail_originating_ip(self):
        findings = analyse(
            b"From: a@webmail.example\r\nTo: c@d.example\r\nSubject: x\r\n"
            b"X-Originating-IP: [203.0.113.200]\r\n"
            b"Received: from mail.webmail.example ([93.184.216.34])"
            b" by mx.example; Mon, 1 Jan 2024 10:00:00 +0000\r\n\r\nhi\r\n"
        )
        route004 = [f for f in findings if f.id == "ROUTE004"]
        assert all(f.severity is Severity.INFO for f in route004)

    def test_message_exported_from_a_sent_folder(self):
        findings = analyse(
            b"From: dana@company.example\r\nTo: c@d.example\r\n"
            b"Subject: notes\r\n\r\nAs discussed.\r\n"
        )
        auth008 = [f for f in findings if f.id == "AUTH008"]
        assert all(f.severity is Severity.INFO for f in auth008)

    def test_forwarded_mail_breaking_spf(self):
        """SPF breaking across an alias is why ARC exists."""
        findings = analyse(
            b"From: Supplier <p@supplier.example>\r\n"
            b"To: me@company.example\r\nSubject: invoice\r\n"
            b"Authentication-Results: mx.company.example;"
            b" spf=pass smtp.mailfrom=alumni.example; dkim=none;"
            b" dmarc=fail action=none header.from=supplier.example\r\n"
            b"\r\nInvoice attached.\r\n"
        )
        auth009 = [f for f in findings if f.id == "AUTH009"]
        assert all(f.severity is Severity.INFO for f in auth009)


class TestTheCleanFixtureStaysClean:
    def test_no_findings_at_all(self, clean_findings):
        assert clean_findings == [], [f.title for f in clean_findings]
