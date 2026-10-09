"""Parser tests: extraction only, no judgement."""

from franking.parse import EmailDoc, classify_ip, scan_zip_entries


class TestAddresses:
    def test_pulls_address_out_of_display_form(self, phish):
        assert phish.from_addr == "billing@acme-invoices.example"
        assert phish.from_display == "Northwind Logistics Billing"

    def test_reply_to_and_return_path(self, phish):
        assert phish.reply_to == "recovery@secure-acme-portal.example"
        assert phish.return_path == "billing@acme-invoices.example"

    def test_domain_of(self):
        assert EmailDoc.domain_of("a@b.example") == "b.example"
        assert EmailDoc.domain_of("not-an-address") == ""


class TestReceivedChain:
    def test_hops_are_in_transit_order(self, phish):
        # The bottom Received header in the file is the earliest hop.
        assert [h.index for h in phish.hops] == [0, 1]
        assert phish.hops[0].from_ip == "198.51.100.8"
        assert phish.hops[1].from_ip == "203.0.113.9"

    def test_parses_hop_fields(self, phish):
        last = phish.hops[-1]
        assert last.by_host == "mx.victim.example"
        assert last.protocol == "ESMTP"
        assert last.ident == "AA1122;"[:6]
        assert last.timestamp is not None
        assert last.timestamp.hour == 9

    def test_chain_ips_excludes_header_only_addresses(self, phish):
        assert phish.chain_ips == ["198.51.100.8", "203.0.113.9"]
        assert "45.33.21.9" not in phish.chain_ips


class TestAuthentication:
    def test_detects_missing_dkim_signature(self, phish):
        assert phish.auth.dkim == "pass"
        assert phish.auth.dkim_signature_present is False

    def test_real_dkim_signature_is_seen(self, clean):
        assert clean.auth.dkim_signature_present is True

    def test_authserv_id_present_only_when_real(self, phish, clean):
        assert phish.auth.authserv_id is None
        assert clean.auth.authserv_id == "mx.company.example"

    def test_received_spf_fields(self, phish):
        assert phish.auth.received_spf_result == "pass"
        assert phish.auth.received_spf_ip == "45.33.21.9"
        assert phish.auth.received_spf_verifier == "protection.outlook.com"

    def test_arc_tags_are_grouped_by_instance(self, phish):
        assert set(phish.auth.arc_sets) == {1}
        assert phish.auth.arc_sets[1]["arc-seal.cv"] == "pass"
        assert "arc-message-signature.b" not in phish.auth.arc_sets[1]


class TestUrls:
    def test_extracts_href_with_its_anchor_text(self, phish):
        real = next(u for u in phish.urls
                    if u.host == "secure-acme-portal.example")
        assert real.path == "/pay/INV-2025-9988"
        assert "billing.acme-invoices.example" in real.anchor_text

    def test_displayed_url_is_captured_separately(self, phish):
        # The anchor text is itself a URL -- that is the deception. Both the
        # destination and the decoy are worth recording, as separate entries.
        hosts = {u.host for u in phish.urls if u.scheme == "https"}
        assert hosts == {"secure-acme-portal.example",
                         "billing.acme-invoices.example"}

    def test_no_urls_in_plain_message(self, clean):
        assert [u for u in clean.urls if u.scheme.startswith("http")] == []


class TestAttachments:
    def test_decodes_and_hashes(self, phish):
        att = phish.attachments[0]
        assert att.filename == "statement_march.zip"
        assert att.content_type == "application/zip"
        assert len(att.sha256) == 64
        assert att.size > 0

    def test_reads_names_inside_the_archive(self, phish):
        names = [e.name for e in phish.attachments[0].archive_entries]
        assert "statement_march.pdf.exe" in names
        assert "readme.txt" in names

    def test_extension_chain(self, phish):
        entry = next(e for e in phish.attachments[0].archive_entries
                     if e.name.endswith(".exe"))
        assert entry.extensions == ["pdf", "exe"]
        assert entry.final_ext == "exe"

    def test_clean_message_has_no_attachments(self, clean):
        assert clean.attachments == []


class TestZipScanner:
    def test_recovers_names_from_a_truncated_archive(self):
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("payload.doc.js", b"x" * 500)
        full = buf.getvalue()

        # Cut the archive to just past the first local header + filename.
        truncated = full[:60]
        entries, was_truncated = scan_zip_entries(truncated)
        assert was_truncated is True
        assert entries[0].name == "payload.doc.js"

    def test_intact_archive_is_not_flagged(self):
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", b"hello")
        entries, was_truncated = scan_zip_entries(buf.getvalue())
        assert was_truncated is False
        assert [e.name for e in entries] == ["a.txt"]

    def test_empty_data_is_safe(self):
        assert scan_zip_entries(b"") == ([], False)


class TestIpClassification:
    def test_documentation_ranges(self):
        assert "TEST-NET-3" in classify_ip("203.0.113.9")
        assert "TEST-NET-2" in classify_ip("198.51.100.8")

    def test_private_ranges(self):
        assert classify_ip("10.1.2.3") is not None
        assert classify_ip("172.16.0.1") == "RFC 1918 private"
        assert classify_ip("172.32.0.1") is None

    def test_public_address_is_unremarkable(self):
        assert classify_ip("93.184.216.34") is None


class TestIdentifiers:
    def test_finds_reference_numbers(self, phish):
        found = phish.identifiers(phish.body_text)
        assert ("INV-2025-0441", "INV", "20250441") in found


class TestMultipartAlternative:
    """Regression: the HTML half of a message must reach the rules.

    body_text used to return only text/plain when both parts existed. In a
    multipart/alternative phish the plain part is routinely a decoy while
    the lure lives in the HTML, so urgency, identifiers and -- worst --
    an archive password were invisible to every rule that searches the
    body. No fixture caught it because they were all single-part.
    """

    ALTERNATIVE = (
        b"From: a@b.example\r\nTo: c@d.example\r\nSubject: statement\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/alternative; boundary="alt"\r\n\r\n'
        b"--alt\r\nContent-Type: text/plain\r\n\r\n"
        b"Please see the attached statement.\r\n"
        b"--alt\r\nContent-Type: text/html\r\n\r\n"
        b"<html><body><p>URGENT: final notice, suspension pending.</p>"
        b"<p>The archive password is Spring2025!</p>"
        b"<p>Invoice INV-2025-0441 is overdue.</p></body></html>\r\n"
        b"--alt--\r\n"
    )

    def test_both_parts_are_parsed(self):
        doc = EmailDoc(self.ALTERNATIVE)
        assert set(doc.bodies) == {"text/plain", "text/html"}

    def test_body_text_includes_the_plain_part(self):
        assert "attached statement" in EmailDoc(self.ALTERNATIVE).body_text

    def test_body_text_includes_the_html_part(self):
        body = EmailDoc(self.ALTERNATIVE).body_text.lower()
        assert "password is spring2025!" in body
        assert "urgent" in body

    def test_identifiers_are_found_in_the_html_half(self):
        doc = EmailDoc(self.ALTERNATIVE)
        assert ("INV-2025-0441", "INV", "20250441") in doc.identifiers(
            doc.body_text)

    def test_html_only_message_still_works(self):
        doc = EmailDoc(
            b"From: a@b.example\r\nTo: c@d.example\r\nSubject: x\r\n"
            b"Content-Type: text/html\r\n\r\n<html><body>hello</body></html>\r\n"
        )
        assert "hello" in doc.body_text

    def test_plain_only_message_still_works(self):
        doc = EmailDoc(
            b"From: a@b.example\r\nTo: c@d.example\r\nSubject: x\r\n\r\n"
            b"hello\r\n"
        )
        assert "hello" in doc.body_text

    def test_message_with_no_body_is_empty(self):
        doc = EmailDoc(b"From: a@b.example\r\nSubject: x\r\n\r\n")
        assert doc.body_text.strip() == ""
