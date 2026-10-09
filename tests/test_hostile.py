"""Parser behaviour on hostile and malformed input.

This tool is pointed at files written by someone who would rather it
reported the wrong thing. Each test here corresponds to a way the parser
could previously be made to produce a confident wrong answer, crash, or
refuse to work at all.
"""

import io
import struct
import time
import zipfile

import pytest

from franking.parse import EmailDoc, scan_zip_entries, valid_ipv4


def local_header(name: bytes, flags=0, csize=None, usize=None, body=b""):
    csize = len(body) if csize is None else csize
    usize = len(body) if usize is None else usize
    return struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, flags, 0, 0, 0,
                       0x1234, csize, usize, len(name), 0) + name + body


def message(*headers: bytes, body: bytes = b"body") -> bytes:
    return b"\r\n".join(headers) + b"\r\n\r\n" + body + b"\r\n"


class TestForgedReceivedHeaders:
    def test_encoded_word_cannot_fabricate_a_hop(self):
        """RFC 2047 decoding used to hand an attacker the delimiters.

        Q-encoding turns "_" into a space and supplies brackets, so a
        whole hop -- host and source IP -- could be written inside one
        encoded word in a header the sender controls.
        """
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Received: from mx.corp.example (mx.corp.example [203.0.113.9])"
            b" by inbound.corp.example; Mon, 1 Jan 2024 10:00:00 +0000",
            b"Received: from =?utf-8?q?evil.example_=5B192=2E0=2E2=2E50=5D?="
            b" by relay.evil.example; Mon, 1 Jan 2024 09:00:00 +0000",
        ))
        assert "192.0.2.50" not in doc.chain_ips
        assert doc.hops[0].from_ip is None

    def test_the_encoded_word_is_recorded_as_a_fact(self):
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Received: from =?utf-8?q?evil_=5B192=2E0=2E2=2E50=5D?="
            b" by mx.example; Mon, 1 Jan 2024 09:00:00 +0000",
        ))
        assert doc.hops[0].encoded_word is True

    def test_by_is_not_matched_inside_a_comment(self):
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Received: from relay.example (authenticated by smtp-auth)"
            b" by real-mx.example with ESMTP id ABC;"
            b" Mon, 1 Jan 2024 00:00:00 +0000",
        ))
        assert doc.hops[0].by_host == "real-mx.example"

    def test_receiver_interface_is_not_reported_as_the_source(self):
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Received: from mail.example (helo=mail.example)"
            b" by mx.internal ([192.168.1.1]) with ESMTPS;"
            b" Mon, 1 Jan 2024 00:00:00 +0000",
        ))
        assert doc.hops[0].from_ip is None

    def test_envelope_from_is_not_mistaken_for_a_helo_name(self):
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Received: by mx.example (Postfix) id 4ABC"
            b" (envelope-from <evil@evil.example>);"
            b" Mon, 1 Jan 2024 00:00:00 +0000",
        ))
        assert doc.hops[0].from_host is None

    def test_out_of_range_octets_are_rejected(self):
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Received: from h ([999.888.777.666]) by mx.example;"
            b" Mon, 1 Jan 2024 00:00:00 +0000",
        ))
        assert doc.hops[0].from_ip is None


class TestValidIpv4:
    @pytest.mark.parametrize("text,ok", [
        ("192.0.2.1", True), ("0.0.0.0", True), ("255.255.255.255", True),
        ("999.888.777.666", False), ("1.2.3", False), ("1.2.3.4.5", False),
        ("01.2.3.4", False), ("a.b.c.d", False), ("", False),
    ])
    def test_octet_validation(self, text, ok):
        assert valid_ipv4(text) is ok


class TestAuthenticationResults:
    def test_verdicts_are_not_read_from_the_arc_comment(self):
        """Gmail restates inner results inside its arc=pass comment.

        A whole-header search found those first, so a message whose real
        results were all failures reported as all passes.
        """
        doc = EmailDoc(message(
            b"From: Bank <no-reply@bank.example>",
            b"Authentication-Results: mx.google.com;"
            b" arc=pass (i=1 spf=pass dkim=pass dmarc=pass);"
            b" spf=softfail (google.com: domain of bounce@evil.example)"
            b" smtp.mailfrom=bounce@evil.example;"
            b" dkim=fail header.d=evil.example;"
            b" dmarc=fail (p=REJECT) header.from=bank.example",
        ))
        assert (doc.auth.spf, doc.auth.dkim, doc.auth.dmarc) == (
            "softfail", "fail", "fail")

    def test_authserv_id_is_still_read(self):
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Authentication-Results: mx.google.com; spf=pass"
            b" smtp.mailfrom=b.example",
        ))
        assert doc.auth.authserv_id == "mx.google.com"

    def test_verdict_and_domain_come_from_the_same_section(self):
        """Independent first-match could pair a fail with another's domain."""
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Authentication-Results: mx.example; dkim=fail;"
            b" dkim=pass header.d=evil.example",
        ))
        assert doc.auth.dkim == "fail"
        assert doc.auth.dkim_domain is None

    def test_additional_result_headers_are_kept(self):
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Authentication-Results: attacker.example; spf=pass",
            b"Authentication-Results: real-mx.example; spf=fail",
        ))
        assert doc.auth.result_header_count == 2
        assert doc.auth.extra_raw

    def test_received_spf_prefers_client_ip_over_prose(self):
        doc = EmailDoc(message(
            b"From: a@b.example",
            b"Received-SPF: fail (bank.example: 192.0.2.1 is not permitted"
            b" to send mail) client-ip=203.0.113.9;",
        ))
        assert doc.auth.received_spf_ip == "203.0.113.9"
        assert doc.auth.received_spf_result == "fail"


class TestZipScanner:
    def test_central_directory_wins_over_local_header(self):
        """Extractors read the central directory; so must we."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("harmless.txt", b"hello world")
        blob = bytearray(buf.getvalue())
        start = blob.find(b"harmless.txt", blob.find(b"PK\x01\x02"))
        blob[start:start + 12] = b"payload.exe\x00"
        entries, _ = scan_zip_entries(bytes(blob))
        assert [e.name for e in entries] == ["payload.exe"]

    def test_data_descriptor_does_not_fabricate_members(self):
        inner = local_header(b"DECOY-NOT-REAL.txt", body=b"\x00" * 4)
        data = local_header(b"real.docx", flags=0x08, csize=0, usize=0,
                            body=b"AAAA" + inner + b"BBBB")
        entries, _ = scan_zip_entries(data)
        assert [e.name for e in entries] == ["real.docx"]

    def test_entry_count_is_capped(self):
        header = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0,
                             0, 0, 0, 8, 0) + b"name.txt"
        entries, _ = scan_zip_entries(header * 200_000)
        assert len(entries) <= 2048

    def test_signature_runs_do_not_become_filenames(self):
        entries, _ = scan_zip_entries(b"PK\x03\x04" * 2000)
        assert all(len(e.name) <= 512 for e in entries)

    def test_large_crafted_archive_is_fast(self):
        header = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0,
                             0, 0, 0, 8, 0) + b"name.txt"
        started = time.monotonic()
        scan_zip_entries(header * 200_000)
        assert time.monotonic() - started < 2.0

    def test_cp437_names_are_decoded(self):
        entries, _ = scan_zip_entries(local_header(b"R\x82sum\x82.exe"))
        assert entries[0].name == "R\xe9sum\xe9.exe"

    def test_utf8_flag_is_honoured(self):
        name = "文書.exe".encode()
        entries, _ = scan_zip_entries(local_header(name, flags=0x800))
        assert entries[0].name == "文書.exe"

    def test_truncated_archive_still_yields_names(self):
        entries, truncated = scan_zip_entries(
            local_header(b"payload.doc.js", csize=9999))
        assert truncated is True
        assert entries[0].name == "payload.doc.js"

    def test_empty_input(self):
        assert scan_zip_entries(b"") == ([], False)


class TestDenialOfAnalysis:
    def test_deep_multipart_nesting_raises_cleanly(self):
        raw = b"From: a@b.example\r\nMIME-Version: 1.0\r\n"
        raw += b'Content-Type: multipart/mixed; boundary="b0"\r\n\r\n'
        for i in range(1200):
            raw += b"--b%d\r\n" % i
            raw += b'Content-Type: multipart/mixed; boundary="b%d"\r\n\r\n' % (i + 1)
        try:
            EmailDoc(raw)
        except ValueError:
            pass  # a clean refusal is acceptable
        except RecursionError:
            pytest.fail("RecursionError escaped the parser")

    @pytest.mark.parametrize("charset", [b"utf-8\x00", b"idna", b"base64",
                                         b"nonexistent-codec"])
    def test_hostile_charset_does_not_abort_the_parse(self, charset):
        doc = EmailDoc(
            b"From: a@b.example\r\nSubject: x\r\n"
            b'Content-Type: text/plain; charset="' + charset + b'"\r\n'
            b"\r\nhello\r\n"
        )
        assert "hello" in doc.body_text

    def test_long_address_header_is_bounded(self):
        raw = b"From: <" + b"a.+-" * 32_000 + b">:;\r\nSubject: x\r\n\r\nb\r\n"
        started = time.monotonic()
        assert EmailDoc(raw).from_addr is not None
        assert time.monotonic() - started < 2.0


class TestNestedMessageAttachment:
    def test_attached_message_reports_its_real_size(self):
        """get_payload(decode=True) is None for message/*.

        The most important artifact in a forwarded report used to show
        0 bytes and the MD5 of the empty string.
        """
        inner = b"From: p@q.example\r\nSubject: inner\r\n\r\ninner body\r\n"
        raw = (b"From: a@b.example\r\nMIME-Version: 1.0\r\n"
               b'Content-Type: multipart/mixed; boundary="x"\r\n\r\n'
               b"--x\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
               b"--x\r\nContent-Type: message/rfc822; name=\"phish.eml\"\r\n"
               b"Content-Disposition: attachment; filename=\"phish.eml\"\r\n\r\n"
               + inner + b"\r\n--x--\r\n")
        doc = EmailDoc(raw)
        attachment = doc.attachments[0]
        assert attachment.size > 0
        assert attachment.md5 != "d41d8cd98f00b204e9800998ecf8427e"
