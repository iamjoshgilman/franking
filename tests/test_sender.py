"""Tests for the corpus-derived sender rules.

These two rules exist because they were measured, not because they
sounded plausible. The numbers in the docstrings are from 4,400
legitimate messages and 3,000 real phishing samples; the tests below
pin the behaviour those numbers describe.
"""

import pytest

from franking.model import Severity
from franking.parse import EmailDoc
from franking.rules import run_all
from franking.rules.sender import looks_generated
from tests.conftest import fired


def message(from_header: bytes, *extra: bytes) -> EmailDoc:
    head = b"From: " + from_header + b"\r\nTo: a@b.example\r\nSubject: hi\r\n"
    for line in extra:
        head += line + b"\r\n"
    return EmailDoc(head + b"\r\nbody\r\n")


class TestLooksGenerated:
    @pytest.mark.parametrize("label", [
        "jklfrostbornwarriors",
        "qsdfhoopleaguee",
    ])
    def test_names_failing_the_vowel_rhythm_test(self, label):
        assert looks_generated(label) is True

    def test_a_pronounceable_but_absurd_name_is_caught_by_length_instead(self):
        """"atyflashfortunepro" reads almost pronounceably.

        The rhythm test is one of two signals; this one is caught by
        being 18 characters long. Asserting the wrong mechanism here
        would invite loosening the rhythm test until it caught it.
        """
        assert looks_generated("atyflashfortunepro") is False
        doc = message(b"<a@atyflashfortunepro.example>")
        assert "SEND002" in fired(run_all(doc))

    @pytest.mark.parametrize("label", [
        "supplier", "northwind", "company", "retailer", "theserverside",
        "münchen-reisebüro", "ucsc", "homeport",
    ])
    def test_human_chosen_names(self, label):
        assert looks_generated(label) is False

    def test_short_names_are_never_generated(self):
        assert looks_generated("abcdefgh") is False


class TestFreeTenantSender:
    def test_microsoft_tenant_fires(self):
        doc = message(b"'Spinboss Slots' <a.b@jklfrostborn.onmicrosoft.com>")
        finding = next(f for f in run_all(doc) if f.id == "SEND001")
        assert finding.severity is Severity.MEDIUM
        assert "onmicrosoft.com" in finding.title

    def test_mentions_that_authentication_proves_nothing(self):
        doc = message(
            b"'Acme' <a@tenant.onmicrosoft.com>",
            b"Authentication-Results: mx.example; spf=pass"
            b" smtp.mailfrom=tenant.onmicrosoft.com;"
            b" dkim=pass header.d=tenant.onmicrosoft.com",
        )
        finding = next(f for f in run_all(doc) if f.id == "SEND001")
        assert "says nothing about who the sender is" in finding.detail

    @pytest.mark.parametrize("domain", [
        b"pages.dev", b"workers.dev", b"netlify.app", b"herokuapp.com",
    ])
    def test_other_free_platforms(self, domain):
        doc = message(b"<a@project." + domain + b">")
        assert "SEND001" in fired(run_all(doc))

    def test_an_ordinary_domain_is_quiet(self):
        assert "SEND001" not in fired(run_all(message(b"<a@supplier.example>")))

    def test_a_domain_merely_containing_the_suffix_is_quiet(self):
        """onmicrosoft.com.evil.example is not a Microsoft tenant."""
        doc = message(b"<a@onmicrosoft.com.evil.example>")
        assert "SEND001" not in fired(run_all(doc))


class TestGeneratedSenderDomain:
    def test_a_generated_name_fires(self):
        doc = message(b"'Rewards' <harper@jkuyhoopleague2503.example>")
        assert "SEND002" in fired(run_all(doc))

    def test_a_very_long_name_fires(self):
        doc = message(b"<a@averyveryverylongdomainname.example>")
        assert "SEND002" in fired(run_all(doc))

    def test_an_ordinary_name_is_quiet(self):
        assert "SEND002" not in fired(run_all(message(b"<a@supplier.example>")))

    def test_punycode_is_judged_on_its_decoded_form(self):
        """An A-label is machine encoding; that is not evidence."""
        doc = message(b"<info@xn--mnchen-reisebro-zvbm.de>")
        assert "SEND002" not in fired(run_all(doc))

    def test_a_long_descriptive_list_name_is_quiet(self):
        doc = message(
            b"<news@internationaldevelopmentnews.example>",
            b"List-Id: <news.internationaldevelopmentnews.example>",
        )
        assert "SEND002" not in fired(run_all(doc))


class TestDiscardedSignals:
    """Signals measured and rejected, recorded so they are not re-added.

    "The display name shares no word with the sending domain" fires on
    81% of legitimate mail against 77% of phishing -- marginally worse
    than a coin toss. It is the heuristic CONT008 originally used.
    """

    def test_display_name_unrelated_to_domain_does_not_fire_alone(self):
        doc = message(b'"Quarterly Review Committee" <noreply@acme.example>')
        loud = [f for f in run_all(doc) if f.severity.rank >= Severity.MEDIUM.rank]
        assert loud == [], [f.title for f in loud]
