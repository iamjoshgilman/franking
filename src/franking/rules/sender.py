"""Rules about the sending domain itself.

Derived by measuring candidate signals across 4,400 legitimate messages
(SpamAssassin ham) and 3,000 real phishing samples (Phishing Pot), and
keeping only those that actually separated the two. Several plausible
ideas were discarded on the evidence -- notably "the display name shares
no word with the sending domain", which fires on 81% of legitimate mail
and 77% of phishing, making it slightly worse than useless.

A caveat that matters for SEND001: the ham corpus predates cloud mail
tenancy entirely, so its 0% rate for that signal is not evidence of a low
false-positive rate on *today's* legitimate mail. The rule is calibrated
conservatively for that reason.
"""

from __future__ import annotations

import collections
import math
import re

from franking.model import Evidence, Severity
from franking.parse import decode_punycode, org_domain
from franking.rules import rule
from franking.rules._context import is_bulk

# Mail tenancies that are free or trivially obtainable, where the domain
# is assigned rather than registered. A real organisation that has
# finished setting up sends from its own name.
TENANT_SUFFIXES = {
    "onmicrosoft.com": "a Microsoft 365 tenant default domain",
    "sharepointonline.com": "a SharePoint Online tenant domain",
    "b2clogin.com": "an Azure AD B2C tenant domain",
    "firebaseapp.com": "a Firebase project domain",
    "web.app": "a Firebase hosting domain",
    "glitch.me": "a Glitch project domain",
    "repl.co": "a Replit project domain",
    "workers.dev": "a Cloudflare Workers default domain",
    "pages.dev": "a Cloudflare Pages default domain",
    "netlify.app": "a Netlify default domain",
    "vercel.app": "a Vercel default domain",
    "herokuapp.com": "a Heroku default domain",
    "r2.dev": "a Cloudflare R2 default domain",
    "blob.core.windows.net": "an Azure Blob Storage domain",
}

VOWELS = frozenset("aeiouy")
MIN_RANDOM_LENGTH = 10
MIN_LABEL_ENTROPY = 3.0
MAX_VOWEL_RATIO = 0.30
MIN_CONSONANT_RUN = 5
LONG_LABEL = 18


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = collections.Counter(text)
    return -sum((n / len(text)) * math.log2(n / len(text))
                for n in counts.values())


def _longest_consonant_run(text: str) -> int:
    best = run = 0
    for char in text:
        if char.isalpha() and char not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def looks_generated(label: str) -> bool:
    """Does a domain label look typed by a program rather than a person?

    Human-chosen names keep a roughly English vowel rhythm even when they
    are invented. Bulk-registered and keyboard-mashed names do not:
    "qsdfhoopleaguee" and "jklfrostbornwarriors" both came out of the
    phishing corpus.
    """
    cleaned = re.sub(r"[^a-z]", "", label.lower())
    if len(cleaned) < MIN_RANDOM_LENGTH:
        return False
    vowel_ratio = sum(1 for c in cleaned if c in VOWELS) / len(cleaned)
    unusual = (vowel_ratio < MAX_VOWEL_RATIO
               or _longest_consonant_run(cleaned) >= MIN_CONSONANT_RUN)
    return unusual and _entropy(cleaned) > MIN_LABEL_ENTROPY


@rule("SEND001", "Sender uses a free cloud tenant domain", Severity.MEDIUM,
      mitre=["T1583.001", "T1566"])
def free_tenant_sender(doc, emit):
    """A domain that was assigned, not registered.

    Measured at 20% of real phishing. A Microsoft 365 trial tenant costs
    nothing, arrives with working DKIM and a Microsoft-signed envelope,
    and gives an attacker authenticated mail from day one -- which is why
    those samples so often pass SPF, DKIM and DMARC.

    Kept at MEDIUM rather than HIGH: organisations mid-migration do
    legitimately send this way, and the legitimate corpus available here
    predates cloud tenancy, so there is no honest measurement of how
    often that happens today.
    """
    domain = doc.domain_of(doc.from_addr)
    if not domain:
        return None
    for suffix, description in TENANT_SUFFIXES.items():
        if domain == suffix or domain.endswith("." + suffix):
            tenant = domain[:-len(suffix)].rstrip(".") or "(none)"
            aligned = doc.auth.dkim == "pass" or doc.auth.spf == "pass"
            note = (
                " Note that it also passes authentication: the tenant "
                "really does own this domain, so a green DKIM or SPF "
                "result says nothing about who the sender is."
                if aligned else ""
            )
            return emit(
                f"The sender's domain {domain} is {description} -- assigned "
                f"automatically with the account rather than registered by "
                f"an organisation. Tenants are free or near-free and "
                f"disposable, which makes them a staple of phishing that "
                f"needs working authentication.{note} An established "
                f"business sends from a domain carrying its own name.",
                [
                    Evidence("Sender domain", domain),
                    Evidence("Tenant name", tenant),
                    Evidence("Domain type", description),
                    Evidence("SPF", doc.auth.spf or "absent"),
                    Evidence("DKIM", doc.auth.dkim or "absent"),
                ],
                title_override=f"Free tenant domain: {domain}",
            )
    return None


@rule("SEND002", "Sender domain looks algorithmically generated",
      Severity.MEDIUM, mitre=["T1583.001"])
def generated_sender_domain(doc, emit):
    """Bulk-registered throwaway domains.

    Measured against both corpora: an unusually long registrable label
    appears in 9.3% of phishing and 0.1% of legitimate mail, and a
    label failing a vowel-rhythm test in 6.3% against 0.4%. Campaigns
    register domains in bulk from a generator and burn them, so the
    names come out longer and less pronounceable than anything a
    business would choose for itself.
    """
    domain = doc.domain_of(doc.from_addr)
    if not domain:
        return None
    # Test the name as a human reads it. A punycode A-label is machine
    # encoding by definition -- "xn--mnchen-reisebro-zvbm" is long and
    # vowel-poor because it is an encoding of "münchen-reisebüro", which
    # is neither.
    readable = decode_punycode(domain) or domain
    org = org_domain(readable)
    label = org.split(".")[0]
    if not label:
        return None

    reasons = []
    if len(label) >= LONG_LABEL:
        reasons.append(f"it is {len(label)} characters long")
    if looks_generated(label):
        cleaned = re.sub(r"[^a-z]", "", label.lower())
        ratio = (sum(1 for c in cleaned if c in VOWELS) / len(cleaned)
                 if cleaned else 0)
        reasons.append(
            f"its letters do not follow a pronounceable rhythm "
            f"({ratio:.0%} vowels, longest consonant run "
            f"{_longest_consonant_run(cleaned)})"
        )
    if not reasons:
        return None
    # A long name on a list that identifies itself is usually a real,
    # descriptive organisation name.
    if len(reasons) == 1 and is_bulk(doc):
        return None

    return emit(
        f"The sending domain's name '{label}' looks generated rather than "
        f"chosen: {', and '.join(reasons)}. Campaigns register domains in "
        f"bulk from a generator and discard them after a few days, so the "
        f"names come out longer and less pronounceable than one a business "
        f"would pick and keep. On its own this is circumstantial; alongside "
        f"any other finding it suggests throwaway infrastructure.",
        [
            Evidence("Sender domain", domain),
            Evidence("Registrable domain", org),
            Evidence("Name examined", label),
            Evidence("Length", str(len(label))),
        ],
        title_override=f"Generated-looking sender domain: {org}",
    )
