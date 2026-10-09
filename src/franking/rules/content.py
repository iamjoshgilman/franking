"""Rules about what the message says and where it points.

Header forgery proves the message is not what it claims to be. Content rules
work out what it is trying to get the reader to *do*, which is what turns an
oddity into an incident.
"""

from __future__ import annotations

import re

from franking.model import Evidence, Severity
from franking.parse import ADDR_RE, BRAND_STEMS, org_domain
from franking.rules import rule
from franking.rules._context import (
    brand_family,
    is_autoreply,
    is_bounce,
    is_bulk,
    is_forwarded,
    same_org,
)

# A bare domain appearing inside free text, e.g. in a display name.
DOMAIN_IN_TEXT_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|co|io|uk|de|fr|us|ca|au|example)\b",
    re.I,
)

# No term may be a substring of another: the rule's only defence against
# noise is "at least two distinct phrases", and "expire"/"expires" both
# matching one word silently defeated it.
URGENCY_TERMS = (
    "urgent", "immediately", "final notice", "overdue", "suspend",
    "terminated", "expire", "within 24 hours", "act now", "last warning",
    "failure to", "penalt", "legal action", "account will be",
    "verify your", "confirm your identity", "unauthorised access",
    "unauthorized access", "click below to",
    # German
    "dringend", "sofort", "letzte mahnung", "gesperrt", "rechtliche",
    # Other languages. "urgent" already matches "urgente" and "suspend"
    # already matches "suspendu"/"suspendido", so those are omitted rather
    # than silently defeating the two-distinct-phrases threshold.
    "imm\u00e9diatement", "derni\u00e8re relance", "inmediatamente",
    "verifique su", "ihr konto", "ihre zahlung",
)

# 555-0100 through 555-0199 are reserved for fiction (NANP / ATIS-0300115).
FICTIONAL_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?555[-.\s]?01\d{2}\b")

PLAUSIBLE_TLD_RE = re.compile(
    r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:[:/?#]|$)", re.I)


def _anchor_hostname(anchor: str) -> str | None:
    """The hostname an anchor's text claims, or None if it claims none.

    "v2.1.0" and "Q1-report.pdf" contain dots but are not hostnames, and
    treating them as such made every CI notification and file-share mail
    a HIGH finding.
    """
    text = anchor.strip().strip("<>\u201c\u201d\"'")
    if " " in text or "@" in text or not PLAUSIBLE_TLD_RE.match(text):
        return None
    # Only a full URL claims a destination. Newsletters routinely use an
    # advertiser's bare company name ("HostJ2EE.com") as link text while
    # the href is the list's click tracker, and that is not deception.
    if not text.lower().startswith(("http://", "https://", "www.")):
        return None
    host = (text.split("://")[-1].split("/")[0].split("?")[0]
            .split("#")[0].lower())
    # A trailing component that is a known file extension means this is a
    # filename, not a host.
    if host.rsplit(".", 1)[-1] in {"pdf", "doc", "docx", "xls", "xlsx", "zip",
                                   "png", "jpg", "jpeg", "gif", "txt", "csv",
                                   "ppt", "pptx", "exe", "msi", "dmg"}:
        return None
    return host or None


# Identifier namespaces that refer to public catalogues rather than to a
# record belonging to this recipient.
PUBLIC_IDENTIFIER_PREFIXES = {
    "CVE", "CWE", "CAPEC", "RFC", "ISO", "ANSI", "NIST", "GHSA", "OSV",
    "KB", "MS", "USN", "DSA", "RHSA", "ALAS", "BDU", "JVN", "VU",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
    "lnkd.in", "t.ly", "s.id", "bl.ink", "kutt.it", "shorte.st",
    "soo.gd", "clck.ru", "qr.ae", "v.gd", "trib.al", "shrtco.de",
}


@rule("CONT001", "Reply-To points to a different address than From",
      Severity.HIGH, mitre=["T1566", "T1656"])
def reply_to_divergence(doc, emit):
    """Replies routed somewhere other than the apparent sender.

    Quiet on list and campaign mail: redirecting replies to the list, or
    away from a no-reply mailbox, is the entire purpose of those systems
    rather than a redirect worth reporting.
    """
    reply, frm = doc.reply_to, doc.from_addr
    if not reply or not frm or reply.lower() == frm.lower():
        return None
    if is_bulk(doc) or is_autoreply(doc):
        return None

    # Compare organisations, not raw hosts: news@news.retailer.example
    # and support@retailer.example are one company.
    if same_org(doc.domain_of(reply), doc.domain_of(frm)):
        return emit(
            f"Replies will go to {reply} rather than {frm}. Both belong to "
            f"{org_domain(doc.domain_of(frm))}, so this is routine routing "
            f"to a monitored mailbox -- noted only so the reply path is "
            f"visible alongside the sender.",
            [Evidence("From", frm), Evidence("Reply-To", reply)],
            severity_override=Severity.INFO,
            title_override="Reply-To is a different mailbox at the same organisation",
        )
    return emit(
        f"Replies will go to {reply}, not {frm} -- an unrelated organisation "
        f"({org_domain(doc.domain_of(reply))}). Recipients reply without "
        f"re-reading the address, so this quietly moves the conversation to "
        f"a mailbox the sender controls. It is the standard setup for "
        f"payment-redirection fraud.",
        [
            Evidence("From", frm),
            Evidence("Reply-To", reply),
            Evidence("Reply organisation", org_domain(doc.domain_of(reply))),
        ],
    )


@rule("CONT002", "Body identifier does not match the identifier in the link",
      Severity.HIGH, mitre=["T1566.002"])
def identifier_mismatch(doc, emit):
    text = doc.body_text
    # On a text/plain body, body_text contains the URLs themselves, so an
    # identifier in the link is also collected as a "body" identifier and
    # the mismatch can never be seen. Compare against prose only.
    prose = text
    for url in doc.urls:
        prose = prose.replace(url.url, " ")
    body_ids = doc.identifiers(prose)
    if not body_ids:
        return None

    findings = []
    for url in doc.urls:
        if url.scheme not in ("http", "https"):
            continue
        for full, prefix, digits in doc.identifiers(url.url.upper()):
            # Public catalogue references are not generated per message.
            # A security advisory can discuss CVE-2025-21345 and link
            # CVE-2025-21298 for context without anything being wrong.
            if prefix in PUBLIC_IDENTIFIER_PREFIXES:
                continue
            matches = [b for b in body_ids if b[1] == prefix]
            if not matches or any(b[2] == digits for b in matches):
                continue
            quoted = matches[0][0]
            findings.append(emit(
                f"The message body refers to {quoted}, but the link carries "
                f"{full}. A real portal link is generated from the record it "
                f"refers to, so the two always agree. A mismatch means the "
                f"link is a fixed landing page reused across every copy of "
                f"the campaign, and the body text was filled in separately.",
                [
                    Evidence("Identifier in body", quoted),
                    Evidence("Identifier in URL", full),
                    Evidence("URL", url.url),
                ],
            ))
    return findings


@rule("CONT003", "Link text does not match its destination",
      Severity.HIGH, mitre=["T1566.002"])
def anchor_destination_mismatch(doc, emit):
    findings = []
    for url in doc.urls:
        anchor = url.anchor_text.strip()
        if not anchor:
            continue
        anchor_host = _anchor_hostname(anchor)
        if anchor_host is None or anchor_host == url.host:
            continue
        # Click-tracking is how virtually every newsletter works: the
        # visible text is the real destination and the href is the ESP's
        # redirector. That is not deception, it is analytics.
        if same_org(anchor_host, url.host) or is_bulk(doc):
            continue
        findings.append(emit(
            f"The link is displayed as '{anchor}' but points at {url.host}. "
            f"The reader checks the visible text and never sees the real "
            f"destination.",
            [Evidence("Displayed", anchor), Evidence("Actual", url.url)],
        ))
    return findings


@rule("CONT004", "URL uses a link shortener", Severity.MEDIUM,
      mitre=["T1566.002"])
def shortened_url(doc, emit):
    findings = []
    for url in doc.urls:
        if url.host not in SHORTENERS:
            continue
        findings.append(emit(
            f"{url.host} hides the real destination behind a redirect, so "
            f"neither the reader nor most mail filters can see where the "
            f"link lands. Legitimate transactional mail links directly.",
            [Evidence("URL", url.url)],
        ))
    return findings


@rule("CONT005", "Urgency and consequence pressure", Severity.MEDIUM,
      mitre=["T1566"])
def urgency_language(doc, emit):
    text = doc.body_text.lower()
    if not text:
        return None
    # An auto-reply talks about deadlines and urgency because that is
    # what absence notices are about, not to pressure the reader.
    if is_autoreply(doc):
        return None
    hits = sorted({term for term in URGENCY_TERMS if term in text})
    if len(hits) < 2:
        return None
    priority = doc.get("X-Priority") or doc.get("Importance") or ""
    evidence = [Evidence("Phrases found", ", ".join(hits))]
    if priority:
        evidence.append(Evidence("Priority header", priority))
    return emit(
        f"The body stacks {len(hits)} pressure phrases ({', '.join(hits)}). "
        f"Manufactured time pressure exists to stop the reader doing the one "
        f"thing that defeats the attack: pausing to verify through a channel "
        f"they already trust.",
        evidence,
    )


@rule("CONT006", "Message carries both links and attachments",
      Severity.INFO, mitre=["T1566.001", "T1566.002"])
def dual_delivery_path(doc, emit):
    web_urls = [u for u in doc.urls if u.scheme in ("http", "https")]
    if not web_urls or not doc.attachments:
        return None
    return emit(
        f"The message carries {len(web_urls)} web link(s) and "
        f"{len(doc.attachments)} attachment(s). Noted as context rather "
        f"than as a finding on its own -- most business mail looks like "
        f"this. It matters when the other findings show the message is "
        f"hostile, because two delivery paths mean blocking one does not "
        f"stop it.",
        [
            Evidence("Links", ", ".join(u.url for u in web_urls)),
            Evidence("Attachments", ", ".join(a.filename for a in doc.attachments)),
        ],
    )


@rule("CONT007", "Reserved fictional phone number", Severity.INFO)
def fictional_phone_number(doc, emit):
    match = FICTIONAL_PHONE_RE.search(doc.body_text)
    if not match:
        return None
    return emit(
        f"{match.group(0)} falls in the 555-01xx block reserved for fiction, "
        f"so it cannot be dialled. Another sign this is training material "
        f"rather than a captured message -- do not treat it as an indicator.",
        [Evidence("Number", match.group(0))],
    )


@rule("CONT008", "Display name impersonates a different sender",
      Severity.HIGH, mitre=["T1656"])
def display_name_impersonation(doc, emit):
    """Only the cases that stand on their own evidence.

    An earlier version flagged any display name whose words were absent
    from the domain, which fires on every personal name -- 'Dana
    Whitfield' at company.example is simply a person, and accusing the
    employee who reported a phish is a fast way to lose an analyst's
    trust. Judging whether an arbitrary organisation name belongs to a
    domain needs a roster of who legitimately sends as what, and that is
    configuration this tool does not have yet.
    """
    display = doc.from_display
    domain = doc.domain_of(doc.from_addr)
    if not display or not domain:
        return None
    if is_bounce(doc):
        # "Microsoft Outlook" <MicrosoftExchange329e...@company.example>
        # is the literal sender of every Exchange non-delivery report.
        return None
    sending_org = org_domain(domain)

    # A display name carrying an address or domain of its own. Clients
    # show the name and hide the address, so "security@paypal.com" reads
    # as the sender while the mail came from somewhere else entirely.
    # Mailman, Google Groups and M365 Groups rewrite From as
    # "author@their.domain (via the list)" when the author's domain
    # publishes p=reject. The named sender really did write it, so
    # reporting it as impersonation is exactly backwards.
    # Only when the display name is *entirely* an address or domain. A
    # name that merely contains a dotted word -- "CNET News.com Daily
    # Dispatch" -- is prose, and matching inside it made a real
    # newsletter the single largest false positive in the corpus.
    stripped = display.strip().strip("<>\"'")
    claimed = (ADDR_RE.fullmatch(stripped)
               or DOMAIN_IN_TEXT_RE.fullmatch(stripped))
    # Forwarding and list software rewrites the display name to carry the
    # original sender, usually with an annotation in brackets or after a
    # slash. That is a provenance note, not an impersonation.
    if claimed and (is_bulk(doc) or is_forwarded(doc)
                    or any(mark in display for mark in "[]()/|")
                    or " via " in display.lower()):
        claimed = None
    if claimed:
        claimed_domain = claimed.group(0).split("@")[-1].lower().strip(".")
        if org_domain(claimed_domain) != sending_org:
            return emit(
                f"The display name is '{display}', which carries the "
                f"address or domain '{claimed_domain}', but the message was "
                f"sent from {domain}. Mail clients show the display name and "
                f"hide the real address, so the reader sees a sender that "
                f"had nothing to do with this message.",
                [
                    Evidence("Display name", display),
                    Evidence("Claimed", claimed_domain),
                    Evidence("Actually sent from", domain),
                ],
            )

    # A display name invoking a brand the sending domain does not belong to.
    # Every brand in the name has to be checked before concluding: with
    # the test inside the loop, "Microsoft Outlook" <noreply@outlook.com>
    # tested only "microsoft", and reported a real Microsoft domain as an
    # impersonation of itself.
    words = set(re.findall(r"[a-z0-9]{3,}", display.lower()))
    invoked = sorted(BRAND_STEMS & words)
    if any(sending_org.split(".")[0] in brand_family(brand)
           for brand in invoked):
        return None
    for brand in invoked:
        return emit(
            f"The message presents as '{display}', invoking {brand}, but was "
            f"sent from {domain}, which is not a {brand} domain. The display "
            f"name is free text chosen by the sender, and it is the only "
            f"part most clients show.",
            [
                Evidence("Display name", display),
                Evidence("Brand invoked", brand),
                Evidence("Sending domain", domain),
            ],
        )
    return None


@rule("CONT009", "Malformed HTML structure", Severity.INFO)
def malformed_html(doc, emit):
    html = doc.bodies.get("text/html")
    if not html:
        return None
    lower = html.lower()
    close_body = lower.find("</body>")
    if close_body < 0:
        return None
    trailing = lower[close_body + 7:].replace("</html>", "").strip()
    if len(trailing) < 40:
        return None
    return emit(
        "There is substantive content after the closing </body> tag. "
        "Browsers render it anyway, so the reader never notices, but it "
        "means the HTML was assembled by concatenating template fragments "
        "rather than authored or generated by a mail system. Common in "
        "reused phishing kits.",
        [Evidence("Trailing content", trailing[:200])],
    )
