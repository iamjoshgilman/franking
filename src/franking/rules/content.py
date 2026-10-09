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

# A bare domain appearing inside free text, e.g. in a display name.
DOMAIN_IN_TEXT_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|co|io|uk|de|fr|us|ca|au|example)\b",
    re.I,
)

URGENCY_TERMS = (
    "urgent", "immediately", "final notice", "overdue", "suspend",
    "suspension", "terminated", "expire", "expires", "within 24 hours",
    "act now", "last warning", "failure to", "penalt", "legal action",
    "account will be", "verify your", "confirm your identity",
)

# 555-0100 through 555-0199 are reserved for fiction (NANP / ATIS-0300115).
FICTIONAL_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?555[-.\s]?01\d{2}\b")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}


@rule("CONT001", "Reply-To points to a different address than From",
      Severity.HIGH, mitre=["T1566", "T1656"])
def reply_to_divergence(doc, emit):
    reply, frm = doc.reply_to, doc.from_addr
    if not reply or not frm or reply.lower() == frm.lower():
        return None
    same_domain = doc.domain_of(reply) == doc.domain_of(frm)
    severity = Severity.MEDIUM if same_domain else Severity.HIGH
    where = (
        "a different mailbox on the same domain"
        if same_domain else
        f"an unrelated domain ({doc.domain_of(reply)})"
    )
    return emit(
        f"Replies will go to {reply}, not {frm} -- {where}. Recipients reply "
        f"without re-reading the address, so this quietly moves the "
        f"conversation to a mailbox the sender controls. It is the standard "
        f"setup for payment-redirection fraud.",
        [Evidence("From", frm), Evidence("Reply-To", reply)],
        severity_override=severity,
    )


@rule("CONT002", "Body identifier does not match the identifier in the link",
      Severity.HIGH, mitre=["T1566.002"])
def identifier_mismatch(doc, emit):
    text = doc.body_text
    body_ids = doc.identifiers(text)
    if not body_ids:
        return None

    findings = []
    for url in doc.urls:
        if url.scheme not in ("http", "https"):
            continue
        for full, prefix, digits in doc.identifiers(url.url.upper()):
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
        looks_like_url = anchor.startswith(("http://", "https://", "www.")) or (
            "." in anchor and " " not in anchor and "@" not in anchor
        )
        if not looks_like_url:
            continue
        anchor_host = (
            anchor.replace("https://", "").replace("http://", "")
            .split("/")[0].lower()
        )
        if not anchor_host or anchor_host == url.host:
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


@rule("CONT006", "Message carries both a link and an attachment lure",
      Severity.MEDIUM, mitre=["T1566.001", "T1566.002"])
def dual_delivery_path(doc, emit):
    web_urls = [u for u in doc.urls if u.scheme in ("http", "https")]
    if not web_urls or not doc.attachments:
        return None
    return emit(
        f"The message offers {len(web_urls)} web link(s) and "
        f"{len(doc.attachments)} attachment(s) delivering the same claimed "
        f"content. Two independent paths means blocking one does not stop "
        f"the campaign, and it gives the reader a fallback if the first "
        f"fails. This redundancy is deliberate.",
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
    sending_org = org_domain(domain)

    # A display name carrying an address or domain of its own. Clients
    # show the name and hide the address, so "security@paypal.com" reads
    # as the sender while the mail came from somewhere else entirely.
    claimed = ADDR_RE.search(display) or DOMAIN_IN_TEXT_RE.search(display)
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
    words = set(re.findall(r"[a-z0-9]{3,}", display.lower()))
    for brand in sorted(BRAND_STEMS & words):
        if sending_org.split(".")[0] == brand:
            return None
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
