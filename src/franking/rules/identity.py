"""Rules about who the message is pretending to be.

These catch deception that happens *before* the reader forms a judgement:
a domain that renders as another one, characters that hide a file's real
extension, a reply grafted onto a conversation that was already trusted.
The common thread is that the evidence is visible in the raw bytes but
invisible on screen.
"""

from __future__ import annotations

import re

from franking.model import Evidence, Severity
from franking.parse import (
    BIDI_OVERRIDES,
    CONFUSABLE_SCRIPTS,
    IMPERSONATION_TARGETS,
    decode_punycode,
    edit_distance,
    invisible_chars,
    mixed_scripts,
    org_domain,
)
from franking.rules import rule

# Reply prefixes only. A forward legitimately starts a new thread with no
# References header, so fw/fwd/tr must not be treated as a missing
# conversation -- that fires on every honest user report.
REPLY_PREFIX_RE = re.compile(r"^\s*(re|aw|sv|antw)\s*[:\]]", re.I)
MSGID_DOMAIN_RE = re.compile(r"<[^@>]+@([^>]+)>")


def _candidate_domains(doc) -> list[tuple[str, str]]:
    """Every domain the message asks the reader to trust, with its source."""
    out: list[tuple[str, str]] = []
    if domain := doc.domain_of(doc.from_addr):
        out.append((domain, "From address"))
    if domain := doc.domain_of(doc.reply_to):
        out.append((domain, "Reply-To address"))
    for url in doc.urls:
        if url.scheme in ("http", "https") and url.host:
            out.append((url.host, "link"))
    seen = set()
    unique = []
    for domain, source in out:
        if domain not in seen:
            seen.add(domain)
            unique.append((domain, source))
    return unique


@rule("IDN001", "Punycode domain", Severity.HIGH,
      mitre=["T1583.001", "T1656"])
def punycode_domain(doc, emit):
    findings = []
    for domain, source in _candidate_domains(doc):
        decoded = decode_punycode(domain)
        if decoded is None or decoded == domain:
            continue
        scripts = mixed_scripts(decoded)
        confusable = [s for s in scripts if s in CONFUSABLE_SCRIPTS]
        severity = (Severity.CRITICAL
                    if confusable and "LATIN" in scripts else Severity.HIGH)
        note = ""
        if confusable and "LATIN" in scripts:
            note = (f" It mixes Latin with {', '.join(sorted(confusable))} "
                    f"characters in one name, which has no legitimate use "
                    f"and exists only to render as a different domain.")
        findings.append(emit(
            f"The {source} uses the punycode domain {domain}, which a "
            f"browser and most mail clients display as '{decoded}'.{note} "
            f"What the reader sees and what the resolver resolves are "
            f"different strings.",
            [
                Evidence("Encoded", domain),
                Evidence("Displayed as", decoded),
                Evidence("Scripts present", ", ".join(sorted(scripts)) or "n/a"),
                Evidence("Source", source),
            ],
            severity_override=severity,
            title_override=f"Punycode domain: {domain}",
        ))
    return findings


@rule("IDN002", "Domain closely resembles a well-known one", Severity.HIGH,
      mitre=["T1583.001", "T1656"])
def lookalike_domain(doc, emit):
    findings = []
    for domain, source in _candidate_domains(doc):
        org = org_domain(domain)
        if org in IMPERSONATION_TARGETS:
            continue
        stem = org.split(".")[0]
        if len(stem) < 4:
            continue

        # Compare the whole name and each hyphen-separated token. Real
        # lookalikes are as often "paypal-security" as "paypa1" -- the
        # brand is embedded beside a reassuring word rather than misspelt
        # on its own.
        candidates = {stem, *(t for t in stem.split("-") if len(t) >= 4)}
        best = None
        for target in IMPERSONATION_TARGETS:
            target_stem = target.split(".")[0]
            for candidate in candidates:
                if abs(len(candidate) - len(target_stem)) > 2:
                    continue
                distance = edit_distance(candidate, target_stem)
                if distance > 2:
                    continue
                if best is None or distance < best[2]:
                    best = (target, candidate, distance)
        if best is None:
            continue

        target, candidate, distance = best
        if distance == 0:
            detail = (
                f"The {source} domain {domain} contains the brand name "
                f"'{candidate}' but is not {target}. Appending a word like "
                f"'security', 'login' or 'support' to a brand produces a "
                f"domain that reads as official to anyone skimming, and "
                f"it is registrable by anyone."
            )
        else:
            detail = (
                f"The {source} domain {domain} is {distance} character"
                f"{'s' if distance > 1 else ''} away from {target} "
                f"('{candidate}' vs '{target.split('.')[0]}'). At a glance, "
                f"and especially on a phone, the two read the same. "
                f"Registering a near-miss of a trusted brand is the cheapest "
                f"way to borrow its credibility."
            )
        findings.append(emit(
            detail,
            [
                Evidence("Observed", domain),
                Evidence("Resembles", target),
                Evidence("Matched on", candidate),
                Evidence("Edit distance", str(distance)),
                Evidence("Source", source),
            ],
            title_override=f"{domain} resembles {target}",
        ))
    return findings


@rule("IDN003", "Invisible characters in displayed text", Severity.HIGH,
      mitre=["T1036.002", "T1027"])
def invisible_characters(doc, emit):
    """Text that renders differently from how it parses.

    A right-to-left override inside a filename is the classic: the bytes
    say ``.exe`` and the screen says ``.txt``.
    """
    findings = []
    places = [
        ("Subject", doc.subject),
        ("From header", doc.get("From") or ""),
        ("Reply-To header", doc.get("Reply-To") or ""),
    ]
    places += [(f"attachment name: {a.filename}", a.filename)
               for a in doc.attachments]
    places += [(f"file in {a.filename}: {e.name}", e.name)
               for a in doc.attachments for e in a.archive_entries]
    places += [(f"link: {u.url}", u.url) for u in doc.urls]

    for where, text in places:
        found = invisible_chars(text)
        if not found:
            continue
        names = ", ".join(sorted({name for _, name in found}))
        is_bidi = any(ch in BIDI_OVERRIDES for ch, _ in found)
        visible = "".join(c for c in text if c not in dict(found))
        if is_bidi:
            detail = (
                f"{where} contains a bidirectional override ({names}). These "
                f"reverse how the text after them is drawn, so a file named "
                f"'…gnp.exe' can appear as '…exe.png'. The name on screen is "
                f"not the name on disk."
            )
            severity = Severity.CRITICAL
        else:
            detail = (
                f"{where} contains zero-width characters ({names}). They "
                f"occupy no space on screen but break the string for any "
                f"filter matching on exact text, which is usually why they "
                f"are there."
            )
            severity = Severity.MEDIUM
        findings.append(emit(
            detail,
            [
                Evidence("Location", where),
                Evidence("Characters", names),
                Evidence("Codepoints",
                         " ".join(f"U+{ord(c):04X}" for c, _ in found)),
                Evidence("With them removed", visible),
            ],
            severity_override=severity,
            title_override=f"Invisible characters in {where.split(':')[0]}",
        ))
    return findings


@rule("IDN004", "Reply injected into an existing conversation",
      Severity.HIGH, mitre=["T1566.001", "T1534"])
def thread_hijack(doc, emit):
    """Replies arrive pre-trusted, which is the point of stealing one."""
    references = (doc.get("References") or "") + " " + (doc.get("In-Reply-To") or "")
    thread_domains = {
        org_domain(d) for d in MSGID_DOMAIN_RE.findall(references)
    }
    from_org = org_domain(doc.domain_of(doc.from_addr))

    if thread_domains and from_org and from_org not in thread_domains:
        return emit(
            f"This is a reply in a conversation whose earlier messages came "
            f"from {', '.join(sorted(thread_domains))}, but it was sent from "
            f"{from_org}. A stolen mailbox lets an attacker answer a thread "
            f"the recipient already trusts, which removes the usual "
            f"unexpected-message cue entirely.",
            [
                Evidence("From", doc.from_addr),
                Evidence("Thread originated at", ", ".join(sorted(thread_domains))),
                Evidence("References", (doc.get("References") or "")[:200]),
            ],
        )

    if REPLY_PREFIX_RE.match(doc.subject) and not references.strip():
        return emit(
            f"The subject is formatted as a reply ({doc.subject!r}) but the "
            f"message carries no In-Reply-To or References header, so there "
            f"is no conversation it belongs to. The prefix was typed to "
            f"borrow the familiarity of an ongoing exchange.",
            [
                Evidence("Subject", doc.subject),
                Evidence("In-Reply-To", doc.get("In-Reply-To") or "absent"),
                Evidence("References", doc.get("References") or "absent"),
            ],
            severity_override=Severity.MEDIUM,
            title_override="Reply subject with no conversation behind it",
        )
    return None
