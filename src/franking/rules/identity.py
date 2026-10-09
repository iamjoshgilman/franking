"""Rules about who the message is pretending to be.

These catch deception that happens *before* the reader forms a judgement:
a domain that renders as another one, characters that hide a file's real
extension, a reply grafted onto a conversation that was already trusted.
The common thread is that the evidence is visible in the raw bytes but
invisible on screen.

The hard part is not detection, it is precision. An internationalised
domain is not an attack, a reply from another company is not a hijack,
and a zero-width joiner in an emoji is not evasion. Each rule here has to
separate the deception from the ordinary thing that resembles it.
"""

from __future__ import annotations

import re

from franking.model import Evidence, Severity
from franking.parse import (
    BIDI_OVERRIDES,
    ZERO_WIDTH,
    decode_punycode,
    invisible_chars,
    mixed_scripts,
    org_domain,
)
from franking.rules import rule
from franking.rules._context import (
    brand_family,
    is_bulk,
    resembles_brand,
    significant_labels,
    skeleton,
)

# Reply prefixes only. A forward legitimately starts a new thread with no
# References header, so fw/fwd/tr must not be treated as a missing
# conversation -- that fires on every honest user report.
REPLY_PREFIX_RE = re.compile(r"^\s*(re|aw|sv|antw|rif|r)\s*(\[\d+\])?\s*[:\]]",
                             re.I)
MSGID_DOMAIN_RE = re.compile(r"<[^@>]+@([^>]+)>")

# Scripts whose letters have Latin twins. Mixing one of these with Latin
# inside a single label has no legitimate use.
CONFUSABLE_SCRIPTS = frozenset({"CYRILLIC", "GREEK", "ARMENIAN"})


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


def _display_form(host: str) -> str:
    """What the reader sees: punycode decoded, everything else as-is."""
    return decode_punycode(host) or host


@rule("IDN001", "Domain renders as different text than it resolves to",
      Severity.HIGH, mitre=["T1583.001", "T1656"])
def deceptive_domain_rendering(doc, emit):
    """Homoglyphs, separated from ordinary internationalisation.

    Three different things look alike here and only one is an attack:

    - Two scripts inside a *single label* (``pаypal``). No language
      does this; it exists to render as something else. CRITICAL.
    - One non-Latin label that reduces to a known brand once confusable
      characters are mapped to their Latin twins (``аррӏе`` -> apple).
      CRITICAL.
    - A non-Latin or accented domain that reduces to nothing in
      particular (``кофейня.ru``, ``münchen-reisebüro.de``). That is a
      Russian coffee shop and a German travel agent. INFO at most.

    The earlier version ran the script check across the whole host
    including the TLD, so every internationalised domain under a Latin
    TLD contained "Latin" by construction and was reported CRITICAL.
    """
    findings = []
    seen = set()
    for host, source in _candidate_domains(doc):
        display = _display_form(host)
        labels = significant_labels(display)
        if not labels:
            continue
        key = org_domain(display)
        if key in seen:
            continue

        worst = None
        for label in labels:
            scripts = mixed_scripts(label)
            confusable = scripts & CONFUSABLE_SCRIPTS
            if confusable and "LATIN" in scripts:
                worst = ("mixed", label, scripts, None)
                break
            if confusable:
                match = resembles_brand(label)
                if match:
                    worst = ("brand", label, scripts, match)
                    break
                worst = worst or ("intl", label, scripts, None)
            elif display != host:
                worst = worst or ("intl", label, scripts, None)

        if worst is None:
            continue
        seen.add(key)
        kind, label, scripts, match = worst
        script_list = ", ".join(sorted(scripts)) or "n/a"

        if kind == "mixed":
            detail = (
                f"The {source} domain renders as '{display}'. The label "
                f"'{label}' mixes {script_list} in a single name, which no "
                f"writing system does. The only purpose of combining scripts "
                f"inside one word is to make it look like a different word."
            )
            severity = Severity.CRITICAL
        elif kind == "brand":
            target, distance = match
            detail = (
                f"The {source} domain renders as '{display}'. Mapping its "
                f"confusable characters to their Latin twins reduces "
                f"'{label}' to '{skeleton(label)}', which is "
                f"{'identical to' if distance == 0 else 'one edit from'} "
                f"{target}. The name is written in {script_list} so that it "
                f"resolves somewhere else entirely while reading as a brand "
                f"the recipient trusts."
            )
            severity = Severity.CRITICAL
        else:
            detail = (
                f"The {source} uses the internationalised domain '{display}'"
                + (f" (encoded as {host})" if display != host else "")
                + f". Its characters are {script_list}. This is normal for "
                f"an organisation that does not write its name in ASCII, and "
                f"is only worth noting because the encoded and displayed "
                f"forms differ. It does not resemble a known brand."
            )
            severity = Severity.INFO

        findings.append(emit(
            detail,
            [
                Evidence("As written", host),
                Evidence("As displayed", display),
                Evidence("Label examined", label),
                Evidence("Scripts in that label", script_list),
                Evidence("Source", source),
            ],
            severity_override=severity,
            title_override=(
                f"Internationalised domain: {display}" if kind == "intl"
                else f"Homoglyph domain: {display}"
            ),
        ))
    return findings


@rule("IDN002", "Domain closely resembles a well-known one", Severity.HIGH,
      mitre=["T1583.001", "T1656"])
def lookalike_domain(doc, emit):
    """ASCII near-misses of a trusted name.

    Deliberately narrow. Reporting every domain that shares a stem with a
    brand flags that brand's own second domains -- atlassian.net,
    github.io, docusign.net are all real -- and a HIGH finding on genuine
    Jira mail teaches an analyst to ignore the rule entirely.
    """
    findings = []
    reported = set()
    for host, source in _candidate_domains(doc):
        # Non-ASCII and punycode hosts are IDN001's job, and it reports
        # them with the rendering explained. Edit-distancing an A-label's
        # checksum suffix against brand names also produces nonsense like
        # "xn--mnchen-reisebro-zvbm resembles zoom".
        if "xn--" in host.lower() or not host.isascii():
            continue
        org = org_domain(host)
        if org in reported:
            continue
        stem = org.split(".")[0]
        if len(stem) < 4:
            continue

        tokens = {stem, *(t for t in stem.split("-") if len(t) >= 4)}
        best = None
        for token in tokens:
            match = resembles_brand(token, max_distance=2)
            if match is None:
                continue
            target, distance = match
            if best is None or distance < best[2]:
                best = (target, token, distance)
        if best is None:
            continue
        target, token, distance = best
        target_stem = target.split(".")[0]

        # The brand's own infrastructure: same name, different suffix, or
        # a sibling brand. atlassian.net is Atlassian.
        if distance == 0 and stem == target_stem:
            continue
        if brand_family(target_stem) & {stem, token}:
            continue

        reported.add(org)
        if distance == 0:
            detail = (
                f"The {source} domain {host} contains the brand name "
                f"'{token}' as part of a longer name, but its registrable "
                f"domain is {org}, which is not {target}. Pairing a brand "
                f"with a reassuring word reads as official to anyone "
                f"skimming, and the result is registrable by anyone."
            )
        else:
            detail = (
                f"The {source} domain {host} is {distance} character"
                f"{'s' if distance > 1 else ''} away from {target} "
                f"('{token}' against '{target_stem}'). At a glance, and "
                f"especially on a phone, the two read the same."
            )
        findings.append(emit(
            detail,
            [
                Evidence("Observed", host),
                Evidence("Registrable domain", org),
                Evidence("Resembles", target),
                Evidence("Matched on", token),
                Evidence("Edit distance", str(distance)),
                Evidence("Source", source),
            ],
            title_override=f"{org} resembles {target}",
        ))
    return findings


@rule("IDN003", "Invisible characters in displayed text", Severity.HIGH,
      mitre=["T1036.002", "T1027"])
def invisible_characters(doc, emit):
    """Text that renders differently from how it parses.

    A right-to-left override inside a filename is the classic: the bytes
    say ``.exe`` and the screen says ``.txt``. Zero-width characters are
    a much weaker signal -- a joiner is *required* to build an emoji and
    to write Persian, Arabic and Devanagari correctly -- so those are
    only reported where they cannot be doing legitimate work.
    """
    findings = []
    places = [
        ("Subject", doc.subject),
        ("From header", doc.get("From") or ""),
        ("Reply-To header", doc.get("Reply-To") or ""),
        ("To header", doc.get("To") or ""),
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
        bidi = [(c, n) for c, n in found if c in BIDI_OVERRIDES]
        zero = [(c, n) for c, n in found if c in ZERO_WIDTH]

        if bidi:
            names = ", ".join(sorted({n for _, n in bidi}))
            findings.append(emit(
                f"{where} contains a bidirectional override ({names}). These "
                f"reverse how the text after them is drawn, so a file named "
                f"'...gnp.exe' appears as '...exe.png'. The name on screen "
                f"is not the name on disk.",
                [
                    Evidence("Location", where),
                    Evidence("Characters", names),
                    Evidence("Codepoints",
                             " ".join(f"U+{ord(c):04X}" for c, _ in bidi)),
                    Evidence("With them removed",
                             "".join(c for c in text
                                     if c not in dict(found))),
                ],
                severity_override=Severity.CRITICAL,
                title_override=f"Bidirectional override in {where.split(':')[0]}",
            ))
            continue

        if zero and _zero_width_is_suspicious(text, zero):
            names = ", ".join(sorted({n for _, n in zero}))
            findings.append(emit(
                f"{where} contains zero-width characters ({names}) among "
                f"ASCII text, where they can serve no typographic purpose. "
                f"They occupy no space on screen but break the string for "
                f"any filter matching on exact text, which is usually why "
                f"they are there.",
                [
                    Evidence("Location", where),
                    Evidence("Characters", names),
                    Evidence("Codepoints",
                             " ".join(f"U+{ord(c):04X}" for c, _ in zero)),
                    Evidence("With them removed",
                             "".join(c for c in text
                                     if c not in dict(found))),
                ],
                severity_override=Severity.MEDIUM,
                title_override=f"Zero-width characters in {where.split(':')[0]}",
            ))
    return findings


def _zero_width_is_suspicious(text: str, found: list[tuple[str, str]]) -> bool:
    """Is a zero-width character doing legitimate typographic work?

    A joiner between two non-ASCII characters is building an emoji or
    writing a script that needs it. A BOM at the start is Windows
    tooling. A joiner sitting between two ASCII letters is hiding
    something.
    """
    for char, _ in found:
        if char == "﻿" and text.startswith(char):
            continue
        index = text.find(char)
        before = text[index - 1] if index > 0 else ""
        after = text[index + 1] if index + 1 < len(text) else ""
        neighbours = before + after
        if neighbours and any(ord(c) > 0x2100 for c in neighbours):
            continue  # emoji or non-Latin script
        return True
    return False


@rule("IDN004", "Reply from a domain impersonating the conversation",
      Severity.HIGH, mitre=["T1566.001", "T1534"])
def thread_hijack(doc, emit):
    """A reply arrives pre-trusted, which is the point of forging one.

    The naive test -- the sender's domain is not one of the thread's --
    is useless: Message-IDs are minted by the *sender's* MTA, so every
    genuine reply from a customer, supplier or Gmail user trips it. It
    is quiet only when you reply to yourself.

    What is actually diagnostic is a reply from a domain that *resembles*
    one already in the thread. That is an attacker who registered a
    near-miss and injected themselves into a conversation the recipient
    was already having, and it has no innocent explanation.
    """
    references = f"{doc.get('References') or ''} {doc.get('In-Reply-To') or ''}"
    thread_domains = {
        org_domain(d) for d in MSGID_DOMAIN_RE.findall(references)
    }
    thread_domains.discard("")
    from_org = org_domain(doc.domain_of(doc.from_addr))

    if thread_domains and from_org and from_org not in thread_domains:
        for thread_org in sorted(thread_domains):
            if _is_near_miss(from_org, thread_org):
                return emit(
                    f"This is a reply in a conversation whose earlier "
                    f"messages came from {thread_org}, but it was sent from "
                    f"{from_org} -- a near-identical domain, not the same "
                    f"one. Someone registered a lookalike and answered into "
                    f"a thread the recipient was already having, which "
                    f"removes the unexpected-message cue entirely.",
                    [
                        Evidence("From", doc.from_addr),
                        Evidence("Thread domain", thread_org),
                        Evidence("Sender domain", from_org),
                        Evidence("References",
                                 (doc.get("References") or "")[:200]),
                    ],
                )

    if (REPLY_PREFIX_RE.match(doc.subject) and not references.strip()
            and not is_bulk(doc)):
        return emit(
            f"The subject is formatted as a reply ({doc.subject!r}) but the "
            f"message carries no In-Reply-To or References header, so there "
            f"is no conversation it belongs to. The prefix was typed to "
            f"borrow the familiarity of an exchange that never happened.",
            [
                Evidence("Subject", doc.subject),
                Evidence("In-Reply-To", doc.get("In-Reply-To") or "absent"),
                Evidence("References", doc.get("References") or "absent"),
            ],
            severity_override=Severity.MEDIUM,
            title_override="Reply subject with no conversation behind it",
        )
    return None


def _is_near_miss(candidate: str, target: str) -> bool:
    """Same organisation name to the eye, different domain in fact."""
    if candidate == target:
        return False
    from franking.parse import edit_distance

    c_stem, t_stem = candidate.split(".")[0], target.split(".")[0]
    if len(t_stem) < 4:
        return False
    if skeleton(c_stem) == skeleton(t_stem):
        return True
    distance = edit_distance(c_stem, t_stem)
    return distance <= 2 and abs(len(c_stem) - len(t_stem)) <= 2
