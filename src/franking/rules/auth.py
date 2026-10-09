"""Rules about SPF, DKIM, DMARC and ARC.

The recurring theme: every one of these headers is just text, and a sender
can type any text they like. A rule here is usually checking that a claimed
result is *internally consistent* with the rest of the message, because that
is the part a forger has to get right and usually does not.
"""

from __future__ import annotations

import re

from franking.model import Evidence, Severity
from franking.parse import org_domain
from franking.rules import rule
from franking.rules._context import AUTHSERV_SUBSTITUTES, is_forwarded


@rule(
    "AUTH009",
    "Authentication passed for a domain that is not the From domain",
    Severity.HIGH,
    mitre=["T1656"],
)
def authentication_not_aligned(doc, emit):
    """The gap SPF and DKIM leave open on their own.

    Each authenticates *a* domain, not necessarily the domain the reader
    sees. DMARC exists precisely because a pass means nothing until the
    authenticated identity aligns with the visible From.
    """
    from_domain = doc.domain_of(doc.from_addr)
    if not from_domain:
        return None
    # A forwarder rewrites the envelope sender, so SPF authenticating a
    # different domain is the expected outcome of forwarding rather than
    # evidence of anything. ARC exists to carry the original result
    # across that boundary.
    if is_forwarded(doc):
        return None
    # DMARC evaluates alignment itself; if the receiver says it passed,
    # contradicting it on the same evidence is noise.
    if doc.auth.dmarc == "pass":
        return None
    from_org = org_domain(from_domain)

    checks = (
        ("SPF", doc.auth.spf, doc.auth.spf_domain, "envelope sender"),
        ("DKIM", doc.auth.dkim, doc.auth.dkim_domain, "signing domain"),
    )
    passed = [(name, dom, what) for name, result, dom, what in checks
              if result == "pass" and dom]
    if not passed:
        return None
    if any(org_domain(dom) == from_org for _, dom, _ in passed):
        return None

    summary = "; ".join(f"{name} passed for {dom} ({what})"
                        for name, dom, what in passed)

    if any(name == "DKIM" for name, _, _ in passed):
        # A DKIM signature survives relaying intact, so unlike SPF this
        # cannot be explained by forwarding: somebody other than the
        # apparent sender signed the message.
        detail = (
            f"{summary} -- but the message displays as being from "
            f"{from_domain}. DKIM signatures survive relaying, so unlike "
            f"SPF this is not explained by forwarding: the message was "
            f"signed by a domain other than the one it claims to come "
            f"from. This is the gap DMARC alignment closes, and it is how "
            f"mail from a compromised bulk sender or an attacker's own "
            f"domain reaches an inbox showing green authentication."
        )
        severity = Severity.HIGH
    elif doc.auth.dkim in (None, "none"):
        # SPF non-alignment with no DKIM at all is the signature of an
        # alias or mailing list: the forwarder rewrote the envelope and
        # the original was never signed. Worth recording, not alarming.
        detail = (
            f"{summary} -- but the message displays as being from "
            f"{from_domain}, and it carries no DKIM signature at all. SPF "
            f"is evaluated against the envelope sender, which every "
            f"forwarder rewrites, so this is the expected result for mail "
            f"relayed through an alias or list rather than evidence of "
            f"forgery. It does mean nothing here ties the message to "
            f"{from_domain}."
        )
        severity = Severity.INFO
    else:
        detail = (
            f"{summary} -- but the message displays as being from "
            f"{from_domain}. A pass only proves the sender controls the "
            f"domain it was checked against, and that is not the domain "
            f"the reader sees. Forwarding can produce this for SPF alone, "
            f"so weigh it against the rest of the path."
        )
        severity = Severity.MEDIUM

    return emit(
        detail,
        [
            Evidence("From domain", from_domain),
            *[Evidence(f"{name} authenticated", dom)
              for name, dom, _ in passed],
            Evidence("DKIM result", doc.auth.dkim or "absent"),
            Evidence("DMARC result", doc.auth.dmarc or "absent"),
            Evidence("Authentication-Results", doc.auth.raw or ""),
        ],
        severity_override=severity,
    )


@rule(
    "AUTH001",
    "dkim=pass claimed but no DKIM-Signature header",
    Severity.CRITICAL,
    mitre=["T1656"],
)
def dkim_pass_without_signature(doc, emit):
    if doc.auth.dkim != "pass" or doc.auth.dkim_signature_present:
        return None
    return emit(
        "Authentication-Results reports a DKIM pass, but the message carries "
        "no DKIM-Signature header. A verifier cannot pass what is not there, "
        "so this result was written by the sender, not measured by a "
        "receiving server. Treat every other result in that header as "
        "equally untrustworthy.",
        [
            Evidence("Authentication-Results", doc.auth.raw or ""),
            Evidence("DKIM-Signature", "absent from the message"),
        ],
    )


@rule(
    "AUTH002",
    "Authentication-Results has no authserv-id",
    Severity.HIGH,
    mitre=["T1656"],
)
def authres_missing_authserv_id(doc, emit):
    if doc.auth.raw is None or doc.auth.authserv_id:
        return None
    lowered = doc.auth.raw.lower()
    if any(marker in lowered for marker in AUTHSERV_SUBSTITUTES):
        # Exchange Online Protection omits the authserv-id deliberately
        # and identifies itself through compauth= and its inline
        # comments. Calling that forgery accuses a whole mail platform.
        return None
    return emit(
        "A real Authentication-Results header begins with the identity of the "
        "server that performed the checks, for example "
        "'mx.example.com; spf=pass ...'. This one starts straight at the "
        "results, which means no verifying host claimed them. Headers in this "
        "shape are typically pasted in by the sender.",
        [Evidence("Authentication-Results", doc.auth.raw)],
    )


@rule("AUTH003", "ARC-Seal i=1 is not cv=none", Severity.HIGH, mitre=["T1656"])
def arc_first_seal_bad_cv(doc, emit):
    seal = doc.auth.arc_sets.get(1, {})
    cv = seal.get("arc-seal.cv")
    if cv is None or cv.lower() == "none":
        return None
    return emit(
        f"The first ARC set must carry cv=none, because at i=1 there is no "
        f"prior chain to validate. This one claims cv={cv}, which is "
        f"impossible for a first hop and is a strong sign the ARC headers "
        f"were copied from another message or invented.",
        [Evidence("ARC-Seal (i=1)", seal.get("arc-seal.raw", ""))],
    )


@rule(
    "AUTH004",
    "ARC-Message-Signature carries no signature data",
    Severity.HIGH,
    mitre=["T1656"],
)
def arc_signature_without_body(doc, emit):
    findings = []
    for instance, tags in sorted(doc.auth.arc_sets.items()):
        if not any(k.startswith("arc-message-signature.") for k in tags):
            continue
        has_b = "arc-message-signature.b" in tags
        has_bh = "arc-message-signature.bh" in tags
        if has_b and has_bh:
            continue
        missing = ", ".join(
            name for name, present in (("b=", has_b), ("bh=", has_bh))
            if not present
        )
        findings.append(emit(
            f"The ARC-Message-Signature at i={instance} is missing {missing}. "
            f"Without the body hash and the signature itself there is nothing "
            f"to verify, so the header is decorative. Real ARC sets always "
            f"carry both.",
            [Evidence(f"ARC-Message-Signature (i={instance})",
                      tags.get("arc-message-signature.raw", ""))],
        ))
    return findings


@rule("AUTH005", "Incomplete ARC set", Severity.MEDIUM, mitre=["T1656"])
def arc_set_incomplete(doc, emit):
    findings = []
    for instance, tags in sorted(doc.auth.arc_sets.items()):
        present = tags.get("_headers", "")
        missing = [
            name for name in
            ("ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results")
            if name not in present
        ]
        if not missing:
            continue
        findings.append(emit(
            f"ARC set i={instance} is missing {', '.join(missing)}. A valid "
            f"set is all three headers together; a partial set cannot be "
            f"evaluated and suggests the headers were added for appearance.",
            [Evidence(f"ARC headers present (i={instance})", present.strip() or "none")],
        ))
    return findings


@rule(
    "AUTH006",
    "SPF verifier does not appear in the delivery path",
    Severity.MEDIUM,
    mitre=["T1656"],
)
def spf_verifier_not_in_path(doc, emit):
    verifier = doc.auth.received_spf_verifier
    if not verifier or not doc.hops:
        return None
    hosts = " ".join(
        f"{h.from_host or ''} {h.by_host or ''}" for h in doc.hops
    ).lower()
    verifier = verifier.lower()
    # Gateways commonly self-identify with an internal name that cannot
    # appear in the public chain -- Proofpoint writes "pps.local". That
    # is not evidence the message went elsewhere.
    if verifier.endswith((".local", ".internal", ".lan")) or "." not in verifier:
        return None
    root = ".".join(verifier.split(".")[-2:])
    if root and root in hosts:
        return None
    # The verifier's own name may differ from its hostnames; check the
    # bare label too (pphosted.example for Proofpoint).
    if verifier.split(".")[0] in hosts:
        return None
    return emit(
        f"Received-SPF says the check was run by '{verifier}', but no hop in "
        f"the Received chain belongs to that infrastructure. The message was "
        f"never handled by the system it credits with verifying it.",
        [
            Evidence("Received-SPF", doc.get("Received-SPF") or ""),
            Evidence("Hosts in chain", hosts.strip() or "none"),
        ],
    )


@rule(
    "AUTH007",
    "Scan-result header not bound to any scanner",
    Severity.LOW,
    mitre=["T1656"],
)
def unbound_scan_header(doc, emit):
    """A clean verdict that names nothing that could have produced it.

    The earlier version matched a vocabulary -- pass/clean/ok/no/safe --
    which got this exactly backwards in both directions. It stayed silent
    on "X-AntiSpam: SCANNED - APPROVED", the self-asserted claim the rule
    exists for, and it fired on SpamAssassin's genuine
    "X-Spam-Status: No, score=-2.6 ... version=3.4.6" because that
    verdict begins with the word "No".

    What distinguishes a real header is not its wording but that it is
    *bound* to something: a score, an engine version, a rule list, a
    host. A bare adjective is an assertion by whoever typed it.
    """
    findings = []
    for header in ("X-AntiSpam", "X-Spam-Status", "X-Spam-Flag",
                   "X-Virus-Scanned", "X-Antivirus", "X-Spam-Checker",
                   "X-Scanned-By", "X-Virus-Status"):
        value = doc.get(header)
        if not value:
            continue
        bound = any((
            re.search(r"score\s*=|_?score|points", value, re.I),
            re.search(r"version\s*[=:]|\bv?\d+\.\d+", value, re.I),
            re.search(r"tests\s*=|rules?\s*=", value, re.I),
            re.search(r"\bby\b.*\.\w{2,}", value, re.I),
            re.search(r"[\w.-]+\.[a-z]{2,}", value, re.I),
        ))
        if bound:
            continue
        findings.append(emit(
            f"'{header}: {value}' states a result but names nothing that "
            f"could have produced it -- no score, no engine version, no "
            f"rule list, no host. Real scanners identify themselves and "
            f"show their working, because the header is written for a "
            f"later hop to read. An unbound verdict is just a sentence the "
            f"sender chose to include.",
            [
                Evidence(header, value),
                Evidence("Binding to a scanner", "none found"),
            ],
            title_override=f"Unbound scan claim in {header}",
        ))
    return findings


@rule("AUTH008", "No authentication results present", Severity.INFO)
def no_auth_results(doc, emit):
    if doc.auth.raw or doc.get("Received-SPF"):
        return None
    return emit(
        "The message carries neither Authentication-Results nor "
        "Received-SPF, so nothing recorded a verification of the sender. "
        "Note this is a property of the capture as much as the message: a "
        "file exported from a Sent folder, a draft, or a message saved "
        "before delivery will never have them.",
        [Evidence("Authentication headers", "none present")],
    )


@rule(
    "AUTH010",
    "DKIM-Signature is not a usable signature",
    Severity.HIGH,
    mitre=["T1656"],
)
def dkim_signature_malformed(doc, emit):
    """A header that exists but cannot be verified.

    AUTH001 only asks whether a DKIM-Signature header is present, so
    writing the literal text "DKIM-Signature: not-really-a-signature"
    silences the rule set's only CRITICAL authentication finding. A
    signature needs, at minimum, a body hash and a signature value.
    """
    findings = []
    for index, tags in enumerate(doc.auth.dkim_sigs):
        missing = [t for t in ("b", "bh", "d", "s") if t not in tags]
        if not missing:
            continue
        claimed = (" The message also claims dkim=pass, which no verifier "
                   "could have produced from this."
                   if doc.auth.dkim == "pass" else "")
        findings.append(emit(
            f"The DKIM-Signature header is missing {', '.join(missing)}. "
            f"Without a signing domain (d=), selector (s=), body hash (bh=) "
            f"and signature (b=) there is nothing a verifier can check, so "
            f"the header is decorative.{claimed}",
            [
                Evidence("DKIM-Signature",
                         (doc.get_all("DKIM-Signature") or [""])[index][:200]),
                Evidence("Missing tags", ", ".join(missing)),
                Evidence("Claimed result", doc.auth.dkim or "none"),
            ],
            severity_override=(Severity.CRITICAL if doc.auth.dkim == "pass"
                               else Severity.HIGH),
        ))
    return findings


@rule("AUTH011", "Conflicting Authentication-Results headers",
      Severity.HIGH, mitre=["T1656"])
def conflicting_auth_results(doc, emit):
    """More than one verifier claim, only the topmost of which is real.

    A receiver prepends its own header, so the lower copies were present
    when the message arrived -- which means the sender wrote them.
    """
    if doc.auth.result_header_count < 2:
        return None
    return emit(
        f"The message carries {doc.auth.result_header_count} "
        f"Authentication-Results headers. A verifier prepends its own, so "
        f"only the topmost was added by the receiving system; the rest "
        f"arrived with the message and were therefore written by the "
        f"sender. Mail clients and analysts commonly read whichever they "
        f"encounter first.",
        [
            Evidence("Header used", doc.auth.raw or ""),
            *[Evidence(f"Also present ({i + 2})", v)
              for i, v in enumerate(doc.auth.extra_raw[:3])],
        ],
    )
