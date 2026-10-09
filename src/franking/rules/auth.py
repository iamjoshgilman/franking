"""Rules about SPF, DKIM, DMARC and ARC.

The recurring theme: every one of these headers is just text, and a sender
can type any text they like. A rule here is usually checking that a claimed
result is *internally consistent* with the rest of the message, because that
is the part a forger has to get right and usually does not.
"""

from __future__ import annotations

from franking.model import Evidence, Severity
from franking.parse import org_domain
from franking.rules import rule


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
    return emit(
        f"{summary} -- but the message displays as being from "
        f"{from_domain}. A pass only proves the sender controls the domain "
        f"it was checked against, and that is not the domain the reader "
        f"sees. This is the gap DMARC alignment closes, and it is how mail "
        f"from a compromised bulk sender or an attacker's own domain lands "
        f"in an inbox showing green authentication results.",
        [
            Evidence("From domain", from_domain),
            *[Evidence(f"{name} authenticated", dom)
              for name, dom, _ in passed],
            Evidence("Authentication-Results", doc.auth.raw or ""),
        ],
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
        [Evidence("ARC-Seal", doc.get("ARC-Seal") or "")],
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
                      doc.get("ARC-Message-Signature") or "")],
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
    root = ".".join(verifier.lower().split(".")[-2:])
    if root and root in hosts:
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
    "Self-asserted anti-spam header",
    Severity.LOW,
    mitre=["T1656"],
)
def fake_antispam_header(doc, emit):
    findings = []
    for header in ("X-AntiSpam", "X-Spam-Status", "X-Virus-Scanned",
                   "X-Antivirus", "X-Spam-Checker"):
        value = doc.get(header)
        if value is None:
            continue
        if not any(word in value.lower()
                   for word in ("pass", "clean", "ok", "no", "safe")):
            continue
        findings.append(emit(
            f"'{header}: {value}' asserts a clean scan, but the header is not "
            f"bound to any scanning engine or receiving host. Anyone can add "
            f"it. Gateways that really scan mail identify themselves and "
            f"usually include a score or engine version.",
            [Evidence(header, value)],
            title_override=f"Self-asserted {header} header",
        ))
    return findings


@rule("AUTH008", "No authentication results at all", Severity.MEDIUM)
def no_auth_results(doc, emit):
    if doc.auth.raw or doc.get("Received-SPF"):
        return None
    return emit(
        "The message carries neither Authentication-Results nor Received-SPF. "
        "Nothing verified the sender, so the From address is unsubstantiated.",
        [Evidence("Authentication headers", "none present")],
    )
