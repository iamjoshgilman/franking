"""Rules about the Received chain and the addresses around it.

Read Received headers bottom-up: the last one in the file is the first hop
the message took. Forged chains tend to break on ordering, on hosts that do
not exist in the path, or on IPs that appear in headers but nowhere a real
server would have written them.
"""

from __future__ import annotations

from franking.model import Evidence, Severity
from franking.parse import ADDR_RE, classify_ip
from franking.rules import rule


@rule(
    "ROUTE001",
    "SPF-authorised IP is absent from the Received chain",
    Severity.HIGH,
    mitre=["T1656"],
)
def spf_ip_not_in_chain(doc, emit):
    claimed = doc.auth.received_spf_ip
    if not claimed or not doc.hops:
        return None
    chain = doc.chain_ips
    if not chain or claimed in chain:
        return None
    return emit(
        f"SPF claims {claimed} was the authorised sender, but that address "
        f"appears in no Received hop. The path actually recorded is "
        f"{' → '.join(chain)}. An SPF result is computed from the "
        f"connecting IP, so a pass for an address that never connected cannot "
        f"be genuine.",
        [
            Evidence("Claimed sender IP", claimed),
            Evidence("Received chain", " → ".join(chain)),
        ],
    )


@rule(
    "ROUTE002",
    "Received header names an email address as its source host",
    Severity.MEDIUM,
    mitre=["T1656"],
)
def received_from_is_address(doc, emit):
    findings = []
    for hop in doc.hops:
        if not hop.from_host or not ADDR_RE.fullmatch(hop.from_host):
            continue
        findings.append(emit(
            f"Hop {hop.index} records 'from {hop.from_host}'. The from-clause "
            f"of a Received header holds the HELO/EHLO hostname of the "
            f"connecting server, never a mailbox address. A real MTA could "
            f"not have written this line.",
            [Evidence(f"Received (hop {hop.index})", hop.raw)],
        ))
    return findings


@rule("ROUTE003", "Received timestamps are out of order", Severity.MEDIUM)
def received_timestamps_non_monotonic(doc, emit):
    stamped = [h for h in doc.hops if h.timestamp]
    findings = []
    for earlier, later in zip(stamped, stamped[1:], strict=False):
        if later.timestamp >= earlier.timestamp:
            continue
        findings.append(emit(
            f"Hop {later.index} is timestamped {later.timestamp:%H:%M:%S}, "
            f"before hop {earlier.index} at {earlier.timestamp:%H:%M:%S}. "
            f"Mail cannot arrive at a later relay before it left an earlier "
            f"one, so at least one of these headers was fabricated.",
            [
                Evidence(f"Hop {earlier.index}", earlier.raw),
                Evidence(f"Hop {later.index}", later.raw),
            ],
        ))
    return findings


@rule(
    "ROUTE004",
    "X-Originating-IP disagrees with the Received chain",
    Severity.MEDIUM,
    mitre=["T1656"],
)
def originating_ip_not_in_chain(doc, emit):
    findings = []
    chain = doc.chain_ips
    if not chain:
        return None
    for header in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        value = doc.get(header)
        if not value:
            continue
        ip = value.strip("[] ")
        if ip in chain:
            continue
        findings.append(emit(
            f"{header} advertises {ip}, which appears nowhere in the "
            f"Received chain ({' → '.join(chain)}). X- headers are set "
            f"by the sending client and are not evidence of origin; where "
            f"they disagree with the chain, trust the chain.",
            [
                Evidence(header, value),
                Evidence("Received chain", " → ".join(chain)),
            ],
            title_override=f"{header} disagrees with the Received chain",
        ))
    return findings


@rule("ROUTE005", "Reserved or documentation IP in the path", Severity.INFO)
def reserved_ips_in_chain(doc, emit):
    findings = []
    seen = set()
    candidates = list(doc.chain_ips)
    if doc.auth.received_spf_ip:
        candidates.append(doc.auth.received_spf_ip)
    for ip in candidates:
        note = classify_ip(ip)
        if not note or ip in seen:
            continue
        seen.add(ip)
        findings.append(emit(
            f"{ip} belongs to {note}. Addresses from these ranges are never "
            f"routed on the public internet, so this is almost certainly a "
            f"synthetic sample rather than captured traffic. Do not submit "
            f"it to a blocklist or threat feed.",
            [Evidence("Address", ip), Evidence("Range", note)],
            title_override=f"Reserved address {ip} in the path",
        ))
    return findings


@rule("ROUTE006", "Return-Path does not match From", Severity.MEDIUM,
      mitre=["T1656"])
def return_path_mismatch(doc, emit):
    rp, frm = doc.return_path, doc.from_addr
    if not rp or not frm or rp.lower() == frm.lower():
        return None
    return emit(
        f"The envelope sender ({rp}) differs from the displayed From "
        f"({frm}). Bounces and SPF are evaluated against the envelope, while "
        f"the recipient only ever sees the From, which is the gap this split "
        f"is designed to exploit.",
        [Evidence("Return-Path", rp), Evidence("From", frm)],
    )


@rule("ROUTE007", "X-Mailer is inconsistent with the delivery path",
      Severity.LOW)
def mailer_inconsistent_with_path(doc, emit):
    mailer = doc.get("X-Mailer") or doc.get("User-Agent")
    if not mailer or not doc.hops:
        return None
    claims_outlook = "outlook" in mailer.lower()
    path = " ".join(h.raw.lower() for h in doc.hops)
    if not claims_outlook:
        return None
    if "outlook" in path or "microsoft" in path or "exchange" in path:
        return None
    agents = [a for a in ("postfix", "exim", "sendmail", "qmail", "zimbra")
              if a in path]
    if not agents:
        return None
    return emit(
        f"X-Mailer claims '{mailer}', but the message was relayed entirely by "
        f"{', '.join(agents)} with no Microsoft infrastructure in the path. "
        f"Mail composed in Outlook normally shows Exchange or Office 365 "
        f"hops. The header is cheap to set and was probably chosen to make "
        f"the message look routine.",
        [Evidence("X-Mailer", mailer),
         Evidence("Relay software seen", ", ".join(agents))],
    )
