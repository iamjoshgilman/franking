"""Rules about the Received chain and the addresses around it.

Read Received headers bottom-up: the last one in the file is the first hop
the message took. Forged chains tend to break on ordering, on hosts that do
not exist in the path, or on IPs that appear in headers but nowhere a real
server would have written them.
"""

from __future__ import annotations

from datetime import timezone

from franking.model import Evidence, Severity
from franking.parse import ADDR_RE, classify_ip
from franking.rules import rule
from franking.rules._context import is_autoreply, is_bulk, same_org

# Relays are not perfectly synchronised; only a gap too large for
# NTP drift is evidence of a fabricated header.
SKEW_TOLERANCE_SECONDS = 120


def _describe(seconds: float) -> str:
    seconds = abs(seconds)
    if seconds < 90:
        return f"{seconds:.0f} seconds"
    if seconds < 5400:
        return f"{seconds / 60:.0f} minutes"
    return f"{seconds / 3600:.1f} hours"


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
    stamped = [h for h in doc.hops
               if h.timestamp and h.timestamp.tzinfo is not None]
    findings = []
    for earlier, later in zip(stamped, stamped[1:], strict=False):
        delta = (earlier.timestamp - later.timestamp).total_seconds()
        # Relays are not perfectly synchronised. A few seconds backwards
        # is NTP drift on real infrastructure, not forgery; only a gap
        # too large for clock skew is evidence of anything.
        if delta <= SKEW_TOLERANCE_SECONDS:
            continue
        findings.append(emit(
            f"Hop {later.index} is timestamped "
            f"{later.timestamp.isoformat()}, which is {_describe(delta)} "
            f"*before* hop {earlier.index} at "
            f"{earlier.timestamp.isoformat()}. Mail cannot arrive at a "
            f"later relay before it left an earlier one, and the gap is "
            f"too large to be clock drift, so at least one of these "
            f"headers was fabricated.",
            [
                Evidence(f"Hop {earlier.index} (UTC)",
                         earlier.timestamp.astimezone(timezone.utc).isoformat()),
                Evidence(f"Hop {later.index} (UTC)",
                         later.timestamp.astimezone(timezone.utc).isoformat()),
                Evidence("Backwards by", _describe(delta)),
                Evidence(f"Hop {earlier.index} raw", earlier.raw),
                Evidence(f"Hop {later.index} raw", later.raw),
            ],
        ))
    return findings


@rule(
    "ROUTE004",
    "X-Originating-IP is not in the Received chain",
    Severity.INFO,
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
            f"{header} records {ip}, which appears in no Received hop "
            f"({' → '.join(chain)}). That is normal for webmail -- "
            f"Outlook.com, Yahoo and Roundcube all stamp the browser's "
            f"address, which never connects to the outbound path -- so "
            f"this is a fact about the sender's client rather than "
            f"evidence of forgery. Useful as an indicator; not a finding "
            f"on its own. Where the two disagree, trust the chain.",
            [
                Evidence(header, value),
                Evidence("Received chain", " → ".join(chain)),
            ],
            title_override=f"{header} is not in the Received chain",
        ))
    return findings


@rule("ROUTE005", "Reserved or documentation IP in the path", Severity.INFO)
def reserved_ips_in_chain(doc, emit):
    findings = []
    private: list[tuple[str, str, str]] = []
    seen = set()
    candidates = list(doc.chain_ips)
    if doc.auth.received_spf_ip:
        candidates.append(doc.auth.received_spf_ip)
    for ip in candidates:
        note = classify_ip(ip)
        if not note or ip in seen:
            continue
        seen.add(ip)
        if "documentation" in note or "MCAST" in note:
            detail = (
                f"{ip} belongs to {note}. Addresses from these ranges exist "
                f"only for examples and are never routed, so this is almost "
                f"certainly a synthetic sample rather than captured traffic. "
                f"Do not submit it to a blocklist or threat feed."
            )
        else:
            detail = (
                f"{ip} belongs to {note}. Private addressing in internal "
                f"hops is exactly what real multi-hop corporate mail looks "
                f"like, so this is context rather than a concern -- but the "
                f"address is meaningless outside the network that used it, "
                f"so do not treat it as an indicator."
            )
        private.append((ip, note, detail))

    for ip, note, detail in private:
        findings.append(emit(
            detail,
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
    # A separate bounce address is required practice for mailing lists
    # and universal for bulk senders, which is most inbound mail.
    if is_bulk(doc) or is_autoreply(doc):
        return None
    if same_org(doc.domain_of(rp), doc.domain_of(frm)):
        return None
    return emit(
        f"The envelope sender ({rp}) differs from the displayed From "
        f"({frm}). Bounces and SPF are evaluated against the envelope, while "
        f"the recipient only ever sees the From, which is the gap this split "
        f"is designed to exploit.",
        [Evidence("Return-Path", rp), Evidence("From", frm)],
    )


@rule("ROUTE007", "X-Mailer is inconsistent with the delivery path",
      Severity.INFO)
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
    agents = [a for a in ("postfix", "exim", "sendmail", "qmail", "zimbra",
                          "smtpd", "opensmtpd", "haraka", "mailenable")
              if a in path]
    if not agents:
        return None
    return emit(
        f"X-Mailer claims '{mailer}', but the message was relayed entirely by "
        f"{', '.join(agents)} with no Microsoft infrastructure in the path. "
        f"Mail composed in Outlook normally shows Exchange or Office 365 "
        f"hops. Many organisations do relay Outlook through a Postfix or "
        f"Exim smarthost, so this is weak on its own -- but X-Mailer is "
        f"free text, and it is worth knowing the claim is unsupported by "
        f"the path.",
        [Evidence("X-Mailer", mailer),
         Evidence("Relay software seen", ", ".join(agents))],
    )
