"""Build the navigable tree from a parsed message and its findings.

Both the TUI and the text report render this tree, so the two can never
disagree about what the message contains.
"""

from __future__ import annotations

from franking.model import Finding, Node, Severity
from franking.parse import EmailDoc


def _verdict(findings: list[Finding]) -> tuple[str, Severity]:
    if not findings:
        return "No findings", Severity.INFO
    worst = max(f.severity.rank for f in findings)
    counts = {s: sum(1 for f in findings if f.severity is s) for s in Severity}
    if worst >= Severity.CRITICAL.rank:
        label = "Malicious -- active payload present"
        sev = Severity.CRITICAL
    elif worst >= Severity.HIGH.rank:
        label = "Phishing -- high confidence"
        sev = Severity.HIGH
    elif worst >= Severity.MEDIUM.rank:
        label = "Suspicious -- warrants review"
        sev = Severity.MEDIUM
    else:
        label = "Low risk"
        sev = Severity.LOW
    detail = ", ".join(
        f"{counts[s]} {s.value}" for s in Severity if counts[s]
    )
    return f"{label}  ({detail})", sev


def _summary_section(doc: EmailDoc, findings: list[Finding]) -> Node:
    label, sev = _verdict(findings)
    node = Node("Summary", severity=sev, badge=str(len(findings)))
    node.add(
        Node("Verdict", label, severity=sev,
             note="Derived from the highest-severity finding. See the "
                  "Findings section for the reasoning behind each one."),
        Node("Subject", doc.subject, ioc_type="subject"),
        Node("From", doc.from_addr, ioc_type="email",
             note=f"Display name: {doc.from_display or '(none)'}"),
        Node("To", doc.to_addr, ioc_type="email"),
        Node("Reply-To", doc.reply_to or "(not set)",
             ioc_type="email" if doc.reply_to else None,
             note="Where replies actually go. Compare against From."),
        Node("Date", doc.get("Date") or "(not set)"),
        Node("Originating IP", doc.originating_ip or "(unknown)",
             ioc_type="ip",
             note="Taken from X-Originating-IP / X-Sender-IP where present, "
                  "falling back to the Received-SPF address. These are "
                  "sender-controlled; the Received chain is the real record."),
        Node("Attachments", str(len(doc.attachments))),
        Node("Links", str(len([u for u in doc.urls if u.scheme.startswith("http")]))),
    )
    return node


def _auth_section(doc: EmailDoc) -> Node:
    auth = doc.auth
    node = Node("Authentication")

    def verdict_sev(result: str | None, trustworthy: bool) -> Severity | None:
        if result is None:
            return None
        if not trustworthy:
            return Severity.HIGH
        return Severity.INFO if result == "pass" else Severity.MEDIUM

    dkim_trustworthy = auth.dkim_signature_present
    node.add(
        Node(
            "SPF",
            auth.received_spf_result or auth.spf or "(none)",
            severity=verdict_sev(auth.received_spf_result or auth.spf, False),
            note="An SPF result is only meaningful if the IP it was computed "
                 "against actually appears in the delivery path. Check "
                 "Routing before trusting it.",
        ).add(
            Node("Received-SPF", doc.get("Received-SPF") or "(none)"),
            Node("Authorised IP", auth.received_spf_ip or "(none)", ioc_type="ip"),
            Node("Verifying host", auth.received_spf_verifier or "(none)"),
        ),
        Node(
            "DKIM",
            (auth.dkim or "(none)") + ("" if dkim_trustworthy else "  [NO SIGNATURE]"),
            severity=verdict_sev(auth.dkim, dkim_trustworthy),
            note="A DKIM result without a DKIM-Signature header in the "
                 "message is impossible. The signature is what gets verified; "
                 "no signature means nothing was verified.",
        ).add(
            Node("DKIM-Signature header",
                 "present" if dkim_trustworthy else "ABSENT",
                 severity=None if dkim_trustworthy else Severity.CRITICAL),
            Node("Claimed result", auth.dkim or "(none)"),
        ),
        Node(
            "DMARC",
            auth.dmarc or "(none)",
            severity=verdict_sev(auth.dmarc, dkim_trustworthy),
            note="DMARC is built on SPF and DKIM. If either input is forged, "
                 "the DMARC result inherits the forgery.",
        ),
        Node("Authentication-Results", auth.raw or "(none)",
             note="A genuine header opens with the verifying host's name "
                  "(the authserv-id) before the first semicolon.").add(
            Node("authserv-id", auth.authserv_id or "MISSING",
                 severity=None if auth.authserv_id else Severity.HIGH),
        ),
    )

    arc = Node("ARC", f"{len(auth.arc_sets)} set(s)" if auth.arc_sets else "(none)")
    for instance, tags in sorted(auth.arc_sets.items()):
        cv = tags.get("arc-seal.cv", "(none)")
        bad_cv = instance == 1 and cv.lower() != "none"
        entry = Node(
            f"i={instance}", f"cv={cv}",
            severity=Severity.HIGH if bad_cv else None,
            note="The first set in a chain must use cv=none; there is no "
                 "earlier chain for it to validate."
                 if bad_cv else None,
        )
        entry.add(Node("Headers present", tags.get("_headers", "").strip() or "none"))
        for key in sorted(k for k in tags if not k.startswith("_")):
            entry.add(Node(key, tags[key]))
        arc.add(entry)
    node.add(arc)
    return node


def _routing_section(doc: EmailDoc) -> Node:
    node = Node("Routing", badge=str(len(doc.hops)))
    node.add(Node(
        "Path", " -> ".join(doc.chain_ips) or "(no IPs recorded)",
        note="Transit order, oldest first. In the raw file these headers "
             "appear in the opposite order: the topmost Received is the last "
             "hop before delivery.",
    ))
    for hop in doc.hops:
        entry = Node(
            f"Hop {hop.index}", hop.summary,
            note="Hop 0 is the earliest recorded hop -- the bottom Received "
                 "header in the file." if hop.index == 0 else None,
        )
        entry.add(
            Node("From host", hop.from_host or "(none)"),
            Node("From IP", hop.from_ip or "(none)", ioc_type="ip"),
            Node("Received by", hop.by_host or "(none)", ioc_type="host"),
            Node("Protocol", hop.protocol or "(none)"),
            Node("Queue ID", hop.ident or "(none)"),
            Node("Timestamp", str(hop.timestamp) if hop.timestamp else "(none)"),
            Node("Raw", hop.raw),
        )
        node.add(entry)
    return node


def _originator_section(doc: EmailDoc) -> Node:
    node = Node("Originator")
    fields = [
        ("From", doc.get("From"), "email"),
        ("Sender address", doc.from_addr, "email"),
        ("Display name", doc.from_display or "(none)", None),
        ("Reply-To", doc.reply_to or "(not set)", "email"),
        ("Return-Path", doc.return_path or "(not set)", "email"),
        ("X-Envelope-From", doc.get("X-Envelope-From"), "email"),
        ("X-Originating-IP", doc.get("X-Originating-IP"), "ip"),
        ("X-Sender-IP", doc.get("X-Sender-IP"), "ip"),
        ("X-Mailer", doc.get("X-Mailer"), None),
        ("X-Organization", doc.get("X-Organization"), "org"),
        ("Message-ID", doc.get("Message-ID"), "msgid"),
        ("X-Priority", doc.get("X-Priority"), None),
        ("List-Unsubscribe", doc.get("List-Unsubscribe"), None),
    ]
    for label, value, ioc in fields:
        if value:
            node.add(Node(label, value, ioc_type=ioc))
    return node


def _urls_section(doc: EmailDoc) -> Node:
    web = [u for u in doc.urls if u.scheme in ("http", "https")]
    node = Node("URLs", badge=str(len(web)) if web else None)
    for url in doc.urls:
        entry = Node(url.host or url.url, url.url, ioc_type="url")
        entry.add(
            Node("Full URL", url.url, ioc_type="url"),
            Node("Scheme", url.scheme),
            Node("Host", url.host, ioc_type="host"),
            Node("Registrable domain", url.registrable, ioc_type="domain",
                 note="Best-effort eTLD+1 without a public suffix list. "
                      "Verify multi-label TLDs by hand."),
            Node("Path", url.path or "/"),
            Node("Link text", url.anchor_text or "(none)",
                 note="What the reader sees. Compare against the host."),
        )
        node.add(entry)
    return node


def _attachments_section(doc: EmailDoc) -> Node:
    node = Node("Attachments", badge=str(len(doc.attachments)) or None)
    for att in doc.attachments:
        risky = any(e.final_ext for e in att.archive_entries)
        entry = Node(att.filename, att.filename, ioc_type="filename",
                     severity=Severity.HIGH if risky else None)
        entry.add(
            Node("Filename", att.filename, ioc_type="filename"),
            Node("Content-Type", att.content_type),
            Node("Size", f"{att.size} bytes"),
            Node("MD5", att.md5, ioc_type="hash"),
            Node("SHA-1", att.sha1, ioc_type="hash"),
            Node("SHA-256", att.sha256, ioc_type="hash",
                 note="Hash of the decoded attachment bytes, which is what "
                      "threat intel platforms index."),
        )
        if att.archive_entries:
            contents = Node("Contents", f"{len(att.archive_entries)} entry(s)")
            for item in att.archive_entries:
                child = Node(item.name, item.name, ioc_type="filename")
                child.add(
                    Node("Name", item.name, ioc_type="filename"),
                    Node("Extension chain",
                         " -> ".join("." + e for e in item.extensions) or "(none)"),
                    Node("Compressed size", f"{item.compressed_size} bytes"),
                    Node("Uncompressed size", f"{item.uncompressed_size} bytes"),
                    Node("CRC-32", f"{item.crc32:08x}"),
                )
                contents.add(child)
            entry.add(contents)
        if att.archive_truncated:
            entry.add(Node(
                "Archive state", "truncated",
                note="Read from local file headers because the central "
                     "directory is missing or the data is cut short. "
                     "Filenames survive; the payload does not.",
            ))
        node.add(entry)
    return node


def _body_section(doc: EmailDoc) -> Node:
    node = Node("Body", badge=str(len(doc.bodies)) if doc.bodies else None)
    for ctype, content in doc.bodies.items():
        node.add(Node(ctype, content.strip()))
    if "text/html" in doc.bodies:
        node.add(Node("rendered text", doc.body_text.strip(),
                      note="HTML tags stripped -- roughly what the reader sees."))
    return node


def _headers_section(doc: EmailDoc) -> Node:
    node = Node("Headers", badge=str(len(doc.headers)))
    for name, value in doc.headers:
        node.add(Node(name, value))
    return node


def _findings_section(findings: list[Finding]) -> Node:
    node = Node(
        "Findings",
        badge=str(len(findings)),
        severity=max((f.severity for f in findings),
                     key=lambda s: s.rank, default=None),
    )
    for finding in findings:
        entry = Node(
            finding.title, finding.title,
            note=finding.detail,
            severity=finding.severity,
        )
        entry.add(
            Node("Rule", finding.id),
            Node("Severity", finding.severity.value),
            Node("Explanation", finding.detail),
        )
        for ev in finding.evidence:
            entry.add(Node(ev.label, ev.value))
        if finding.mitre:
            entry.add(Node("MITRE ATT&CK", ", ".join(finding.mitre),
                           ioc_type="mitre"))
        node.add(entry)
    return node


def _iocs_section(doc: EmailDoc, findings: list[Finding]) -> Node:
    """A flat, copy-ready list of every indicator worth extracting."""
    node = Node("IOCs")
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, note: str | None = None) -> None:
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        node.add(Node(kind, value, note=note, ioc_type=kind.lower()))

    add("Sender", doc.from_addr)
    add("Reply-To", doc.reply_to)
    add("Return-Path", doc.return_path)
    add("Originating IP", doc.originating_ip)
    for ip in doc.chain_ips:
        add("Relay IP", ip)
    for url in doc.urls:
        if url.scheme in ("http", "https"):
            add("URL", url.url)
            add("Domain", url.host)
    for att in doc.attachments:
        add("Attachment", att.filename)
        add("SHA-256", att.sha256)
        for item in att.archive_entries:
            add("Archived file", item.name)
    techniques = sorted({t for f in findings for t in f.mitre})
    if techniques:
        add("MITRE techniques", ", ".join(techniques))
    return node


def build_tree(doc: EmailDoc, findings: list[Finding]) -> Node:
    """Assemble the full navigable tree."""
    root = Node(doc.path.name if doc.path else "message")
    root.add(
        _summary_section(doc, findings),
        _findings_section(findings),
        _auth_section(doc),
        _routing_section(doc),
        _originator_section(doc),
        _urls_section(doc),
        _attachments_section(doc),
        _body_section(doc),
        _headers_section(doc),
        _iocs_section(doc, findings),
    )
    return root
