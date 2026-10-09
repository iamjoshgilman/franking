"""Headless output: a readable terminal report and machine-readable JSON."""

from __future__ import annotations

import json
import shutil
import textwrap

from franking.model import Finding, Node, Severity
from franking.parse import EmailDoc
from franking.view import build_tree

ANSI = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _width() -> int:
    return min(shutil.get_terminal_size((100, 24)).columns, 100)


def _paint(text: str, code: str, colour: bool) -> str:
    return f"{code}{text}{RESET}" if colour else text


def findings_report(
    doc: EmailDoc,
    findings: list[Finding],
    colour: bool = True,
    show_evidence: bool = True,
) -> str:
    width = _width()
    out: list[str] = []
    name = doc.path.name if doc.path else "message"

    out.append(_paint(f"{name}", BOLD, colour))
    out.append(_paint(f"  {doc.subject}", DIM, colour))
    out.append(_paint(f"  {doc.from_addr} -> {doc.to_addr}", DIM, colour))
    out.append("")

    if not findings:
        out.append("No findings.")
        return "\n".join(out)

    counts = {s: sum(1 for f in findings if f.severity is s) for s in Severity}
    tally = "  ".join(
        _paint(f"{counts[s]} {s.value}", ANSI[s], colour)
        for s in Severity if counts[s]
    )
    out.append(f"{_paint('FINDINGS', BOLD, colour)}  ({len(findings)})   {tally}")
    out.append("")

    for finding in findings:
        colour_code = ANSI[finding.severity]
        header = (
            f"{_paint(finding.severity.glyph, colour_code, colour)} "
            f"{_paint(finding.severity.value.upper().ljust(8), colour_code, colour)} "
            f"{_paint(finding.id, DIM, colour)}  {BOLD if colour else ''}"
            f"{finding.title}{RESET if colour else ''}"
        )
        out.append(header)
        for line in textwrap.wrap(finding.detail, width - 13):
            out.append(f"            {line}")
        if show_evidence:
            for ev in finding.evidence:
                value = ev.value if len(ev.value) <= width - 28 else ev.value[:width - 31] + "..."
                out.append(_paint(f"            {ev.label}: {value}", DIM, colour))
        if finding.mitre:
            out.append(_paint(f"            ATT&CK: {', '.join(finding.mitre)}",
                              DIM, colour))
        out.append("")

    techniques = sorted({t for f in findings for t in f.mitre})
    if techniques:
        out.append(f"{_paint('ATT&CK techniques', BOLD, colour)}: {', '.join(techniques)}")
    return "\n".join(out)


def iocs_report(doc: EmailDoc, findings: list[Finding]) -> str:
    tree = build_tree(doc, findings)
    section = next((c for c in tree.children if c.label == "IOCs"), None)
    if section is None:
        return ""
    width = max((len(c.label) for c in section.children), default=0)
    return "\n".join(
        f"{c.label.ljust(width)}  {c.value}" for c in section.children
    )


def tree_report(node: Node, depth: int = 0, max_depth: int = 2) -> str:
    """Plain indented dump of the tree, for piping into grep."""
    lines: list[str] = []
    pad = "  " * depth
    value = f"  {node.value}" if node.value and node.is_leaf else ""
    badge = f" [{node.badge}]" if node.badge else ""
    lines.append(f"{pad}{node.label}{badge}{value}")
    if depth < max_depth:
        for child in node.children:
            lines.append(tree_report(child, depth + 1, max_depth))
    return "\n".join(lines)


def json_report(doc: EmailDoc, findings: list[Finding]) -> str:
    payload = {
        "file": str(doc.path) if doc.path else None,
        "subject": doc.subject,
        "from": doc.from_addr,
        "from_display": doc.from_display,
        "to": doc.to_addr,
        "reply_to": doc.reply_to,
        "return_path": doc.return_path,
        "date": doc.get("Date"),
        "message_id": doc.get("Message-ID"),
        "originating_ip": doc.originating_ip,
        "authentication": {
            "authserv_id": doc.auth.authserv_id,
            "spf": doc.auth.spf,
            "dkim": doc.auth.dkim,
            "dmarc": doc.auth.dmarc,
            "dkim_signature_present": doc.auth.dkim_signature_present,
            "received_spf_result": doc.auth.received_spf_result,
            "received_spf_ip": doc.auth.received_spf_ip,
            "received_spf_verifier": doc.auth.received_spf_verifier,
            "arc_sets": doc.auth.arc_sets,
        },
        "hops": [
            {
                "index": h.index,
                "from_host": h.from_host,
                "from_ip": h.from_ip,
                "by_host": h.by_host,
                "protocol": h.protocol,
                "id": h.ident,
                "timestamp": h.timestamp.isoformat() if h.timestamp else None,
            }
            for h in doc.hops
        ],
        "urls": [
            {
                "url": u.url,
                "scheme": u.scheme,
                "host": u.host,
                "path": u.path,
                "anchor_text": u.anchor_text,
            }
            for u in doc.urls
        ],
        "attachments": [
            {
                "filename": a.filename,
                "content_type": a.content_type,
                "size": a.size,
                "md5": a.md5,
                "sha1": a.sha1,
                "sha256": a.sha256,
                "truncated": a.archive_truncated,
                "contents": [
                    {
                        "name": e.name,
                        "compressed_size": e.compressed_size,
                        "uncompressed_size": e.uncompressed_size,
                        "crc32": f"{e.crc32:08x}",
                        "extensions": e.extensions,
                    }
                    for e in a.archive_entries
                ],
            }
            for a in doc.attachments
        ],
        "findings": [f.as_dict() for f in findings],
        "mitre": sorted({t for f in findings for t in f.mitre}),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
