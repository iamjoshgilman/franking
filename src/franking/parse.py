"""Turn a .eml file into structured facts the rules can reason about.

Nothing in here judges the message -- it only extracts. All the "is this
suspicious" logic lives in :mod:`franking.rules`, so the parser stays
reusable and the rules stay testable.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path

# RFC 5737 / 3849 documentation ranges and RFC 1918 private space. Sample
# messages from training platforms lean on these heavily, and it is worth
# saying so out loud rather than letting someone paste them into a blocklist.
DOC_RANGES = (
    ("192.0.2.", "RFC 5737 TEST-NET-1 (documentation)"),
    ("198.51.100.", "RFC 5737 TEST-NET-2 (documentation)"),
    ("203.0.113.", "RFC 5737 TEST-NET-3 (documentation)"),
    ("233.252.0.", "RFC 5771 MCAST-TEST-NET (documentation)"),
)
PRIVATE_PREFIXES = ("10.", "192.168.", "127.")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ADDR_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# Identifiers like INV-2025-0012, ACC_99381, REF2025-0987.
IDENT_RE = re.compile(r"\b([A-Z]{2,6})[-_ ]?(\d{3,}(?:[-_]\d+)*)\b")

ZIP_LOCAL_HEADER = b"PK\x03\x04"
ZIP_LOCAL_HEADER_LEN = 30

EXECUTABLE_EXTS = {
    "bat", "cmd", "com", "cpl", "exe", "hta", "jar", "js", "jse", "lnk",
    "msc", "msi", "ps1", "pif", "reg", "scr", "vb", "vbe", "vbs", "wsf",
    "wsh", "iso", "img", "chm", "scf", "inf", "application",
}
DOCUMENT_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "htm", "html", "xml", "json",
}
ARCHIVE_TYPES = {"application/zip", "application/x-zip-compressed",
                 "application/x-rar-compressed", "application/x-7z-compressed"}


def classify_ip(ip: str) -> str | None:
    """Return a human note if ``ip`` is from a reserved range, else None."""
    for prefix, label in DOC_RANGES:
        if ip.startswith(prefix):
            return label
    for prefix in PRIVATE_PREFIXES:
        if ip.startswith(prefix):
            return "RFC 1918 private / loopback"
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
        except (IndexError, ValueError):
            return None
        if 16 <= second <= 31:
            return "RFC 1918 private"
    return None


@dataclass
class Hop:
    """One ``Received:`` header, parsed.

    ``index`` is transit order: 0 is the hop closest to the origin, which is
    the *bottom* ``Received`` header in the file.
    """

    index: int
    raw: str
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    protocol: str | None = None
    ident: str | None = None
    timestamp: datetime | None = None

    @property
    def summary(self) -> str:
        src = self.from_ip or self.from_host or "?"
        return f"{src} → {self.by_host or '?'}"


@dataclass
class ArchiveEntry:
    """A file inside an attached archive, read from its local header."""

    name: str
    compressed_size: int
    uncompressed_size: int
    crc32: int
    extensions: list[str] = field(default_factory=list)

    @property
    def final_ext(self) -> str:
        return self.extensions[-1] if self.extensions else ""


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes
    archive_entries: list[ArchiveEntry] = field(default_factory=list)
    archive_truncated: bool = False

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def extensions(self) -> list[str]:
        return _extensions(self.filename)

    @property
    def md5(self) -> str:
        return hashlib.md5(self.data).hexdigest()

    @property
    def sha1(self) -> str:
        return hashlib.sha1(self.data).hexdigest()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def is_archive(self) -> bool:
        return (self.content_type in ARCHIVE_TYPES
                or self.final_ext in {"zip", "rar", "7z"})

    @property
    def final_ext(self) -> str:
        exts = self.extensions
        return exts[-1] if exts else ""


@dataclass
class Url:
    url: str
    anchor_text: str = ""
    scheme: str = ""
    host: str = ""
    path: str = ""

    @property
    def registrable(self) -> str:
        """Best-effort eTLD+1. No PSL dependency, so treat it as a hint."""
        labels = self.host.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else self.host


@dataclass
class AuthResults:
    """Everything the message *claims* about its own authentication."""

    authserv_id: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    raw: str | None = None
    received_spf_result: str | None = None
    received_spf_ip: str | None = None
    received_spf_verifier: str | None = None
    dkim_signature_present: bool = False
    arc_sets: dict[int, dict[str, str]] = field(default_factory=dict)


class _LinkExtractor(HTMLParser):
    """Collect hrefs together with their anchor text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._anchor: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._anchor).strip()))
            self._href = None
            self._anchor = []

    def handle_data(self, data):
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", "".join(self.text_parts))


def _extensions(filename: str) -> list[str]:
    """Return lowercase extension chain, e.g. ``a.pdf.bat`` -> [pdf, bat]."""
    parts = filename.strip().lower().split(".")
    # A leading dot means a hidden file, not an extension.
    return [p for p in parts[1:] if p]


def scan_zip_entries(data: bytes) -> tuple[list[ArchiveEntry], bool]:
    """Read ZIP local file headers directly.

    ``zipfile`` needs an intact central directory, which truncated samples do
    not have. Walking local headers still recovers the filenames, which is
    usually the thing you actually want. Returns (entries, truncated).
    """
    entries: list[ArchiveEntry] = []
    truncated = False
    offset = 0

    while True:
        start = data.find(ZIP_LOCAL_HEADER, offset)
        if start < 0:
            break
        header = data[start:start + ZIP_LOCAL_HEADER_LEN]
        if len(header) < ZIP_LOCAL_HEADER_LEN:
            truncated = True
            break

        crc32, csize, usize = struct.unpack_from("<III", header, 14)
        name_len, extra_len = struct.unpack_from("<HH", header, 26)

        name_start = start + ZIP_LOCAL_HEADER_LEN
        raw_name = data[name_start:name_start + name_len]
        if len(raw_name) < name_len:
            truncated = True
            break
        name = raw_name.decode("utf-8", errors="replace")

        entries.append(ArchiveEntry(
            name=name,
            compressed_size=csize,
            uncompressed_size=usize,
            crc32=crc32,
            extensions=_extensions(name),
        ))

        body_end = name_start + name_len + extra_len + csize
        if body_end > len(data):
            # The header promises more bytes than the file holds.
            truncated = True
            break
        # A zero compressed size with following data means a data descriptor
        # was used; scanning forward for the next signature still works.
        offset = max(body_end, name_start + name_len)

    return entries, truncated


def _parse_tag_list(value: str) -> dict[str, str]:
    """Parse ``k=v; k2=v2`` tag lists used by DKIM/ARC headers."""
    tags: dict[str, str] = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, _, val = chunk.partition("=")
        tags[key.strip().lower()] = val.strip()
    return tags


class EmailDoc:
    """A parsed .eml file."""

    def __init__(self, raw: bytes, path: Path | None = None):
        self.raw = raw
        self.path = path
        self.msg: EmailMessage = email.message_from_bytes(
            raw, policy=email.policy.default
        )
        self.headers: list[tuple[str, str]] = [
            (k, str(v)) for k, v in self.msg.items()
        ]
        self.hops: list[Hop] = self._parse_received()
        self.auth: AuthResults = self._parse_auth()
        self.bodies: dict[str, str] = {}
        self.attachments: list[Attachment] = []
        self.urls: list[Url] = []
        self._parse_parts()

    # -- construction ----------------------------------------------------

    @classmethod
    def from_path(cls, path: str | Path) -> EmailDoc:
        p = Path(path)
        return cls(p.read_bytes(), path=p)

    # -- header access ---------------------------------------------------

    def get(self, name: str) -> str | None:
        value = self.msg.get(name)
        return None if value is None else str(value).strip()

    def get_all(self, name: str) -> list[str]:
        return [str(v).strip() for v in (self.msg.get_all(name) or [])]

    def has_header(self, name: str) -> bool:
        return self.msg.get(name) is not None

    @property
    def subject(self) -> str:
        return self.get("Subject") or ""

    @property
    def from_addr(self) -> str:
        return self._first_addr(self.get("From"))

    @property
    def from_display(self) -> str:
        raw = self.get("From") or ""
        name = raw.split("<")[0].strip().strip('"')
        return name if "<" in raw else ""

    @property
    def reply_to(self) -> str:
        return self._first_addr(self.get("Reply-To"))

    @property
    def return_path(self) -> str:
        return self._first_addr(self.get("Return-Path"))

    @property
    def to_addr(self) -> str:
        return self._first_addr(self.get("To"))

    @property
    def originating_ip(self) -> str | None:
        for header in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
            value = self.get(header)
            if value:
                match = IP_RE.search(value)
                if match:
                    return match.group(0)
        return self.auth.received_spf_ip

    @property
    def chain_ips(self) -> list[str]:
        return [h.from_ip for h in self.hops if h.from_ip]

    @property
    def body_text(self) -> str:
        if "text/plain" in self.bodies:
            return self.bodies["text/plain"]
        if "text/html" in self.bodies:
            extractor = _LinkExtractor()
            extractor.feed(self.bodies["text/html"])
            return extractor.text
        return ""

    @staticmethod
    def _first_addr(value: str | None) -> str:
        if not value:
            return ""
        match = ADDR_RE.search(value)
        return match.group(0) if match else ""

    @staticmethod
    def domain_of(addr: str) -> str:
        return addr.split("@")[-1].lower() if "@" in addr else ""

    # -- parsing ---------------------------------------------------------

    def _parse_received(self) -> list[Hop]:
        raws = self.get_all("Received")
        hops: list[Hop] = []
        # File order is newest-first; transit order is the reverse.
        for index, raw in enumerate(reversed(raws)):
            flat = " ".join(raw.split())
            hop = Hop(index=index, raw=flat)

            if m := re.search(r"\bfrom\s+([^\s;()]+)", flat, re.I):
                hop.from_host = m.group(1)
            if m := re.search(r"\bby\s+([^\s;()]+)", flat, re.I):
                hop.by_host = m.group(1)
            if m := re.search(r"\bwith\s+([A-Za-z0-9/]+)", flat, re.I):
                hop.protocol = m.group(1)
            if m := re.search(r"\bid\s+([^\s;]+)", flat, re.I):
                hop.ident = m.group(1)

            # Prefer a bracketed IP (the real source) over any other match.
            if m := re.search(r"[\[(](" + IP_RE.pattern.strip("\\b") + r")[\])]", flat):
                hop.from_ip = m.group(1)
            elif m := IP_RE.search(flat.split(" by ")[0] if " by " in flat else flat):
                hop.from_ip = m.group(0)

            if ";" in flat:
                try:
                    hop.timestamp = parsedate_to_datetime(flat.rsplit(";", 1)[1].strip())
                except (TypeError, ValueError, IndexError):
                    hop.timestamp = None

            hops.append(hop)
        return hops

    def _parse_auth(self) -> AuthResults:
        auth = AuthResults()
        auth.dkim_signature_present = self.has_header("DKIM-Signature")

        raw = self.get("Authentication-Results")
        if raw:
            auth.raw = " ".join(raw.split())
            first = auth.raw.split(";")[0].strip()
            # A real authserv-id is a bare token before the first ';'.
            if first and "=" not in first:
                auth.authserv_id = first
            for method in ("spf", "dkim", "dmarc"):
                m = re.search(rf"\b{method}=(\w+)", auth.raw, re.I)
                if m:
                    setattr(auth, method, m.group(1).lower())

        spf_raw = self.get("Received-SPF")
        if spf_raw:
            flat = " ".join(spf_raw.split())
            m = re.match(r"\s*(\w+)", flat)
            if m:
                auth.received_spf_result = m.group(1).lower()
            if ip := IP_RE.search(flat):
                auth.received_spf_ip = ip.group(0)
            if v := re.search(r"\(([^\s:]+):", flat):
                auth.received_spf_verifier = v.group(1)

        for header in ("ARC-Seal", "ARC-Message-Signature",
                       "ARC-Authentication-Results"):
            for value in self.get_all(header):
                tags = _parse_tag_list(" ".join(value.split()))
                try:
                    instance = int(tags.get("i", "0"))
                except ValueError:
                    continue
                entry = auth.arc_sets.setdefault(instance, {})
                for key, val in tags.items():
                    entry[f"{header.lower()}.{key}"] = val
                entry.setdefault("_headers", "")
                entry["_headers"] += f"{header} "

        return auth

    def _parse_parts(self) -> None:
        for part in self.msg.walk():
            if part.get_content_maintype() == "multipart":
                continue

            filename = part.get_filename()
            disposition = (part.get_content_disposition() or "").lower()
            ctype = part.get_content_type()

            if filename or disposition == "attachment":
                data = part.get_payload(decode=True) or b""
                att = Attachment(
                    filename=filename or "(unnamed)",
                    content_type=ctype,
                    data=data,
                )
                if att.is_archive and data:
                    att.archive_entries, att.archive_truncated = scan_zip_entries(data)
                self.attachments.append(att)
                continue

            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            self.bodies[ctype] = self.bodies.get(ctype, "") + text

        self.urls = self._extract_urls()

    def _extract_urls(self) -> list[Url]:
        seen: dict[str, Url] = {}

        def add(href: str, anchor: str = "") -> None:
            href = href.strip()
            if not href or href.startswith("#"):
                return
            scheme, _, rest = href.partition(":")
            scheme = scheme.lower()
            if scheme == "mailto":
                host = rest.split("@")[-1].split("?")[0]
                url = Url(href, anchor, "mailto", host, "")
            elif scheme in ("http", "https"):
                authority = rest.lstrip("/")
                host, _, path = authority.partition("/")
                url = Url(href, anchor, scheme, host.lower().split("@")[-1], "/" + path)
            else:
                return
            existing = seen.get(href)
            if existing is None:
                seen[href] = url
            elif anchor and not existing.anchor_text:
                existing.anchor_text = anchor

        if html := self.bodies.get("text/html"):
            extractor = _LinkExtractor()
            extractor.feed(html)
            for href, anchor in extractor.links:
                add(href, anchor)

        for text in self.bodies.values():
            for match in re.finditer(r"https?://[^\s<>\"')]+", text):
                add(match.group(0))

        return list(seen.values())

    # -- derived helpers for rules ---------------------------------------

    def identifiers(self, text: str) -> list[tuple[str, str, str]]:
        """Find reference-number-shaped tokens.

        Returns (full, alpha_prefix, normalised_digits) so two spellings of
        the same identifier compare equal.
        """
        out = []
        for match in IDENT_RE.finditer(text):
            full = match.group(0)
            digits = re.sub(r"[^0-9]", "", match.group(2))
            out.append((full, match.group(1).upper(), digits))
        return out
