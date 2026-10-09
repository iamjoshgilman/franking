"""Turn a .eml file into structured facts the rules can reason about.

Nothing in here judges the message -- it only extracts. All the "is this
suspicious" logic lives in :mod:`franking.rules`, so the parser stays
reusable and the rules stay testable.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import io
import re
import struct
import zipfile
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
# Matched only inside a balanced bracket pair, so a stray digit run in
# prose is not mistaken for an address.
BRACKETED_IP_RE = re.compile(r"\[((?:\d{1,3}\.){3}\d{1,3})\]"
                             r"|\(((?:\d{1,3}\.){3}\d{1,3})\)")
ADDR_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# An RFC 5322 comment. Non-greedy and non-nesting, which is enough for
# the single-level comments real MTAs write.
COMMENT_RE = re.compile(r"\([^()]*\)")
ENCODED_WORD_RE = re.compile(r"=\?[^?]+\?[BbQq]\?[^?]*\?=")
# ADDR_RE backtracks quadratically on a long run with no "@"; refuse to
# run it on anything longer than a plausible header.
MAX_ADDR_SCAN = 4096
# Identifiers like INV-2025-0012, ACC_99381, REF2025-0987.
IDENT_RE = re.compile(r"\b([A-Z]{2,6})[-_ ]?(\d{3,}(?:[-_]\d+)*)\b")

ZIP_LOCAL_HEADER = b"PK\x03\x04"
ZIP_LOCAL_HEADER_LEN = 30
ZIP_FLAG_ENCRYPTED = 0x0001
ZIP_FLAG_DATA_DESCRIPTOR = 0x0008
ZIP_FLAG_UTF8 = 0x0800
ZIP_DATA_DESCRIPTOR = b"PK\x07\x08"
# Caps so a crafted archive cannot turn a 32 MB attachment into a
# million-entry report, or put kilobytes of binary into a filename.
MAX_ZIP_ENTRIES = 2048
MAX_ZIP_NAME = 512

# Characters that make a string render differently from how it reads.
BIDI_OVERRIDES = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}
ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
}
INVISIBLE = {**BIDI_OVERRIDES, **ZERO_WIDTH}

# Scripts that, mixed with Latin inside one domain label, mean a homoglyph
# attack rather than genuine internationalisation.
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN")

# A nested message can nest again; cap it so a malformed sample cannot
# recurse without bound.
MAX_NESTING = 5
# Multipart nesting is separate from message/rfc822 nesting and was
# previously unbounded.
MAX_PART_DEPTH = 24

# Brands worth impersonating. A floor, not a list: an organisation should
# extend it with its own names and those of its suppliers and banks.
IMPERSONATION_TARGETS = (
    "microsoft.com", "office365.com", "outlook.com", "live.com",
    "google.com", "gmail.com", "apple.com", "icloud.com", "amazon.com",
    "paypal.com", "netflix.com", "facebook.com", "instagram.com",
    "linkedin.com", "dropbox.com", "docusign.com", "adobe.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "hsbc.com",
    "barclays.co.uk", "santander.com", "citibank.com", "americanexpress.com",
    "fedex.com", "ups.com", "dhl.com", "usps.com", "royalmail.com",
    "salesforce.com", "slack.com", "zoom.us", "github.com", "atlassian.com",
)
BRAND_STEMS = {t.split(".")[0] for t in IMPERSONATION_TARGETS}

# Two-label public suffixes common enough to matter when approximating the
# organisational domain. Not a public suffix list -- see org_domain().
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "co.za", "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.br", "com.mx", "com.cn", "com.sg", "com.hk", "com.tr",
    "co.in", "co.kr", "co.il",
}

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


def valid_ipv4(text: str) -> bool:
    """Four dot-separated octets, each in range.

    IP_RE's \\d{1,3} happily matches 999.888.777.666, and without this
    check such a string is published as an indicator.
    """
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(p.isdigit() and 0 <= int(p) <= 255 and
                   (p == "0" or not p.startswith("0") or len(p) == 1)
                   for p in parts)
    except ValueError:
        return False


def org_domain(host: str) -> str:
    """Approximate the organisational domain (eTLD+1).

    Deliberately dependency-free, with a short table of the two-label
    suffixes that actually show up. It is an approximation: treat a
    surprising answer on an exotic TLD as the limitation it is.
    """
    labels = [p for p in host.lower().strip(".").split(".") if p]
    if len(labels) < 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def invisible_chars(text: str) -> list[tuple[str, str]]:
    """Return (character, Unicode name) for every invisible char in text."""
    return [(ch, INVISIBLE[ch]) for ch in text if ch in INVISIBLE]


def script_of(ch: str) -> str | None:
    """The writing system a letter belongs to, by Unicode name prefix."""
    import unicodedata

    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    return name.split()[0]


def mixed_scripts(text: str) -> set[str]:
    """Scripts present among the letters of ``text``."""
    return {s for s in (script_of(c) for c in text) if s}


def decode_punycode(host: str) -> str | None:
    """Decode an IDNA host to its Unicode form, or None if not punycode."""
    if "xn--" not in host.lower():
        return None
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return None


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance, iterative two-row form."""
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]


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
    # True when the header contained an RFC 2047 encoded word. Received is
    # unstructured, so a decoder would expand it -- and an attacker can
    # hide a whole fabricated hop inside one.
    encoded_word: bool = False

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
    encrypted: bool = False
    # True when read from the central directory, which is the name an
    # extractor will actually write to disk.
    from_central_directory: bool = False

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
    def is_encrypted(self) -> bool:
        return any(e.encrypted for e in self.archive_entries)

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
    # Which domain each result was computed *for*. DMARC passes only if one
    # of these aligns with the From domain, so the domain matters as much
    # as the verdict.
    spf_domain: str | None = None
    dkim_domain: str | None = None
    dmarc_domain: str | None = None
    received_spf_result: str | None = None
    received_spf_ip: str | None = None
    received_spf_verifier: str | None = None
    dkim_signature_present: bool = False
    dkim_sigs: list[dict[str, str]] = field(default_factory=list)
    arc_sets: dict[int, dict[str, str]] = field(default_factory=dict)
    # Additional Authentication-Results headers beyond the first. A
    # receiver prepends its own, so a second one is often the sender's
    # forgery left in place below it.
    extra_raw: list[str] = field(default_factory=list)
    result_header_count: int = 0
    duplicate_methods: set = field(default_factory=set)


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


def _decode_zip_name(raw: bytes, flags: int) -> str:
    """Decode an entry name per APPNOTE 4.4.4.

    Names are CP437 unless general-purpose bit 11 says UTF-8. Assuming
    UTF-8 unconditionally turns every non-ASCII name into mojibake.
    """
    if flags & ZIP_FLAG_UTF8:
        return raw.decode("utf-8", errors="replace")
    try:
        return raw.decode("cp437")
    except (UnicodeDecodeError, LookupError):
        return raw.decode("utf-8", errors="replace")


def _zip64_sizes(extra: bytes, csize: int, usize: int) -> tuple[int, int]:
    """Replace 0xFFFFFFFF sentinels from the ZIP64 extra field (id 0x0001)."""
    offset = 0
    while offset + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, offset)
        body = extra[offset + 4:offset + 4 + size]
        if header_id == 0x0001:
            values = []
            for i in range(0, min(len(body), 16), 8):
                if i + 8 <= len(body):
                    values.append(struct.unpack_from("<Q", body, i)[0])
            # Order in the record is uncompressed then compressed, and
            # only the fields that were sentinels are present.
            sentinels = [usize == 0xFFFFFFFF, csize == 0xFFFFFFFF]
            idx = 0
            if sentinels[0] and idx < len(values):
                usize = values[idx]
                idx += 1
            if sentinels[1] and idx < len(values):
                csize = values[idx]
            break
        offset += 4 + size
    return csize, usize


def _entries_from_central_directory(data: bytes) -> list[ArchiveEntry] | None:
    """Read the central directory, which is what real extractors use.

    A ZIP can name one file in its local header and a different one in
    the central directory. ``unzip`` writes the central directory's name
    to disk, so reporting the local one names a file that never appears
    and omits the one that does.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = []
            for info in archive.infolist()[:MAX_ZIP_ENTRIES]:
                if info.is_dir():
                    continue
                name = info.filename[:MAX_ZIP_NAME]
                entries.append(ArchiveEntry(
                    name=name,
                    compressed_size=info.compress_size,
                    uncompressed_size=info.file_size,
                    crc32=info.CRC,
                    extensions=_extensions(name),
                    encrypted=bool(info.flag_bits & ZIP_FLAG_ENCRYPTED),
                    from_central_directory=True,
                ))
            return entries
    except (zipfile.BadZipFile, OSError, ValueError, EOFError,
            NotImplementedError, RuntimeError):
        return None


def scan_zip_entries(data: bytes) -> tuple[list[ArchiveEntry], bool]:
    """List the files inside a ZIP, tolerating damage.

    Prefers the central directory, because that is what an extractor
    reads and therefore what the recipient will actually get. Falls back
    to walking local file headers when the directory is missing or
    unreadable -- which is the normal state of a deliberately truncated
    training sample, and still recovers the filenames.

    Returns (entries, truncated).
    """
    if not data:
        return [], False

    central = _entries_from_central_directory(data)
    if central is not None:
        return central, False

    entries: list[ArchiveEntry] = []
    truncated = False
    offset = 0

    while len(entries) < MAX_ZIP_ENTRIES:
        start = data.find(ZIP_LOCAL_HEADER, offset)
        if start < 0:
            break
        header = data[start:start + ZIP_LOCAL_HEADER_LEN]
        if len(header) < ZIP_LOCAL_HEADER_LEN:
            truncated = True
            break

        flags = struct.unpack_from("<H", header, 6)[0]
        crc32, csize, usize = struct.unpack_from("<III", header, 14)
        name_len, extra_len = struct.unpack_from("<HH", header, 26)

        # A plausible header has a plausible name length. Without this a
        # run of PK\x03\x04 bytes inside compressed data yields entries
        # with kilobytes of binary garbage as their "filename".
        if name_len == 0 or name_len > MAX_ZIP_NAME:
            offset = start + 4
            continue

        name_start = start + ZIP_LOCAL_HEADER_LEN
        raw_name = data[name_start:name_start + name_len]
        if len(raw_name) < name_len:
            truncated = True
            break
        name = _decode_zip_name(raw_name, flags)

        extra = data[name_start + name_len:name_start + name_len + extra_len]
        if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF:
            csize, usize = _zip64_sizes(extra, csize, usize)

        entries.append(ArchiveEntry(
            name=name,
            compressed_size=csize,
            uncompressed_size=usize,
            crc32=crc32,
            extensions=_extensions(name),
            encrypted=bool(flags & ZIP_FLAG_ENCRYPTED),
        ))

        body_end = name_start + name_len + extra_len + csize
        if flags & ZIP_FLAG_DATA_DESCRIPTOR and csize == 0:
            # The real size lives in a trailing descriptor we cannot see
            # from here. Skip to the next descriptor signature rather
            # than rescanning the payload, where arbitrary bytes would
            # otherwise be parsed as further members.
            marker = data.find(ZIP_DATA_DESCRIPTOR, name_start + name_len)
            body_end = marker + 16 if marker >= 0 else len(data)
        elif body_end > len(data):
            truncated = True
            break
        offset = max(body_end, name_start + name_len + 1)

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

    def __init__(self, raw: bytes, path: Path | None = None, depth: int = 0):
        self.raw = raw
        self.path = path
        self.depth = depth
        # A second, undecoded view of the same bytes, built on first use.
        # False means it could not be built.
        self._raw_msg: object = None
        try:
            self.msg: EmailMessage = email.message_from_bytes(
                raw, policy=email.policy.default
            )
        except RecursionError as exc:
            # ~1000 nested multipart boundaries in 61 KB exhausts the
            # stdlib parser's stack. RecursionError is a RuntimeError, so
            # it escaped the CLI's handler as a traceback.
            raise ValueError(
                "message nesting is too deep to parse safely"
            ) from exc
        self.headers: list[tuple[str, str]] = [
            (k, str(v)) for k, v in self.msg.items()
        ]
        self.hops: list[Hop] = self._parse_received()
        self.auth: AuthResults = self._parse_auth()
        self.bodies: dict[str, str] = {}
        self.bad_charsets: list[str] = []
        self.attachments: list[Attachment] = []
        self.urls: list[Url] = []
        self.nested: list[EmailDoc] = self._parse_nested()
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

    def _raw_header_values(self, name: str) -> list[str]:
        """Header values as written, without RFC 2047 decoding.

        ``str()`` on a policy-default header decodes encoded words, and
        for an unstructured header like Received that is a forgery
        primitive: Q-encoding turns ``_`` into a space and supplies
        brackets and parens, so an attacker can write an entire
        fabricated hop -- source host and IP included -- inside a single
        encoded word. compat32 keeps the bytes as sent, so the clause
        parser sees what the MTA actually wrote.
        """
        if self._raw_msg is None:
            try:
                self._raw_msg = email.message_from_bytes(
                    self.raw, policy=email.policy.compat32)
            except Exception:  # noqa: BLE001 - fall back to the decoded view
                self._raw_msg = False
        if self._raw_msg is False:
            return self.get_all(name)
        values = self._raw_msg.get_all(name) or []
        return [" ".join(str(v).split()) for v in values]

    def has_header(self, name: str) -> bool:
        return self.msg.get(name) is not None

    @property
    def subject(self) -> str:
        return self.get("Subject") or ""

    def _address(self, header: str) -> tuple[str, str]:
        """(addr_spec, display_name) for a header, via the stdlib parser.

        A regex over the raw header picks the *first* address it sees,
        which is wrong whenever the display name contains one of its own:
        in ``"billing@supplier.example" <attacker@evil.example>`` the
        sender is the second address, and the first is the lie.
        """
        value = self.msg.get(header)
        if value is None:
            return "", ""
        addresses = getattr(value, "addresses", None)
        if addresses:
            first = addresses[0]
            return (str(first.addr_spec or ""), str(first.display_name or ""))
        return self._first_addr(str(value)), ""

    @property
    def from_addr(self) -> str:
        return self._address("From")[0]

    @property
    def from_display(self) -> str:
        return self._address("From")[1]

    @property
    def reply_to(self) -> str:
        return self._address("Reply-To")[0]

    @property
    def return_path(self) -> str:
        return self._address("Return-Path")[0]

    @property
    def to_addr(self) -> str:
        return self._address("To")[0]

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
        """All human-readable body text, plain and HTML parts together.

        Returning only the plain part when one exists would hide the half
        that matters. In a multipart/alternative phish the plain part is
        routinely an innocuous decoy -- "please see the attached
        statement" -- while the lure, the urgency and the archive password
        live in the HTML the recipient actually sees. Rules that search
        the body need both.
        """
        chunks = []
        if plain := self.bodies.get("text/plain"):
            chunks.append(plain)
        if html := self.bodies.get("text/html"):
            extractor = _LinkExtractor()
            extractor.feed(html)
            chunks.append(extractor.text)
        return "\n".join(chunks)

    @staticmethod
    def _first_addr(value: str | None) -> str:
        if not value:
            return ""
        # ADDR_RE backtracks quadratically over a long run containing no
        # "@", and an empty address group routes a whole header here. A
        # 128 KB From header took 16 seconds before this bound.
        match = ADDR_RE.search(value[:MAX_ADDR_SCAN])
        return match.group(0) if match else ""

    @staticmethod
    def domain_of(addr: str) -> str:
        return addr.split("@")[-1].lower() if "@" in addr else ""

    # -- parsing ---------------------------------------------------------

    def _parse_received(self) -> list[Hop]:
        # Use the undecoded header text. str() on a policy-default header
        # RFC 2047-decodes it, and a Q-encoded word turns "_" into a space
        # and supplies "[", "]" and "(" -- so an attacker can write an
        # entire fabricated hop, complete with source IP, inside one
        # encoded word in a header they control.
        raws = self._raw_header_values("Received")
        hops: list[Hop] = []
        # File order is newest-first; transit order is the reverse.
        for index, raw in enumerate(reversed(raws)):
            flat = " ".join(raw.split())
            hop = Hop(index=index, raw=flat)
            hop.encoded_word = bool(ENCODED_WORD_RE.search(flat))

            # Timestamp first: it is the only part delimited by the final
            # semicolon, and removing it keeps its digits out of the IP
            # and clause matching below.
            body = flat
            if ";" in flat:
                body, _, when = flat.rpartition(";")
                try:
                    hop.timestamp = parsedate_to_datetime(when.strip())
                except (TypeError, ValueError, IndexError):
                    hop.timestamp = None

            # Comments carry prose an MTA wrote about the hop; matching
            # clauses inside them yields the wrong host ("authenticated by
            # smtp-auth" -> by_host='smtp-auth') and the wrong IP (the
            # receiver's own interface). Keep them for the IP of the from
            # clause, which conventionally lives in the first comment, but
            # match the clauses themselves against comment-free text.
            bare = COMMENT_RE.sub(" ", body)
            comments = COMMENT_RE.findall(body)

            if m := re.search(r"\bfrom\s+([^\s;()]+)", bare, re.I):
                candidate = m.group(1)
                # "from" must introduce a HELO name, not appear as part of
                # "envelope-from" or similar.
                if not candidate.startswith("<"):
                    hop.from_host = candidate
            if m := re.search(r"\bby\s+([^\s;()]+)", bare, re.I):
                hop.by_host = m.group(1)
            if m := re.search(r"\bwith\s+([A-Za-z0-9/]+)", bare, re.I):
                hop.protocol = m.group(1)
            if m := re.search(r"\bid\s+([^\s;]+)", bare, re.I):
                hop.ident = m.group(1)

            hop.from_ip = self._hop_source_ip(body, comments)
            hops.append(hop)
        return hops

    @staticmethod
    def _hop_source_ip(body: str, comments: list[str]) -> str | None:
        """The connecting client's address, not the receiver's.

        Scoped to the text before the ``by`` clause: an address appearing
        after it belongs to the receiving side, and reporting that as the
        source puts the wrong IP in the IOC list.
        """
        source_part = re.split(r"\bby\b", body, maxsplit=1, flags=re.I)[0]
        for match in BRACKETED_IP_RE.finditer(source_part):
            candidate = match.group(1) or match.group(2)
            if candidate and valid_ipv4(candidate):
                return candidate
        # Some MTAs put the address in the first comment without brackets.
        for comment in comments[:1]:
            for candidate in IP_RE.findall(comment):
                if valid_ipv4(candidate):
                    return candidate
        for candidate in IP_RE.findall(source_part):
            if valid_ipv4(candidate):
                return candidate
        return None

    @staticmethod
    def _fill_auth_results(auth: AuthResults, raw: str) -> None:
        """Read an Authentication-Results header section by section.

        RFC 8601 structures this header as an authserv-id followed by
        semicolon-separated resinfo sections, each one method, result and
        properties. Searching the whole string for ``spf=`` instead finds
        whichever match comes first -- and Gmail restates every inner
        verdict inside its leading ``arc=pass (...)`` comment, so a
        message whose real results are all failures reads as all passes.
        Parse per section, with comments removed, and keep the method and
        its properties together.
        """
        sections = [s.strip() for s in COMMENT_RE.sub(" ", raw).split(";")]
        sections = [s for s in sections if s]
        if not sections:
            return

        # A real authserv-id is a bare token before the first ';'.
        if "=" not in sections[0]:
            auth.authserv_id = sections[0].split()[0]
            sections = sections[1:]

        for section in sections:
            m = re.match(r"(\w+)\s*=\s*(\w+)", section)
            if m is None:
                continue
            method, result = m.group(1).lower(), m.group(2).lower()
            if method not in ("spf", "dkim", "dmarc"):
                continue
            # First section for a method wins; a later duplicate is
            # recorded rather than allowed to overwrite it.
            if getattr(auth, method) is not None:
                auth.duplicate_methods.add(method)
                continue
            setattr(auth, method, result)

            # Properties are scoped to this section, so the verdict and
            # the identity it applies to can never come from different
            # mechanisms.
            if method == "spf":
                if p := re.search(r"smtp\.mailfrom=([^\s;]+)", section, re.I):
                    auth.spf_domain = p.group(1).split("@")[-1].lower()
                elif p := re.search(r"smtp\.helo=([^\s;]+)", section, re.I):
                    auth.spf_domain = p.group(1).lower()
            elif method == "dkim":
                if p := re.search(r"header\.d=([^\s;]+)", section, re.I):
                    auth.dkim_domain = p.group(1).lower()
            elif method == "dmarc" and (
                    p := re.search(r"header\.from=([^\s;]+)", section, re.I)):
                auth.dmarc_domain = p.group(1).split("@")[-1].lower()

    def _parse_auth(self) -> AuthResults:
        auth = AuthResults()
        auth.dkim_signature_present = self.has_header("DKIM-Signature")
        auth.dkim_sigs = [
            _parse_tag_list(" ".join(v.split()))
            for v in self.get_all("DKIM-Signature")
        ]

        all_results = self.get_all("Authentication-Results")
        auth.result_header_count = len(all_results)
        if all_results:
            auth.raw = " ".join(all_results[0].split())
            auth.extra_raw = [" ".join(v.split()) for v in all_results[1:]]
            self._fill_auth_results(auth, auth.raw)

        spf_raw = self.get("Received-SPF")
        if spf_raw:
            flat = " ".join(spf_raw.split())
            bare = COMMENT_RE.sub(" ", flat)
            if m := re.search(r"\b(pass|fail|softfail|neutral|none|"
                              r"temperror|permerror)\b", bare, re.I):
                auth.received_spf_result = m.group(1).lower()
            # client-ip= is the address the check was actually run against.
            # Prose inside the comment often names a *different* address
            # ("192.0.2.1 is not permitted to send mail"), and taking that
            # one publishes the wrong source IOC.
            m = re.search(r"client-ip=([0-9.]+)", flat, re.I)
            if m and valid_ipv4(m.group(1)):
                auth.received_spf_ip = m.group(1)
            if auth.received_spf_ip is None:
                for candidate in IP_RE.findall(flat):
                    if valid_ipv4(candidate):
                        auth.received_spf_ip = candidate
                        break
            if v := re.search(r"\(([^\s:()]+):", flat):
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

    def _own_parts(self, msg) -> list:
        """Leaf parts belonging to this message only.

        Unlike ``walk()`` this stops at a ``message/rfc822`` boundary: an
        attached message's own attachments belong to *that* message, not to
        the envelope carrying it. Without this, a forwarded phishing report
        inherits the payload it contains while its headers stay those of
        the employee who reported it -- so every finding is attributed to
        the wrong message.
        """
        return self._walk_parts(msg, 0)

    def _walk_parts(self, msg, depth: int) -> list:
        if depth > MAX_PART_DEPTH:
            return []
        if msg.get_content_maintype() == "multipart":
            parts = []
            payload = msg.get_payload()
            if isinstance(payload, list):
                for sub in payload:
                    parts.extend(self._walk_parts(sub, depth + 1))
            return parts
        return [msg]

    def _parse_nested(self) -> list[EmailDoc]:
        """Messages attached to this one, parsed in their own right."""
        if self.depth >= MAX_NESTING:
            return []
        nested: list[EmailDoc] = []
        for part in self._own_parts(self.msg):
            if part.get_content_type() != "message/rfc822":
                continue
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else payload
            if not hasattr(inner, "as_bytes"):
                continue
            try:
                nested.append(EmailDoc(inner.as_bytes(), path=self.path,
                                       depth=self.depth + 1))
            except (ValueError, TypeError):
                continue
        return nested

    def innermost(self) -> EmailDoc:
        """The message a report is actually *about*.

        A user forwards a phish; the thing worth analysing is the
        attachment, not the covering note. Recurses, so a forward of a
        forward still resolves to the original.
        """
        return self.nested[0].innermost() if self.nested else self

    def _parse_parts(self) -> None:
        for part in self._own_parts(self.msg):
            if part.get_content_maintype() == "multipart":
                continue

            filename = part.get_filename()
            disposition = (part.get_content_disposition() or "").lower()
            ctype = part.get_content_type()

            if filename or disposition == "attachment":
                data = part.get_payload(decode=True) or b""
                if not data and part.get_content_maintype() == "message":
                    # get_payload(decode=True) returns None for message/*,
                    # which made the most important artifact in a
                    # forwarded report show 0 bytes and the hash of the
                    # empty string.
                    inner = part.get_payload()
                    if isinstance(inner, list) and inner:
                        inner = inner[0]
                    if hasattr(inner, "as_bytes"):
                        try:
                            data = inner.as_bytes()
                        except (ValueError, TypeError, UnicodeEncodeError):
                            data = b""
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
            except (LookupError, ValueError, UnicodeError):
                # An attacker-supplied charset can be unknown, contain a
                # NUL, or name a non-text codec. Any of those used to
                # abort the whole parse, which is a cheap way to make a
                # phish unanalysable by the tool meant to analyse it.
                text = payload.decode("utf-8", errors="replace")
                self.bad_charsets.append(charset)
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
