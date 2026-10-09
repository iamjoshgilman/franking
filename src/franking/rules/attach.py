"""Rules about attachments and what is inside them.

The attachment is usually the payload, so these rules carry the highest
severities in the set. Most of the work is noticing that a file's real type
is not the type its name advertises.
"""

from __future__ import annotations

import re

from franking.model import Evidence, Severity
from franking.parse import DOCUMENT_EXTS, EXECUTABLE_EXTS
from franking.rules import rule
from franking.rules._context import (
    ARCHIVE_EXTS,
    HIGH_RISK_EXTS,
    ZIP_BASED_EXTS,
)

# "the password is hunter2", "pw: hunter2", "passcode hunter2"
# Requires an actual assignment -- "password: hunter2", "pw is hunter2" --
# not the bare word. Without a mandatory separator this matched any
# sentence merely mentioning passwords, including "we never send the
# password by email", which promoted a legitimate partner's encrypted
# archive to CRITICAL and printed "password by" as the evidence.
PASSWORD_RE = re.compile(
    r"(?:pass\s?(?:word|code)|passphrase|pwd|\bpw)\s*(?:is|=|:)\s*"
    r"[\"'‘“]?(?P<secret>[^\s\"'’”<>,.;]{3,40})",
    re.I,
)
# Phrases meaning the password is deliberately *not* in this message.
PASSWORD_ABSENT_RE = re.compile(
    r"(?:never|not|won't|will not|do not|don't)\s+(?:\w+\s+){0,3}"
    r"(?:send|share|include|provide|email|disclose)\b[^.]{0,80}"
    r"(?:pass\s?(?:word|code)|passphrase)",
    re.I,
)

# Leading bytes -> what the file actually is, regardless of its name.
MAGIC = (
    (b"MZ", "Windows PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP archive (or OOXML / JAR)"),
    (b"%PDF", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "OLE2 compound file (legacy Office)"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "gzip stream"),
)


def _describe_chain(name: str, exts: list[str]) -> str:
    return f"{name} ({' -> '.join('.' + e for e in exts)})"


@rule("ATT001", "Attachment uses a double extension", Severity.CRITICAL,
      mitre=["T1036.007", "T1204.002"])
def double_extension(doc, emit):
    findings = []
    targets = [(a.filename, a.extensions, "attachment", None) for a in doc.attachments]
    for att in doc.attachments:
        for entry in att.archive_entries:
            targets.append((entry.name, entry.extensions,
                            f"file inside {att.filename}", att.filename))

    for name, exts, where, parent in targets:
        if len(exts) < 2:
            continue
        final, penultimate = exts[-1], exts[-2]
        if final not in EXECUTABLE_EXTS or penultimate not in DOCUMENT_EXTS:
            continue
        findings.append(emit(
            f"The {where} is named '{name}'. It ends in .{final}, which "
            f"Windows executes, but the .{penultimate} before it makes the "
            f"name read as a harmless document. With 'hide extensions for "
            f"known file types' enabled -- the default -- Explorer displays "
            f"this as '{name.rsplit('.', 1)[0]}' and shows a document icon. "
            f"Double-clicking runs it.",
            [
                Evidence("Filename", name),
                Evidence("Extension chain", _describe_chain(name, exts)),
                Evidence("Executed as", f".{final}"),
            ] + ([Evidence("Container", parent)] if parent else []),
            title_override=f"Double extension: {name}",
        ))
    return findings


@rule("ATT002", "Archive contains an executable file", Severity.CRITICAL,
      mitre=["T1566.001", "T1204.002"])
def archive_contains_executable(doc, emit):
    findings = []
    for att in doc.attachments:
        risky = [e for e in att.archive_entries
                 if e.final_ext in EXECUTABLE_EXTS]
        if not risky:
            continue
        names = ", ".join(e.name for e in risky)
        # Severity by what is actually inside. A zip of a web build
        # contains .js by definition; a zip containing .exe does not have
        # an innocent reading.
        direct = [e for e in risky if e.final_ext in HIGH_RISK_EXTS]
        disguised = [e for e in risky if len(e.extensions) > 1]
        severity = (Severity.CRITICAL if (direct or disguised)
                    else Severity.MEDIUM)
        if severity is Severity.CRITICAL:
            detail = (
                f"'{att.filename}' contains {names}. Archiving an executable "
                f"is the standard way past a mail gateway, which often scans "
                f"attachments by type without opening the container. The "
                f"recipient extracting the file is what delivers the payload."
            )
        else:
            detail = (
                f"'{att.filename}' contains {names}. Script files inside an "
                f"archive are routine in software distribution -- a web "
                f"build or a Java artifact looks exactly like this -- so "
                f"this is only notable alongside other findings. None of "
                f"them runs on a double-click."
            )
        findings.append(emit(
            detail,
            [
                Evidence("Archive", att.filename),
                Evidence("Archive SHA-256", att.sha256),
                Evidence("Executable content", names),
            ],
            title_override=f"Executable inside {att.filename}",
            severity_override=severity,
        ))
    return findings


@rule("ATT003", "Attachment type contradicts its contents", Severity.HIGH,
      mitre=["T1036"])
def magic_mismatch(doc, emit):
    findings = []
    for att in doc.attachments:
        if not att.data:
            continue
        actual = next((desc for sig, desc in MAGIC
                       if att.data.startswith(sig)), None)
        if actual is None:
            continue
        ext = att.final_ext
        consistent = (
            (ext in ZIP_BASED_EXTS and actual.startswith("ZIP"))
            or (ext == "pdf" and actual.startswith("PDF"))
            or (ext in {"doc", "xls", "ppt", "msg"} and actual.startswith("OLE2"))
            or (ext in {"exe", "dll", "scr"} and actual.startswith("Windows PE"))
            or (ext == "rar" and actual.startswith("RAR"))
            or (ext == "7z" and actual.startswith("7-Zip"))
            or (ext == "gz" and actual.startswith("gzip"))
        )
        if consistent or not ext:
            continue
        findings.append(emit(
            f"'{att.filename}' is named as a .{ext} file but its leading "
            f"bytes identify it as a {actual}. The extension is decoration; "
            f"what matters is the content.",
            [
                Evidence("Filename", att.filename),
                Evidence("Declared type", att.content_type),
                Evidence("Actual type", actual),
            ],
            title_override=f"{att.filename} is not a .{ext}",
        ))
    return findings


@rule("ATT004", "Executable attached directly", Severity.CRITICAL,
      mitre=["T1566.001", "T1204.002"])
def bare_executable(doc, emit):
    findings = []
    for att in doc.attachments:
        ext = att.final_ext
        if ext not in EXECUTABLE_EXTS:
            continue
        # Defer to ATT001 only when ATT001 will actually fire -- that is,
        # when the preceding extension is a known document type. Skipping
        # every multi-extension name left a seam: Invoice.v2.exe matched
        # neither rule, so a bare mailed executable went unreported.
        exts = att.extensions
        if len(exts) > 1 and exts[-2] in DOCUMENT_EXTS:
            continue
        disguise = (f" The '.{exts[-2]}' before it adds nothing but "
                    f"confusion to the name." if len(exts) > 1 else "")
        findings.append(emit(
            f"'{att.filename}' is a .{ext} file sent directly.{disguise} "
            f"Running it hands the sender code execution on the host. No "
            f"routine business process requires mailing a file of this type.",
            [
                Evidence("Filename", att.filename),
                Evidence("SHA-256", att.sha256),
            ],
            title_override=f"Executable attachment: {att.filename}",
        ))
    return findings


@rule("ATT006", "Encrypted archive with the password in the message",
      Severity.CRITICAL, mitre=["T1027.002", "T1566.001"])
def encrypted_archive_with_password(doc, emit):
    """The oldest trick that still works on most mail gateways.

    A scanner cannot read what it cannot decrypt, so an encrypted archive
    passes inspection untouched. Putting the password in the body hands
    the recipient the key the gateway was denied, which is the whole
    design -- and why the combination says far more than either half.
    """
    findings = []
    match = PASSWORD_RE.search(doc.body_text)
    if match and PASSWORD_ABSENT_RE.search(doc.body_text):
        # The body is saying where the password is *not*.
        match = None

    for att in doc.attachments:
        if not att.is_encrypted:
            continue
        locked = ", ".join(e.name for e in att.archive_entries if e.encrypted)
        if match:
            detail = (
                f"'{att.filename}' is encrypted, and the body supplies the "
                f"password. Encryption stops the mail gateway and any "
                f"sandbox from examining the contents, while the recipient "
                f"is handed exactly what they need to open it. That "
                f"asymmetry is the point: it is an anti-analysis measure "
                f"aimed past the user at the controls protecting them."
            )
            severity = Severity.CRITICAL
            evidence = [
                Evidence("Archive", att.filename),
                Evidence("Encrypted entries", locked),
                Evidence("Password in body", match.group("secret")),
                Evidence("SHA-256", att.sha256),
            ]
        else:
            detail = (
                f"'{att.filename}' is encrypted, so neither a gateway nor "
                f"this tool can inspect what it holds. Filenames remain "
                f"readable from the archive headers, but the contents are "
                f"opaque. If the sender expects it to be opened, the "
                f"password reached the recipient somehow -- check the thread."
            )
            severity = Severity.HIGH
            evidence = [
                Evidence("Archive", att.filename),
                Evidence("Encrypted entries", locked),
                Evidence("SHA-256", att.sha256),
            ]
        findings.append(emit(
            detail, evidence,
            severity_override=severity,
            title_override=(
                f"Encrypted archive {att.filename}"
                + (" with password in body" if match else "")
            ),
        ))
    return findings


@rule("ATT007", "Archive contains another archive", Severity.HIGH,
      mitre=["T1027.002", "T1566.001"])
def nested_archive(doc, emit):
    """Double-zipping, the oldest gateway evasion there is.

    Every attachment rule reads one level of archive contents, so a
    payload one level deeper is invisible to all of them: the same
    .pdf.exe that fires two CRITICALs at depth one produces nothing at
    depth two. Until the parser recurses, the nesting itself is the
    finding -- and it is a strong one, because there is almost no honest
    reason to put a zip inside a zip in email.
    """
    findings = []
    for att in doc.attachments:
        inner = [e for e in att.archive_entries
                 if e.final_ext in ARCHIVE_EXTS]
        if not inner:
            continue
        names = ", ".join(e.name for e in inner)
        findings.append(emit(
            f"'{att.filename}' contains {names} -- an archive inside an "
            f"archive. Scanners that look one level deep see only another "
            f"container, and so does this tool: nothing can be said about "
            f"what is in the innermost layer. Legitimate mail essentially "
            f"never nests archives, while gateway evasion relies on it. "
            f"Extract the inner archive and analyse it separately.",
            [
                Evidence("Outer archive", att.filename),
                Evidence("Nested archive(s)", names),
                Evidence("Outer SHA-256", att.sha256),
            ],
            title_override=f"Nested archive inside {att.filename}",
        ))
    return findings


@rule("ATT008", "Archive format could not be inspected", Severity.INFO)
def uninspected_archive(doc, emit):
    """Say so rather than implying an empty archive is a safe one.

    is_archive accepts .rar and .7z, then the ZIP scanner finds nothing
    in them -- so archive_entries is empty, is_encrypted is False, and
    every content rule silently passes. An encrypted RAR could not be
    reported at all.
    """
    findings = []
    for att in doc.attachments:
        if not att.is_archive or att.archive_entries:
            continue
        fmt = att.final_ext.upper() or "unknown"
        if fmt.lower() in ("zip",):
            continue
        findings.append(emit(
            f"'{att.filename}' is a {fmt} archive. Only ZIP containers can "
            f"be listed here, so its contents are unknown -- not empty, and "
            f"not safe. Any finding about what this attachment holds is "
            f"absent because it could not be read, which is worth knowing "
            f"before concluding the message is clean.",
            [
                Evidence("Attachment", att.filename),
                Evidence("Format", fmt),
                Evidence("SHA-256", att.sha256),
            ],
            title_override=f"{att.filename} ({fmt}) was not inspected",
        ))
    return findings


@rule("ATT005", "Archive is truncated or malformed", Severity.INFO)
def truncated_archive(doc, emit):
    findings = []
    for att in doc.attachments:
        if not att.archive_truncated:
            continue
        declared = sum(e.compressed_size for e in att.archive_entries)
        findings.append(emit(
            f"'{att.filename}' is {att.size} bytes, but its local headers "
            f"declare {declared} bytes of compressed content. The archive is "
            f"cut short, so the payload itself cannot be extracted or "
            f"analysed. Filenames and sizes are still readable from the "
            f"headers, which is usually enough to identify the lure. In "
            f"training samples the payload is removed on purpose.",
            [
                Evidence("Actual size", f"{att.size} bytes"),
                Evidence("Declared compressed size", f"{declared} bytes"),
                Evidence("Recovered entries",
                         ", ".join(e.name for e in att.archive_entries) or "none"),
            ],
            title_override=f"{att.filename} is truncated",
        ))
    return findings
