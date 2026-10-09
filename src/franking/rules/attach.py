"""Rules about attachments and what is inside them.

The attachment is usually the payload, so these rules carry the highest
severities in the set. Most of the work is noticing that a file's real type
is not the type its name advertises.
"""

from __future__ import annotations

from franking.model import Evidence, Severity
from franking.parse import DOCUMENT_EXTS, EXECUTABLE_EXTS
from franking.rules import rule

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
        findings.append(emit(
            f"'{att.filename}' contains {names}. Archiving an executable is "
            f"the standard way to get it past a mail gateway, which will "
            f"often scan attachments by type but not open the container. The "
            f"recipient extracting the file is what delivers the payload.",
            [
                Evidence("Archive", att.filename),
                Evidence("Archive SHA-256", att.sha256),
                Evidence("Executable content", names),
            ],
            title_override=f"Executable inside {att.filename}",
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
            (ext in {"zip", "jar", "docx", "xlsx", "pptx"} and actual.startswith("ZIP"))
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
        if ext not in EXECUTABLE_EXTS or len(att.extensions) > 1:
            continue  # the double-extension rule covers the disguised case
        findings.append(emit(
            f"'{att.filename}' is a .{ext} file sent directly. Running it "
            f"hands the sender code execution on the host. No routine "
            f"business process requires mailing a file of this type.",
            [
                Evidence("Filename", att.filename),
                Evidence("SHA-256", att.sha256),
            ],
            title_override=f"Executable attachment: {att.filename}",
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
