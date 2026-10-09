"""Shared predicates for rules.

Most false positives come from rules that judge a message without first
asking what kind of message it is. A bounce envelope that differs from the
From address is forgery on personal mail and mandatory practice on a
mailing list; a Reply-To pointing elsewhere is a redirect on an invoice and
the entire purpose of a discussion list. These helpers let a rule ask that
question in one line instead of re-deriving it badly.
"""

from __future__ import annotations

from franking.parse import IMPERSONATION_TARGETS, edit_distance, org_domain

# Headers that mark a message as list or machine traffic. Their presence is
# not suspicious: it is a statement about the message's provenance that
# several rules need in order to stand down.
BULK_HEADERS = (
    "List-Id", "List-Unsubscribe", "List-Post", "List-Help",
    "Auto-Submitted", "X-Auto-Response-Suppress", "X-Mailing-List",
    "X-Campaign-Id", "X-Mailer-LID", "Feedback-ID",
)

# Verifiers that omit the RFC 8601 authserv-id but identify themselves by
# other means. Exchange Online writes compauth=; several gateways note the
# connecting IP inline. Treating these as forgery accuses whole platforms.
AUTHSERV_SUBSTITUTES = (
    "compauth=", "(sender ip is", "x-ms-exchange", "dkim=pass (signature",
    "spf=pass (sender", "reason=",
)

# Brands under common ownership, so invoking one from another's domain is
# not impersonation. Keyed by the stem used in IMPERSONATION_TARGETS.
BRAND_FAMILIES = {
    "microsoft": {"microsoft", "office365", "outlook", "live", "msn",
                  "sharepoint", "azure", "skype"},
    "office365": {"microsoft", "office365", "outlook", "live"},
    "outlook": {"microsoft", "office365", "outlook", "live"},
    "live": {"microsoft", "office365", "outlook", "live"},
    "google": {"google", "gmail", "youtube", "googlemail"},
    "gmail": {"google", "gmail", "googlemail"},
    "apple": {"apple", "icloud", "itunes", "me"},
    "icloud": {"apple", "icloud", "itunes", "me"},
    "facebook": {"facebook", "instagram", "meta", "whatsapp"},
    "instagram": {"facebook", "instagram", "meta", "whatsapp"},
}

# Latin letters that another script supplies a visual twin for. Used to
# reduce a label to a comparable skeleton, which is what separates a
# homoglyph attack from ordinary internationalisation: кофейня.ru is a
# Russian word, while аррӏе.com reduces to "apple".
CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "к": "k",
    "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ӏ": "l",
    "қ": "k", "ԁ": "d", "ԍ": "g", "ԛ": "q",
    "ԝ": "w", "һ": "h", "ґ": "r", "г": "r",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i",
    "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "σ": "o", "τ": "t", "υ": "u", "χ": "x",
    "μ": "u", "η": "n", "γ": "y",
    # Latin lookalikes from other blocks
    "ı": "i", "ɡ": "g", "Ү": "y",
}

# Containers that are legitimately ZIP archives on disk, so "its bytes say
# ZIP" is not evidence the extension is a lie.
ZIP_BASED_EXTS = {
    "zip", "jar", "war", "ear", "apk", "ipa", "xpi", "crx",
    "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm",
    "pptx", "pptm", "potx", "ppsx", "odt", "ods", "odp", "odg", "otp",
    "epub", "vsdx", "whl", "egg", "nupkg", "kmz", "3mf", "usdz",
}

ARCHIVE_EXTS = {"zip", "rar", "7z", "gz", "bz2", "xz", "tar", "tgz",
                "cab", "arj", "lzh", "ace", "iso", "img"}

# Scripting and executable types differ in how directly they run. A .js in
# a web build is routine; a .exe never is.
HIGH_RISK_EXTS = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msc", "hta", "lnk",
    "bat", "cmd", "vbs", "vbe", "wsf", "wsh", "ps1", "jse", "reg",
    "chm", "scf", "inf", "application",
}
CONTEXT_RISK_EXTS = {"js", "jar", "vb", "iso", "img"}


def is_bulk(doc) -> bool:
    """List, campaign or machine-generated mail."""
    for header in BULK_HEADERS:
        value = doc.get(header)
        if value and value.strip().lower() != "no":
            return True
    precedence = (doc.get("Precedence") or "").strip().lower()
    return precedence in {"bulk", "list", "junk", "auto_reply"}


def is_autoreply(doc) -> bool:
    auto = (doc.get("Auto-Submitted") or "").strip().lower()
    return bool(auto) and auto != "no"


def same_org(a: str, b: str) -> bool:
    """Do two hosts or domains belong to the same organisation?"""
    if not a or not b:
        return False
    return org_domain(a) == org_domain(b)


def public_suffix(host: str) -> str:
    """The part of ``host`` that org_domain() treats as the suffix."""
    org = org_domain(host)
    labels = org.split(".")
    return ".".join(labels[1:]) if len(labels) > 1 else ""


def significant_labels(host: str) -> list[str]:
    """Labels of ``host`` excluding the public suffix.

    Script analysis has to skip the suffix: every domain under .com or .ru
    contains Latin letters there, so including it makes every
    internationalised domain look like Latin/Cyrillic mixing.
    """
    host = host.lower().strip(".")
    suffix = public_suffix(host)
    labels = [p for p in host.split(".") if p]
    if suffix:
        drop = len(suffix.split("."))
        labels = labels[:-drop] if drop < len(labels) else labels
    return labels


def skeleton(text: str) -> str:
    """Map confusable characters to their Latin twins."""
    return "".join(CONFUSABLES.get(c, c) for c in text.lower())


def resembles_brand(label: str, max_distance: int = 1) -> tuple[str, int] | None:
    """Does a label reduce to something that looks like a known brand?"""
    reduced = skeleton(label)
    if not reduced or len(reduced) < 4:
        return None
    best = None
    for target in IMPERSONATION_TARGETS:
        stem = target.split(".")[0]
        if abs(len(reduced) - len(stem)) > 1:
            continue
        distance = edit_distance(reduced, stem)
        if distance <= max_distance and (best is None or distance < best[1]):
            best = (target, distance)
    return best


def brand_family(stem: str) -> set[str]:
    return BRAND_FAMILIES.get(stem, {stem})


def is_forwarded(doc) -> bool:
    """Signs the message was relayed by an alias or forwarder.

    SPF is evaluated against the envelope sender, which a forwarder
    rewrites, so a mismatch between the authenticated domain and the From
    domain is the expected outcome of forwarding rather than evidence of
    anything. ARC exists precisely to carry the original result across
    that boundary.
    """
    if doc.get("ARC-Seal") or doc.get("ARC-Authentication-Results"):
        return True
    for header in ("X-Forwarded-For", "X-Forwarded-To", "Resent-From",
                   "X-Original-To", "Delivered-To"):
        if doc.get(header):
            return True
    return False
