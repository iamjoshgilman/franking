"""Core data types shared by the parser, the rules and the views."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """How much a finding should worry you.

    Subclasses ``str`` so findings serialise to JSON without a custom encoder.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    @property
    def glyph(self) -> str:
        return _GLYPHS[self]


_RANKS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_GLYPHS = {
    Severity.CRITICAL: "✗",
    Severity.HIGH: "✗",
    Severity.MEDIUM: "⚠",
    Severity.LOW: "⚠",
    Severity.INFO: "·",
}


@dataclass
class Evidence:
    """One concrete thing in the file that supports a finding."""

    label: str
    value: str

    def as_dict(self) -> dict:
        return {"label": self.label, "value": self.value}


@dataclass
class Finding:
    """A conclusion a rule reached about the message."""

    id: str
    title: str
    severity: Severity
    detail: str
    evidence: list[Evidence] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "evidence": [e.as_dict() for e in self.evidence],
            "mitre": self.mitre,
        }


@dataclass
class Node:
    """A row in the browser.

    The TUI renders a tree of these as Miller columns, so a section, a field
    and a sub-field are all the same shape. ``value`` is what ``y`` copies;
    ``note`` is the prose that explains why the value matters.
    """

    label: str
    value: str | None = None
    note: str | None = None
    children: list[Node] = field(default_factory=list)
    severity: Severity | None = None
    badge: str | None = None
    ioc_type: str | None = None

    def add(self, *children: Node) -> Node:
        """Append children and return self, so trees can be built inline."""
        self.children.extend(children)
        return self

    @property
    def is_leaf(self) -> bool:
        return not self.children

    def as_dict(self) -> dict:
        out: dict = {"label": self.label}
        if self.value is not None:
            out["value"] = self.value
        if self.note is not None:
            out["note"] = self.note
        if self.severity is not None:
            out["severity"] = self.severity.value
        if self.children:
            out["children"] = [c.as_dict() for c in self.children]
        return out
