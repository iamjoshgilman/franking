"""The rule registry.

A rule is a function that looks at a parsed :class:`~franking.parse.EmailDoc`
and either stays quiet or emits one or more :class:`~franking.model.Finding`
objects. Rules are registered by decorating them::

    @rule("AUTH001", "Short title", Severity.HIGH, mitre=["T1656"])
    def my_rule(doc, emit):
        if something_wrong(doc):
            return emit("What it means", evidence=[Evidence("Header", value)])

``emit`` is a factory pre-loaded with the decorator's metadata, so the body
only has to supply what varies.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from franking.model import Evidence, Finding, Severity
from franking.parse import EmailDoc

RuleFn = Callable[[EmailDoc], list[Finding]]
_REGISTRY: dict[str, RuleFn] = {}


def rule(
    rule_id: str,
    title: str,
    severity: Severity,
    mitre: Iterable[str] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a rule function under ``rule_id``."""

    mitre_ids = list(mitre)

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def emit(
            detail: str,
            evidence: Iterable[Evidence] = (),
            *,
            severity_override: Severity | None = None,
            title_override: str | None = None,
        ) -> Finding:
            return Finding(
                id=rule_id,
                title=title_override or title,
                severity=severity_override or severity,
                detail=detail,
                evidence=list(evidence),
                mitre=list(mitre_ids),
            )

        def runner(doc: EmailDoc) -> list[Finding]:
            result = fn(doc, emit)
            if result is None:
                return []
            if isinstance(result, Finding):
                return [result]
            return list(result)

        runner.__name__ = fn.__name__
        runner.__doc__ = fn.__doc__
        if rule_id in _REGISTRY:
            raise ValueError(f"duplicate rule id: {rule_id}")
        _REGISTRY[rule_id] = runner
        return fn

    return decorator


def run_all(doc: EmailDoc) -> list[Finding]:
    """Run every registered rule, most severe first."""
    findings: list[Finding] = []
    for runner in _REGISTRY.values():
        findings.extend(runner(doc))
    findings.sort(key=lambda f: (-f.severity.rank, f.id))
    return findings


def registered_ids() -> list[str]:
    return sorted(_REGISTRY)


# Importing the rule modules is what populates the registry.
from franking.rules import attach, auth, content, routing  # noqa: E402,F401

__all__ = ["rule", "run_all", "registered_ids", "Evidence", "Severity"]
