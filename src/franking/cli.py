"""Command line entry point."""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

from franking import __version__
from franking.parse import EmailDoc
from franking.report import (
    findings_report,
    iocs_report,
    json_report,
    tree_report,
)
from franking.rules import catalogue, run_all
from franking.view import build_tree


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="franking",
        description="Interactive analysis lens for .eml files.",
        epilog="With no output flag, franking opens the interactive browser.",
    )
    parser.add_argument("file", type=Path, nargs="?",
                        help="path to a .eml message")
    parser.add_argument("--rules", action="store_true",
                        help="list every detection rule and exit")
    parser.add_argument("--version", action="version",
                        version=f"franking {__version__}")

    out = parser.add_argument_group("output modes")
    out.add_argument("--findings", action="store_true",
                     help="print the findings report and exit")
    out.add_argument("--json", action="store_true",
                     help="print the full analysis as JSON and exit")
    out.add_argument("--iocs", action="store_true",
                     help="print extracted indicators and exit")
    out.add_argument("--tree", action="store_true",
                     help="print the section tree and exit")

    tweak = parser.add_argument_group("output tuning")
    tweak.add_argument(
        "--wrapper", action="store_true",
        help="analyse the covering message rather than the one attached to "
             "it; by default a forwarded report is unwrapped to the message "
             "being reported",
    )
    tweak.add_argument("--no-color", action="store_true",
                       help="disable ANSI colour")
    tweak.add_argument("--no-evidence", action="store_true",
                       help="omit evidence lines from the findings report")
    tweak.add_argument("--depth", type=int, default=2,
                       help="depth for --tree (default: 2)")
    tweak.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="hide findings below this severity (default: info)",
    )
    return parser


def rules_catalogue() -> str:
    """The rule set as a table, generated from the registry itself.

    Documentation written by hand drifts from the code; this cannot.
    """
    rules = catalogue()
    width = max(len(r.title) for r in rules)
    lines = [f"{len(rules)} rules", ""]
    current = None
    for info in rules:
        if info.module != current:
            current = info.module
            lines.append(f"-- {current} " + "-" * (width - len(current) + 4))
        mitre = ", ".join(info.mitre) or "--"
        lines.append(f"{info.id:<9} {info.severity.value:<8} "
                     f"{info.title:<{width}}  {mitre}")
    return "\n".join(lines)


def _use_utf8_output() -> None:
    """Stop Windows consoles from crashing on the characters that matter.

    Reports carry the raw non-ASCII found in the message, which is the point:
    Cyrillic homoglyphs in a lookalike domain are evidence. On Windows the
    default stdout encoding is the console code page, so printing them raises
    UnicodeEncodeError and takes the whole run down. errors="replace" means a
    legacy console degrades to '?' instead of dying.
    """
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, OSError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _use_utf8_output()
    args = build_parser().parse_args(argv)

    if args.rules:
        print(rules_catalogue())
        return 0
    if args.file is None:
        build_parser().print_usage(sys.stderr)
        print("franking: a file is required unless --rules is given",
              file=sys.stderr)
        return 2

    if not args.file.is_file():
        print(f"franking: {args.file}: no such file", file=sys.stderr)
        return 2

    try:
        doc = EmailDoc.from_path(args.file)
    except (OSError, ValueError) as exc:
        print(f"franking: cannot parse {args.file}: {exc}", file=sys.stderr)
        return 1

    # A reported phish arrives attached to a covering note. Analysing the
    # note tells you about the employee who reported it, which is never
    # the question being asked.
    outer = doc
    if doc.nested and not args.wrapper:
        doc = doc.innermost()
        if not args.json:
            print(
                f"franking: unwrapped {outer.subject or '(no subject)'!r} "
                f"to the message attached to it "
                f"(--wrapper to analyse the covering message instead)",
                file=sys.stderr,
            )

    findings = run_all(doc)

    from franking.model import Severity
    floor = Severity(args.min_severity).rank
    findings = [f for f in findings if f.severity.rank >= floor]

    colour = not args.no_color and sys.stdout.isatty()

    if args.json:
        print(json_report(doc, findings))
    elif args.findings:
        print(findings_report(doc, findings, colour=colour,
                              show_evidence=not args.no_evidence))
    elif args.iocs:
        print(iocs_report(doc, findings))
    elif args.tree:
        print(tree_report(build_tree(doc, findings), max_depth=args.depth))
    else:
        try:
            from franking.tui.app import run as run_tui
        except ImportError:
            print(
                "franking: textual is not installed, so the interactive "
                "browser is unavailable.\n"
                "Install it with 'pip install textual', or use --findings, "
                "--json, --iocs or --tree.",
                file=sys.stderr,
            )
            return 1
        run_tui(doc, findings)

    # Exit non-zero when something worth acting on was found, so the tool
    # composes with shell conditionals and CI.
    from franking.model import Severity as S
    return 1 if any(f.severity.rank >= S.HIGH.rank for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
