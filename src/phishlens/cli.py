"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phishlens import __version__
from phishlens.parse import EmailDoc
from phishlens.report import (
    findings_report,
    iocs_report,
    json_report,
    tree_report,
)
from phishlens.rules import run_all
from phishlens.view import build_tree


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="Interactive analysis lens for .eml files.",
        epilog="With no output flag, phishlens opens the interactive browser.",
    )
    parser.add_argument("file", type=Path, help="path to a .eml message")
    parser.add_argument("--version", action="version",
                        version=f"phishlens {__version__}")

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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.file.is_file():
        print(f"phishlens: {args.file}: no such file", file=sys.stderr)
        return 2

    try:
        doc = EmailDoc.from_path(args.file)
    except (OSError, ValueError) as exc:
        print(f"phishlens: cannot parse {args.file}: {exc}", file=sys.stderr)
        return 1

    findings = run_all(doc)

    from phishlens.model import Severity
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
            from phishlens.tui.app import run as run_tui
        except ImportError:
            print(
                "phishlens: textual is not installed, so the interactive "
                "browser is unavailable.\n"
                "Install it with 'pip install textual', or use --findings, "
                "--json, --iocs or --tree.",
                file=sys.stderr,
            )
            return 1
        run_tui(doc, findings)

    # Exit non-zero when something worth acting on was found, so the tool
    # composes with shell conditionals and CI.
    from phishlens.model import Severity as S
    return 1 if any(f.severity.rank >= S.HIGH.rank for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
