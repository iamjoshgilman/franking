#!/usr/bin/env python3
"""Regenerate docs/RULES.md from the rule registry.

Hand-maintained documentation of 41 rules drifts within a week, so the
catalogue is generated. Run after adding or renaming a rule; there is a
test asserting the file is current.

    python tools/gen_rules_doc.py           # write docs/RULES.md
    python tools/gen_rules_doc.py --check   # fail if it would change
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from franking.rules import catalogue  # noqa: E402

TARGET = ROOT / "docs" / "RULES.md"

SECTION_TITLES = {
    "attach": "Attachments and archives",
    "auth": "SPF, DKIM, DMARC and ARC",
    "content": "Body text and links",
    "identity": "Impersonation and deception",
    "routing": "Received chain and addresses",
    "sender": "The sending domain itself",
}


def render() -> str:
    rules = catalogue()
    by_module: dict[str, list] = {}
    for info in rules:
        by_module.setdefault(info.module, []).append(info)

    out = [
        "# Rule catalogue",
        "",
        "Generated from the registry -- do not edit by hand.",
        "Regenerate with `python tools/gen_rules_doc.py`.",
        "",
        f"{len(rules)} rules. Severity drives the summary verdict and the",
        "`--min-severity` filter; see CONTRIBUTING.md for how these are",
        "calibrated against real mail.",
        "",
    ]
    for module in sorted(by_module):
        out.append(f"## {SECTION_TITLES.get(module, module)} "
                   f"(`rules/{module}.py`)")
        out.append("")
        out.append("| ID | Severity | Title | ATT&CK |")
        out.append("| --- | --- | --- | --- |")
        for info in by_module[module]:
            mitre = ", ".join(f"`{m}`" for m in info.mitre) or "—"
            out.append(f"| `{info.id}` | {info.severity.value} | "
                       f"{info.title} | {mitre} |")
        out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero if the file is out of date")
    args = parser.parse_args()

    content = render()
    if args.check:
        current = TARGET.read_text() if TARGET.exists() else ""
        if current != content:
            print(f"{TARGET} is out of date; run tools/gen_rules_doc.py",
                  file=sys.stderr)
            return 1
        return 0

    TARGET.parent.mkdir(exist_ok=True)
    TARGET.write_text(content)
    print(f"wrote {TARGET} ({len(catalogue())} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
