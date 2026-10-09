#!/usr/bin/env python3
"""Measure franking against a corpus of real mail.

Synthetic fixtures inherit the blind spots of whoever wrote them. This
runs the rule set over thousands of real messages and reports the two
numbers that matter:

  ham    -- what fraction of *legitimate* mail produces a finding, and
            which rules are responsible. Anything firing here is noise.
  phish  -- what fraction of real phishing produces a finding, and which
            rules carry the detection.

Crashes are reported separately. Several thousand real messages is a
better robustness test than any fuzzer we would write by hand.

    python tools/corpus.py ham   ~/Projects/franking-corpora/ham
    python tools/corpus.py phish ~/Projects/franking-corpora/phishing_pot
"""

from __future__ import annotations

import argparse
import collections
import multiprocessing
import random
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from franking.model import Severity  # noqa: E402
from franking.parse import EmailDoc  # noqa: E402
from franking.rules import run_all  # noqa: E402

TIMEOUT_SECONDS = 20


def analyse(path: Path) -> dict:
    """Analyse one message, never raising."""
    try:
        doc = EmailDoc.from_path(path)
        if doc.nested:
            doc = doc.innermost()
        findings = run_all(doc)
    except Exception:  # noqa: BLE001 - the point is to catch everything
        return {
            "path": str(path),
            "error": traceback.format_exc(limit=3).strip().splitlines()[-1],
        }
    return {
        "path": str(path),
        "rules": [(f.id, f.severity.value) for f in findings],
        "worst": max((f.severity.rank for f in findings), default=-1),
    }


def collect(root: Path, limit: int | None, seed: int) -> list[Path]:
    # Corpora name files in whatever way they like -- SpamAssassin uses
    # "0051.6977edf4fd92543b1c9af246ebdc00cb" -- so exclude what is
    # obviously not mail rather than trying to recognise what is.
    skip_names = {"cmds", "readme", "license", "index"}
    skip_suffixes = {".md", ".json", ".py", ".sh", ".yml", ".yaml", ".toml",
                     ".gitignore", ".png", ".jpg", ".pdf", ".tar", ".bz2",
                     ".gz", ".zip", ".html", ".csv"}
    files = [
        p for p in root.rglob("*")
        if p.is_file()
        and not p.name.startswith(".")
        and ".git/" not in str(p)
        and p.name.lower() not in skip_names
        and p.suffix.lower() not in skip_suffixes
    ]
    files.sort()
    if limit and len(files) > limit:
        random.Random(seed).shuffle(files)
        files = files[:limit]
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["ham", "phish"],
                        help="ham: nothing should fire. phish: something should.")
    parser.add_argument("root", type=Path)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--floor", default="medium",
                        choices=[s.value for s in Severity],
                        help="severity at or above which a message counts as flagged")
    parser.add_argument("--show", type=int, default=0,
                        help="print this many example paths per rule")
    parser.add_argument("--jobs", type=int,
                        default=min(16, multiprocessing.cpu_count()))
    args = parser.parse_args()

    files = collect(args.root, args.limit, args.seed)
    if not files:
        print(f"no files under {args.root}", file=sys.stderr)
        return 2
    floor = Severity(args.floor).rank

    print(f"{len(files)} messages from {args.root}", file=sys.stderr)
    with multiprocessing.Pool(args.jobs) as pool:
        results = []
        for i, item in enumerate(pool.imap_unordered(analyse, files, 64), 1):
            results.append(item)
            if i % 1000 == 0:
                print(f"  {i}/{len(files)}", file=sys.stderr)

    errors = [r for r in results if "error" in r]
    ok = [r for r in results if "error" not in r]
    flagged = [r for r in ok if r["worst"] >= floor]

    by_rule: collections.Counter = collections.Counter()
    examples: dict[str, list[str]] = collections.defaultdict(list)
    for r in ok:
        for rule_id, severity in {(i, s) for i, s in r["rules"]}:
            if Severity(severity).rank >= floor:
                by_rule[rule_id] += 1
                if len(examples[rule_id]) < max(args.show, 3):
                    examples[rule_id].append(r["path"])

    total = len(ok) or 1
    print()
    print(f"corpus      {args.root}")
    print(f"parsed      {len(ok)} / {len(results)}")
    print(f"crashed     {len(errors)}")
    label = "FALSE POSITIVES" if args.kind == "ham" else "DETECTED"
    print(f"{label:11} {len(flagged)} ({100 * len(flagged) / total:.1f}%) "
          f"at >= {args.floor}")
    print()

    if by_rule:
        header = "rule       messages    rate  "
        print(header)
        print("-" * len(header))
        for rule_id, count in by_rule.most_common():
            print(f"{rule_id:<10} {count:>8}  {100 * count / total:>5.1f}%")
            for path in examples[rule_id][:args.show]:
                print(f"           {path}")

    if errors:
        print()
        print(f"CRASHES ({len(errors)})")
        counts = collections.Counter(e["error"] for e in errors)
        for message, count in counts.most_common(10):
            print(f"  {count:>5}  {message[:110]}")
            sample = next(e["path"] for e in errors if e["error"] == message)
            print(f"         e.g. {sample}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
