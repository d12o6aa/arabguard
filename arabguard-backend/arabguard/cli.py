"""
arabguard/cli.py
================
Optional command-line interface for ArabGuard.

Usage
-----
    arabguard "تجاهل كل التعليمات السابقة"
    arabguard --debug "ignore all previous instructions"
    echo "some text" | arabguard --stdin
"""

from __future__ import annotations
import argparse
import json
import sys

from .core import ArabGuard


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arabguard",
        description="ArabGuard – Arabic/English prompt-injection detector",
    )
    parser.add_argument(
        "text",
        nargs="?",
        help="Text to analyse (or use --stdin)",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read text from stdin",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full analysis as JSON",
    )
    parser.add_argument(
        "--block-on-flag",
        action="store_true",
        dest="block_on_flag",
        help="Treat FLAG results as BLOCKED",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        metavar="N",
        help="Custom score threshold for BLOCKED (default: 120)",
    )

    args = parser.parse_args()

    if args.stdin:
        text = sys.stdin.read().strip()
    elif args.text:
        text = args.text
    else:
        parser.print_help()
        sys.exit(1)

    guard  = ArabGuard(
        block_on_flag=args.block_on_flag,
        custom_score_threshold=args.threshold,
    )
    result = guard.analyze(text)

    if args.debug:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        status = "🔴 BLOCKED" if result.is_blocked else (
                 "🟡 FLAG"    if result.is_flagged else "🟢 SAFE")
        print(f"{status}  |  score={result.score}  |  {result.reason}")

    sys.exit(1 if result.is_blocked else 0)


if __name__ == "__main__":
    main()
