"""Regenerate the complete RCSC evidence bundle."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from rcsc.experiment import run_all


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "results",
        help="directory for generated JSON/CSV evidence (default: artifact/results)",
    )
    parser.add_argument(
        "--per-family",
        type=int,
        default=40,
        help="number of generated pairs per vulnerability family (default: 40)",
    )
    args = parser.parse_args()
    if not 1 <= args.per_family <= 47:
        parser.error("--per-family must be between 1 and 47 (600 retained-pair cap)")
    return args


def main() -> None:
    args = parse_args()
    summary = run_all(args.output.resolve(), per_family=args.per_family)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
