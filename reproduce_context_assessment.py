"""Run the supplementary owned finite assessment; no network or native code."""
from pathlib import Path
import argparse
import json
from rcsc.context_assessment import run_assessment

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('results/context_assessment'))
    args = parser.parse_args()
    print(json.dumps(run_assessment(args.output), indent=2, sort_keys=True))
