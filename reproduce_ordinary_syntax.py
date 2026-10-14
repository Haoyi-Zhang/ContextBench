"""Run/check the frozen ordinary syntax comparison without altering history."""
import argparse
import json
from pathlib import Path
from rcsc.ordinary_syntax import run, check

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path('results/context_assessment'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    function = check if args.check else run
    print(json.dumps(function(args.source, args.output), indent=2, sort_keys=True))
