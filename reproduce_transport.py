"""Rebuild the separately bounded context-transport evidence."""
import argparse
import json
from pathlib import Path
from rcsc.transport_experiment import run_transport
if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parent/'results')
    args=parser.parse_args()
    print(json.dumps(run_transport(args.output, Path(__file__).resolve().parent/'results'),indent=2,sort_keys=True))
