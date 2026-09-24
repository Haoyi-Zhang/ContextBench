"""Verify one bounded JSON pair, source-bound pair, or transformation packet."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import sys
from typing import Any

from rcsc.checker import check_pair
from rcsc.model import validate_json_tree
from rcsc.source_bridge import check_source_pair
from rcsc.transform import check_transform
from rcsc.transport import check_transport

MAX_PACKET_BYTES = 2 * 1024 * 1024
DEADLINE_SECONDS = 15


def _unique_object(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError('duplicate JSON object key')
        out[key] = value
    return out


def _integer(text: str) -> int:
    if len(text.lstrip('-')) > 78:
        raise ValueError('integer literal exceeds the admitted bound')
    value = int(text)
    if value.bit_length() > 256:
        raise ValueError('integer literal exceeds the admitted bound')
    return value


def _noninteger(text: str):
    raise ValueError('floating-point and nonfinite literals are outside the fragment')


def load_packet(path: Path) -> dict[str, Any]:
    with path.open('rb') as handle:
        data = handle.read(MAX_PACKET_BYTES + 1)
    if len(data) > MAX_PACKET_BYTES:
        raise ValueError('packet exceeds the byte limit')
    value = json.loads(data, object_pairs_hook=_unique_object, parse_int=_integer,
                       parse_float=_noninteger, parse_constant=_noninteger)
    validate_json_tree(value)
    if type(value) is not dict:
        raise ValueError('packet must be a JSON object')
    return value


def verify_packet(kind: str, packet: dict[str, Any]):
    if kind not in ('pair', 'source-pair', 'transform', 'transport'):
        raise ValueError('unknown certificate kind')
    if kind == 'transport':
        return check_transport(packet)
    if kind == 'pair':
        expected = {'vulnerable', 'patched', 'certificate'}
    elif kind == 'source-pair':
        expected = {
            'vulnerable_source', 'patched_source', 'vulnerable', 'patched',
            'source_certificate', 'certificate',
        }
    else:
        expected = {'source', 'target', 'certificate'}
    if set(packet) != expected:
        raise ValueError('packet fields do not match the selected certificate kind')
    if kind == 'pair':
        return check_pair(packet['vulnerable'], packet['patched'], packet['certificate'])
    if kind == 'source-pair':
        if type(packet['vulnerable_source']) is not str or type(packet['patched_source']) is not str:
            raise ValueError('source-pair source fields must be strings')
        return check_source_pair(
            packet['vulnerable_source'], packet['patched_source'],
            packet['vulnerable'], packet['patched'],
            packet['source_certificate'], packet['certificate'],
        )
    return check_transform(packet['source'], packet['target'], packet['certificate'])


def _deadline(signum, frame):
    raise TimeoutError('verification deadline exceeded')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=('pair', 'source-pair', 'transform', 'transport'))
    parser.add_argument('packet', type=Path)
    args = parser.parse_args(argv)
    # The bounded command is defined for POSIX. Do not silently omit its deadline.
    if not hasattr(signal, 'SIGALRM'):
        print(json.dumps({'accepted': False, 'reason': 'unsupported-deadline-platform'}))
        return 2
    previous = signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(DEADLINE_SECONDS)
    try:
        report = verify_packet(args.kind, load_packet(args.packet))
        result = report.to_json()
        code = 0 if report.accepted else 1
    except (ValueError, TypeError, OSError, UnicodeError, RecursionError, TimeoutError, MemoryError) as exc:
        result = {'accepted': False, 'reason': 'input-or-resource-error', 'diagnostic': str(exc)}
        code = 2
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return code


if __name__ == '__main__':
    sys.exit(main())
