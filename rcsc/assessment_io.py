"""Lossless text storage for supplementary assessment records."""
import gzip

COMPRESSED = frozenset(('features.json', 'functional_domain.json',
                       'historical_functional_domain.json', 'models.json',
                       'oracle.csv', 'packets.json', 'predictions.csv', 'split_manifest.csv'))


def open_record(path, mode='r', newline=None):
    if path.name in COMPRESSED:
        path = path.with_name(path.name + '.gz')
        return gzip.open(path, mode + 't', encoding='utf-8', newline=newline)
    return path.open(mode, encoding='utf-8', newline=newline)
