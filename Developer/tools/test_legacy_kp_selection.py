#!/usr/bin/env python3
"""Explicit inventories preserve the historical four-artifact Oracle."""
from pathlib import Path
import tempfile
from test_legacy_kp_metadata import select_sources


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        pair = ['zram_zstd_1.2.0.kpm', 'zram_zstd_1.2.0_baselines.kpm']
        for name in pair:
            (root / name).touch()
        assert [p.name for p in select_sources(root, pair)] == sorted(pair)
        try:
            select_sources(root)
        except AssertionError:
            pass
        else:
            raise AssertionError('historical four-artifact contract was weakened')
        for names in ([], pair + pair, ['missing.kpm'], ['../escape.kpm'], ['bad_legacy.kpm']):
            try:
                select_sources(root, names)
            except ValueError:
                pass
            else:
                raise AssertionError(names)
        for name in ('zram_zstd_1.2.0_debug.kpm', 'zram_zstd_1.2.0_baselines_debug.kpm'):
            (root / name).touch()
        assert len(select_sources(root)) == 4
        assert [p.name for p in select_sources(root, pair)] == sorted(pair)
    print('PASS: historical four-artifact default and exact named inventory; missing/duplicate/path/legacy rejection')


if __name__ == '__main__':
    main()
