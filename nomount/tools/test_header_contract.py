#!/usr/bin/env python3
"""Developer: a fresh freestanding TU obtains size_t from the KP SDK."""
import argparse
from pathlib import Path
import subprocess

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--cc', required=True)
ap.add_argument('--output', type=Path, required=True)
a = ap.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
root = Path(__file__).resolve().parents[2]
source = a.output / 'sdk-size.c'
source.write_text('#include <ktypes.h>\n#include <linux/kernel.h>\n'
                  'struct sample { char first; size_t length; };\n'
                  '_Static_assert(sizeof(size_t) == 8, "ARM64 size_t");\n'
                  '_Static_assert(offsetof(struct sample, length) == 8, "SDK offsetof");\n'
                  'size_t sdk_size(void) { return sizeof(struct sample); }\n')
flags = [str(root / 'KernelPatch/kernel' / d) for d in
         ('.', 'include', 'patch/include', 'linux/include', 'linux/arch/arm64/include', 'linux/tools/arch/arm64/include')]
subprocess.run([a.cc, '-Wall', '-Werror', '-ffreestanding', '-nostdinc', *['-I' + d for d in flags],
                '-c', str(source), '-o', str(a.output / 'sdk-size.o')], check=True)
print('new SDK-only translation unit: PASS')
