#!/usr/bin/env python3
"""沿用静态 Oracle 的全部断言，以当前生产文件的完整静态边界生成夹具。"""
from pathlib import Path
import re


def main():
    original_path = Path(__file__).with_name('test_static_targets.py')
    original = original_path.read_text()
    before = ".split('#ifndef CONFIG_KPM_BASELINES', 1)[0]"
    after = ".split('\\n#ifndef CONFIG_KPM_BASELINES\\n#include \"nm_btf.c\"', 1)[0]"
    assert original.count(before) == 1
    source = original.replace(before, after, 1)
    before = "    c = '''#include <stdint.h>"
    assert source.count(before) == 1
    source = source.replace(before, "    c = '''#define CONFIG_KPM_BASELINES 1\n#include <stdint.h>", 1)
    # 此夹具只编译布局访问器；静态版新增的原生ABI查询另由BTF/控制入口自检。
    include = '#ifdef CONFIG_KPM_BASELINES\n// 静态偏移保持表值；新接入的 idmap 控制入口仍需验证原生函数 ABI。\n#include "nm_btf.c"\n#endif\n'
    before = "    source = source.replace('__attribute__"
    at = source.index(before)
    source = source[:at] + '    source = source.replace(' + repr(include) + ', "")\n' + source[at:]
    # 文件内部的动态容量门不再是顶层静态区的终点；原 C/Python 断言逐字保留。
    assert re.findall(r'\bassert[^\n]+', source) == re.findall(r'\bassert[^\n]+', original)
    exec(compile(source, str(original_path), 'exec'), {'__name__': '__main__', '__file__': str(original_path)})


if __name__ == '__main__':
    main()
