# DEV-010 修复响应：mcgrps 局部用途匹配

问题编号：DEV-010。严重度：高。归属与发现方：Developer。

归属：Developer。实现与发现过程见[汇总自检记录](../2026-10-07-development-selfchecks.md)。状态：实现已修复，待冻结和独立复核；原问题保持 open。

修复 commit：尚未提交。完整基础 commit `3d0f8b937a74830f4d5d18cd37b886db442a456b`，探索源树 SHA-256 `96b835a5d924600c51fa48af48c93321d084cb56ca729703a315a125eae91ed2`。实例与产物 SHA-256：

| 产物 | Build ID 与实例 instance_id | SHA-256 |
| --- | --- | --- |
| `re_kernel_8.0.0.kpm` | `re_kernel-8.0.0+g96b835a5d924.re0dad127.kpb51197a.ndk26.3.11579264#1` | `fff040fea826843a977d9a057ccd6bcdad2e641f43a6f27d7fd3dc21d7e23f35` |
| `re_kernel_8.0.0_debug.kpm` | `re_kernel-8.0.0_debug+g96b835a5d924.rda3e2da2.kpb51197a.ndk26.3.11579264#1` | `08725e6ac091958caadffe1da9667d716ae8b3153628baaeb86f726df3a0956c` |

规则从首个 family 指针读取改为固定局部范围中的“64 位读取 → 同加载结果寄存器参与 SXTW #4 数组寻址 + 事件参数 8”。首次指针缺失后索引 91 及新窗口内的无关读取均报错，缓存保持原值；前置旧读取被覆盖时取得真实读取。五份原授权语料偏移匹配，235 项负例拒绝。新增公共解码宏按 ARM64 汇编器编码核对。

## 证据

```bash
python3 re_kernel/tools/test_genl_offsets.py --evidence local/rekernel-x-feasibility-20261002-01 \
  --image kernel_4.4 --image kernel_4.9 --image kernel_4.9_miui \
  --image kernel_4.14 --image kernel_4.19 --output <新的结果文件>
python3 re_kernel/tools/test_genl.py --output <新的空目录>
```

五份语料各 7 字段匹配、47 个负例通过；base/network/指令宏 ASan/UBSan 通过。原索引 91 反例及相邻旧指针诱饵均在生产 C 推导中复现和核对。

相关生产 C 自检结果见[汇总记录](../2026-10-07-development-selfchecks.md)。本响应保留本次修复的探索身份和哈希。这是 Developer exploration 自检，未提供独立审计、冻结候选或真机结论。请发现方在后续冻结身份上复核并决定关闭；本响应不改变问题单状态。
