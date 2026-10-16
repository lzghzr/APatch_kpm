# 当前 NoMount 动态候选的 4.4 兼容派生件

按维护者[追加请求](../../../docs/records/2026-10-15-nomount-4.4-probe-bound-request.md)，本轮4.4复测采用由动态候选`1ab36727…`转换的派生件。该父件已包含TST-001修复。

## 身份与产物

| 项 | 值 |
| --- | --- |
| 源码commit | `ebad05883bcd6173d5e2a867559aa6bcb3e45810` |
| 父实例 | `nomount-2.1.1-20261014+g9f323cd3deaa.r33de5496.kpb51197a.ndk26.3.11579264#1` |
| 父KPM SHA-256 | `1ab36727b82cab1723da56f6f82273ff1fee57071836b8992f4e3d26ad40e1fa` |
| 派生SHA-256 | `06bd68500f2d6f9725038499a16bca1f54e88f1cde3c21f2dc95aa96f276d8ee` |
| 派生大小 | 221728字节 |
| 转换工具SHA-256 | `97a51b293af447b3cd6608c953cec95cdfc62f985346463f2285b28ab3c86033` |
| compat收据SHA-256 | `c0ef4a4ac95e4938dea6f825fb01cec0f263db2fce039c5631473ceb64a54dc2` |

[4.4待测KPM](../../../artifacts/binary-port/nomount/06bd68500f2d6f9725038499a16bca1f54e88f1cde3c21f2dc95aa96f276d8ee/NoMount_2.1.1-20261014.kpm)；[专用交接清单](../handoffs/2026-10-15-nomount-current-dynamic-legacy.json)；[开发者字节自检](../data/2026-10-15-nomount-current-dynamic-legacy.json)。清单含父实例、父件身份、目标镜像、转换工具与完整命令、派生身份及compat收据。

目标为`B2N-416G_boot.img`／`4.4.192-perf+`／旧KP `0xd04`，加载参数留空，测试加载时机为`pre-kernel-init`。boot镜像及裸内核哈希在清单中分别绑定。

## 生成与复核

使用现有`patch_offsets.py legacy-kp`在新输出目录重新生成，输出为`06bd6850…`，与哈希归档目录内已有的对应派生字节及收据逐字节一致；保留归档原文件。本次补交独立的`binary_ports[]`清单，方便维护者登记这份动态兼容件。

转换仅将后缀查找调用转接至旧KP的`kallsyms_lookup_name`函数指针。自检复核父件candidate身份、原代码／数据／重定位不变、模块信息不变、ADRP／LDR／BR x16转接与指针调用模型，以及未定义导入中已去除后缀查找依赖。工具字节与父源码冻结提交一致。

对应归档的复现命令为：

```text
python3 patch_offsets.py legacy-kp artifacts/nomount-2.1.1-20261014+g9f323cd3deaa.r33de5496.kpb51197a.ndk26.3.11579264/NoMount_2.1.1-20261014.kpm --output artifacts/binary-port/nomount/06bd68500f2d6f9725038499a16bca1f54e88f1cde3c21f2dc95aa96f276d8ee/NoMount_2.1.1-20261014.kpm
```

归档已存在时工具会拒绝覆盖；本轮实际新输出命令记录在清单的`regeneration.command`。基础KPM、源码、Makefile及既有测试均未修改。

## 方案复核

**保留（Retain）。** 有效性：重新生成字节与指定父件的转换收据一致，原程序内容保留。简洁性：现有二进制转换入口即可完成，不需要重建基础候选。后果：原名查找替代后缀查找，目标实际符号与原生加载行为仍须由Tester验证；该检查不构成实机结论。

## 交接

请维护者登记专用清单后，按已追加的Auditor范围复核TST-001和当前候选，再由Tester使用本报告的`06bd6850…`测试4.4加载及用户主路径，并一并复测DEV-042。当前候选的静态等价判断仍归尾部锚点轮审计，本次仅交付动态兼容派生件。

本响应为Developer自检与交接，没有操作设备，也不关闭TST-001／DEV-042／AUD-001。已按are-you-sure、no-negative-echo和respect-the-oracle复核本轮文件，原始证据和测试断言保留。
