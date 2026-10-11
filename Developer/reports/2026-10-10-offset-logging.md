# 偏移推导日志整理

Developer；2026-10-10。删除 rek、rekx、hosts_redirect、dont_kill_freeze、cgroupv2_freeze 中扫描时逐条输出函数指令的 45 处 CONFIG_DEBUG 日志块。保留偏移推导、扫描窗口、函数地址、偏移结果与业务日志；五份源码与修改前的差异逐项核对仅为这些日志块。

本轮构建 11 份探索 KPM：rek、rekx 各四种模式，其他三个模块各 debug。rek、rekx 两份普通动态版及四份静态基线字节保持一致，两份动态 debug 和另外三份 debug 的体积减小。Genl/锚点/Binder 状态及清理宿主测试、双模式 ELF 与补丁自检通过；测试源码及断言未变。regular 门禁 16/16 通过，既有 489 个归档文件与交接清单哈希保持一致。

are-you-sure 复核为 Retain：45 处调用只输出扫描指令，移除不改变推导控制流；直接删除独立日志块即可，保留其他调试用途。按 no-negative-echo 回读修改源码、清单和本记录，respect-the-oracle 核对判据保持原样。

这是 Developer 构建及 Tier-3 宿主自检，不作为独立审计或实机结论。本轮未提交、未冻结，未操作镜像或设备。私有证据：`local/debug-offset-logs-z6yyz_24/`。

源码基准：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true、kind=exploration。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；工具链：NDK 26.3.11579264。rek、rekx 目标 `all debug -j4`；其他模块目标 `debug`。各模块清单位于 `handoffs/<模块>-20261010-offset-logging-exploration.json`。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| `re_kernel_11.7.kpm` | `re_kernel-11.7+ga7059e0c204b.r1cb7ab9b.kpb51197a.ndk26.3.11579264#1` | `72afa556eee88ac418efec8c0b22e455a88cdcb233fc3c9cdb8e4762830767d7` |
| `re_kernel_11.7_baselines.kpm` | `re_kernel-11.7_baselines+ga7059e0c204b.r68f66140.kpb51197a.ndk26.3.11579264#1` | `a54945f94f1fe7b8c11882204f15099681e2d8136f590e4394ef59a69a4b80ba` |
| `re_kernel_11.7_baselines_debug.kpm` | `re_kernel-11.7_baselines_debug+ga7059e0c204b.r6e3b3280.kpb51197a.ndk26.3.11579264#1` | `3f3e70d7b73cd68317e7d1457446cf6603a47cd147c2999361e1ab437dfbca1b` |
| `re_kernel_11.7_debug.kpm` | `re_kernel-11.7_debug+ga7059e0c204b.r62edf3bb.kpb51197a.ndk26.3.11579264#1` | `bda0fc86b7eb03489b3e6cef46420417cadd52ce61472d492fafdc32c0374b2d` |
| `re_kernel_x_1.6-20261008.kpm` | `re_kernel_x-1.6-20261008+g6a7fdf487d1f.r2743a85d.kpb51197a.ndk26.3.11579264#1` | `edff9d8c00afb220f04e65aede455219e6b9d0c5a89c23783cecb49196097331` |
| `re_kernel_x_1.6-20261008_baselines.kpm` | `re_kernel_x-1.6-20261008_baselines+g6a7fdf487d1f.r1e3a0ecf.kpb51197a.ndk26.3.11579264#1` | `023bbae5af28bf5d982aaaf880943c8f5ecf66014165538eb5d7e81c47bf7d69` |
| `re_kernel_x_1.6-20261008_baselines_debug.kpm` | `re_kernel_x-1.6-20261008_baselines_debug+g6a7fdf487d1f.rfa83dd93.kpb51197a.ndk26.3.11579264#1` | `ade02e8bd50326d3d663d2360fe5ea7a5577ef7fd60e47d059551ef9c35f88f9` |
| `re_kernel_x_1.6-20261008_debug.kpm` | `re_kernel_x-1.6-20261008_debug+g6a7fdf487d1f.r2e52278e.kpb51197a.ndk26.3.11579264#1` | `a62317e8083e05c3a6ae711db299314e712cbb1ef21d25dde34cb3457989fd9c` |
| `hosts_redirect_2.0.0_debug.kpm` | `hosts_redirect-2.0.0_debug+g127ff5013d61.rc065ce4f.kpb51197a.ndk26.3.11579264#1` | `b5c8cb51e95e92168c639fe353da49311f9e3684a5be9bbce54a2f6ed1a23767` |
| `dont_kill_freeze_1.0.2_debug.kpm` | `dont_kill_freeze-1.0.2_debug+g940e265e2336.r5f3221d9.kpb51197a.ndk26.3.11579264#1` | `396ddf38cd0c98587a8d2903cb2d4f1618f652a440960dbf3a74859837d3bb68` |
| `cgroupv2_freeze_1.0.12_debug.kpm` | `cgroupv2_freeze-1.0.12_debug+g4e33886a317b.rd8aa4760.kpb51197a.ndk26.3.11579264#1` | `ae1428f095a369b0ba67e7e5656b46a2c1c76a7f22ba1fbd44130c26977f18bd` |
