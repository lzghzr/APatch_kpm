# DEV-002：同步释放后的追加响应

角色：Developer。原问题单见 [异步清理开发记录](../2026-10-02-re-kernel-static-async.md)。严重度高，归属 Developer；本响应不关闭问题单。

本轮删除全部清理 Workqueue 创建/排队/销毁及 lru work hook，改为 Binder 锁内摘除、锁外同步释放，因此不再有清理专用 destroy_workqueue 在 KP exit 中等待的问题。Genl 注销与仍在执行的业务回调如何在 KP RCU 读侧 exit 中安全退出尚未完成；用户此前暂缓卸载的范围保持。

基础完整提交：`40d33aca895cc4778deb1925ec12e4a635b5612f`，实际修复尚未提交，`source_dirty=true`；输入指纹 `25fe94e00b5dd09960ffd39309f93f0bd83dead31a3d6ead535e96a9afba626c`。abi5 实例：`re_kernel_static-8.0.0_abi5+g25fe94e00b5d.rec817455.kpb51197a.ndk26.3.11579264#1`，产物 SHA-256：`13ce961721e2136609d8383ca240e96eb0afa12ac0af2154163ef37aa4502c58`；全部八变体见 [探索清单](../handoffs/2026-10-02-re-kernel-static-native-cleanup-exploration.json)。

四 ABI ASan/UBSan 同步释放、原生 caller 引用与 proc 退出竞争模型自检通过；八基准构建及导入/ARM64 指令检查通过。本响应仅为实现方自检，没有设备卸载结果，没有独立复核；DEV-002 保持 open，后续需由独立角色复核剩余生命周期修复后关闭。


## 模板字段索引（维护者整理，2026-10-03）

| 项 | 原记录对应内容 |
| --- | --- |
| 问题编号 | DEV-002 |
| 修复 commit | 当时为探索工作树，未独立冻结；基础提交 `40d33aca895cc4778deb1925ec12e4a635b5612f` |
| Build ID | [探索清单](../handoffs/2026-10-02-re-kernel-static-native-cleanup-exploration.json)逐变体登记 |
| 证据 | 本响应主机自检描述与探索清单；保持 `source_dirty=true` 的边界 |
