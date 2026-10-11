# run_cmd 公共 BTF 查询

Developer；2026-10-10。来源基点 commit：`5b3dc4656b9d1653e6a38d497a1dfa78ca905cfa`。沿用前一轮偏移精简工作树，本轮接入根目录公共 BTF 查询。当前为未冻结探索，`source_dirty=true`；完整指纹与产物身份见 [构建清单](data/2026-10-10-run-cmd-common-btf-build.json) 和 [自检收据](data/2026-10-10-run-cmd-common-btf.json)。

## 复核决定（Decision）

**精简（Simplify）**。通过已有公共接口消除模块重复的类型定义与成员解析。

## 挑战

### 有效性

`kpm_btf_type()` 查询结构体类型，`kpm_btf_offset()` 已处理成员尺寸、位域、字节位置与范围。本轮删除本模块 find_btf_struct/btf_member_offset 和 run_cmd.h 内的 BTF UAPI 重复定义，直接调用这两个公共接口。局部 kpm_btf 绑定已有数据与四个查询指针；模块继续负责 worker 共同布局、LSM blob 加量、已知 security 偏移核对和字段失败时的函数推导。

### 简洁性

calculate_offsets 的 BTF 查找直接使用公共实现，模块内减少 30 行查询代码及 13 行重复类型声明。kpm_utils.h 原文件保持不变。原生 BTF 符号查找和数据生命周期仍由本模块加载流程管理，公共接口不承担业务配置。

### 后果

公共接口可遍历匿名/嵌套成员，代码段从 7408 增至 7928 字节（增加 520 字节）。新增 ELF 导入 kf_strncmp，在本次构建所用 KP 的 kernel/patch/ksyms/libs.c:70-71 已导出；其余导入集合不变。导出核对绑定本次 SDK，不代表所有运行端 KP 都相同。两份临时旧 KP 兼容件经既有 ELF 与指针转接检查通过。

## 更新后的方案

run_cmd 统一使用根目录 BTF 类型与成员接口，自身只保留业务字段和初始化规则。函数推导的指令链、扫描窗口、偏移存储与消费者保持前一轮实现。

## 验证

- 当前 12 份裸内核的原/新结果一致，且匹配真实入口参考；其中 6 份 BTF 查询结果匹配原始成员记录。逐镜像 SHA-256、字段值与证据边界保存在收据；6.18 按用户指示暂缓兼容。6.12 为离线观察，不能外推为 KP 支持。
- Sony 5.15 设备镜像的函数/BTF 查询同时匹配 path=0x38、security=0x78、sid=0x4；未连接设备。
- 原宿主 C 夹具逐字节不变，191 条 assert 全部保留并通过 ASan/UBSan。两份 Python 生成器增加公共 BTF helper 和宿主 u8/u64 类型别名的编译输入；其已有断言及断言生成文本逐项保持不变，无判据调整。
- 普通/debug 构建成功；按 .clang-format 格式化并检查差异。既有冻结/探索资产复算哈希保持一致。

## 身份与自查

- instance_id：`run_cmd_demo-1.2.0+gfd06b5353361.rbaa8f505.kpb51197a.ndk26.3.11579264#1`；SHA-256：`9b39623b3750323eafc7584461252b294a8f79188aaf49d8a4d3109f2cd29e46`。
- instance_id：`run_cmd_demo-1.2.0_debug+gfd06b5353361.r521c896b.kpb51197a.ndk26.3.11579264#1`；SHA-256：`3d2e97459bb775e58e494691f3574426d9f59648b83c7ca049efaa74ae46ebc0`。

按 are-you-sure 核对公共 API、模块调用路径与代码体积/导入变化；按 no-negative-echo 复读最终代码、报告和清单；按 respect-the-oracle 核对断言与冻结资产。此为 Developer 自检，未提交冻结，不替代 Auditor 或 Tester 结论。

最终常规门禁 16 项通过，0 失败，0 警告。
