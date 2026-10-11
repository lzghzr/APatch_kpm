# run_cmd 静态基线与规范归属

Developer；2026-10-10。来源 commit：`5b3dc4656b9d1653e6a38d497a1dfa78ca905cfa`。本轮为未冻结探索，`source_dirty=true`；四份产物由统一构建入口生成，完整配方与身份见 [构建清单](data/2026-10-10-run-cmd-baselines-build.json)，自检与保全见 [收据](data/2026-10-10-run-cmd-baselines.json)。

## 复核决定（Decision）

**修改（Modify）**。保留四字段基线与同一业务代码，将现代 SELinux blob 起点作为运行时值取得。一次有界独立只读复核确认：镜像中的 lbs_cred 是初始化前的大小，不能直接编入部署偏移。依据见 [既有偏移记录](2026-10-10-run-cmd-offset-patterns.md)。

## 挑战

### 有效性

run_cmd 的模块自有字段为 UMH path、cred.security、结构内 SID 和旧 worker 大小。静态配置的 SID 仅含 task_security_struct 内偏移，calculate_offsets 在加载时加实际 selinux_blob_sizes.lbs_cred。动态保留现有 BTF 与函数推导。执行域 SID、符号、新旧 worker API 及 KP 凭据布局继续运行时取得。

### 简洁性

使用 CONFIG_KPM_BASELINES 共用 run_cmd.c，不另建执行实现。配置集中于 rc_offsets.c，四项 int16 的 volatile 表为 8 字节。默认 -1 是未移植模板，静态加载仅检查必要字段和旧 worker 必需大小，不重新扫描函数。保留字段别名使原消费者与 C Oracle 使用同一配置。

### 后果

静态版不查询 BTF，工作项共同前缀需离线核对；普通偏移补丁不能解决不兼容前缀。SID 的运行时加量与卸载限制分别写入模块 AGENTS 和用户 README。静态 KPM 17416 字节，动态 KPM 26520 字节；四版导入均匹配本次 KP SDK 的真实导出，静态 10 项、动态 12 项，没有裸 memcpy/memset。反汇编核对指令操作数，未观察到 FP/SIMD 寄存器。

## 实现与文件归属

版本升为 1.3.0。独立 Makefile 的 all/debug 生成 static/dynamic 普通及 debug 四份 KPM，baselines 单独生成两份静态 KPM。静态附配套 JSON，动态不附布局。根目录 patch_offsets.py 延续使用者此前要求更新该移植工具的授权，增加 schema 3 普通偏移表；schema 1/2 的固定及可选择 Binder ABI 契约保持。Genl 宽度校验对含对应字段的表执行，普通表不添加 Binder 字段。

README 写法偏好存入用户区域；项目开发约定存于 run_cmd_demo/AGENTS.md 和 Developer/README.md。维护者拥有的技能接入清单与版本声明仅提供 [补丁建议](../proposals/2026-10-10-run-cmd-baselines/README.md)。旧构建、结论和历史身份不改写。

## 验证

- 统一构建事务四份 KPM 全部完成，日志无编译警告，输入复核通过。
- 原 C Oracle 的 191 条断言及文件字节保持，动态宿主 ASan/UBSan 自检通过。两个 Python 生成器仅适配元信息宏与 ELF section 属性，不修改已有断言。
- 静态普通/debug 的 schema 3 JSON/blob 往返通过，改变仅位于 8 字节配置段，父哈希与派生哈希对应。静态 SID 初始化夹具覆盖无 blob、两个运行时 blob 加量和旧 worker 路径；这是宿主契约验证。
- 原 test_static.py 不修改，实际两份统一 Binder 基线的四种调用配置、已有非法输入判据及八份 schema 1 旧基线往返全部通过。
- 559 份先前资产复算 SHA-256 一致。clang-format、差异空白检查和维护者补丁 apply --check 通过。
- 常规门禁 15 项通过、1 项失败：rek、rekx、run_cmd 新版本尚未同步维护者声明元数据。三个模块的声明同步均已有补丁建议；不放宽门禁或改写旧身份。

最初统一构建发现模块内新生成 JSON 被现有身份工具计入源码清单，因此拒绝登记；原失败记录保留。最终使用独立 LAYOUT_DIR 后重建，通过输入复核。宿主 Mach-O section 适配、元信息宏参数及新增检查器的路径/变量名错误均在探索阶段修复，生产编译、原 Oracle 和新增检查器重新通过。

本轮不重新分析镜像，不操作设备，不提交冻结；Developer 自检不替代 Auditor 或 Tester 结论。

## 产物身份

- `run_cmd_demo-1.3.0+g5fc7311b91b9.r7d4c90fd.kpb51197a.ndk26.3.11579264#1`；SHA-256：`caf3ada14a6e2fbaabb9c8b439f7e7c9613c12ffabc54b6f5fdb3a144ca1d178`。
- `run_cmd_demo-1.3.0_baselines+g5fc7311b91b9.r72b98a54.kpb51197a.ndk26.3.11579264#1`；SHA-256：`e2daa67ebb34a423c3e8f62c4aa947ae2cc1a602c34249ff741b014941ec18e1`。
- `run_cmd_demo-1.3.0_baselines_debug+g5fc7311b91b9.r38396b9a.kpb51197a.ndk26.3.11579264#1`；SHA-256：`6b8c4e3e3c89ef785f9e4e42a0717bfeb91936287dadf233167488dc5e1be436`。
- `run_cmd_demo-1.3.0_debug+g5fc7311b91b9.rc6589b76.kpb51197a.ndk26.3.11579264#1`；SHA-256：`46a513ca49356a80f1f8638aac894e95359ed087cc7ba6335938609e87a76d48`。

配套布局 SHA-256 保存在收据中。仅静态版可通过根目录工具替换，模板需移植后使用。

## 最终自查

are-you-sure 复核静态 SID 与工作项布局契约后采用 Modify；no-negative-echo 回读模块 README、AGENTS、更新记录与构建元信息；respect-the-oracle 核对原 C Oracle、旧基线和既存资产，保留宿主验证边界。
