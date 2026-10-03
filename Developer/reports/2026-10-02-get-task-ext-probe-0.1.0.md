# 开发报告：get_task_ext_probe 0.1.0

角色：Developer。用于用户请求的最小链接与显式调用探针。

## 身份

冻结提交：`06b1d95db7ba6a4dc51aa3eb9c1452b1a1f10f8a`。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`（0.13.9）。工具链：NDK 26.3.11579264。通过隔离的干净检出运行 `tools/build_candidate.py get_task_ext_probe --target "all debug" --handoff ...`，原工作树与分支未切换。冻结提交为未签名的临时检查点。

完整配方、源码指纹和构建事务见 [身份清单](handoffs/2026-10-02-get-task-ext-probe.json)。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| get_task_ext_probe_0.1.0.kpm | `get_task_ext_probe-0.1.0+gd8fb87994db8.r14b91adc.kpb51197a.ndk26.3.11579264#1` | `8652d17ed38a79d6f857808c807a8e65f1cf0070f54ebc8049222abb054b55f8` |
| get_task_ext_probe_0.1.0_debug.kpm | `get_task_ext_probe-0.1.0_debug+gd8fb87994db8.rfc22ddd0.kpb51197a.ndk26.3.11579264#1` | `a4e1b3f5bf8cbf8ae8d236973024bf9cbfdc9b6970c4a27a2370c27afae9e2ea` |

## 自检与测试步骤

两份产物按冻结提交执行 candidate 身份核验通过，ARM64 指令检查未发现 FP/SIMD/SVE。强制保留 `kf_get_task_ext` 未定义符号；加载 init 仅打印函数地址，显式 `ctl0 call` 才调用 `get_task_ext(current)`。返回的扩展区不被解引用或写入。输出复制依据 SDK 的“已复制字节数”返回约定转换成控制接口的零成功返回。

用户加载普通版。如果设备报 `unknown symbol: kf_get_task_ext`，该次加载器不能解析这个导入；加载成功后发送 `ctl0 call`，收集控制输出和内核日志。调用返回只说明该次接口可调用，不说明扩展区容量或旧模块 task-local 用法正确。

## 边界

这是 Developer 构建与产物自检，不是独立审计或设备测试。用户报告现有 KPM 在 KP 0.13.9 可加载；该事实未被本地新编译产物的符号检查否定。旧 KPM 是否导入 `kf_get_task_ext` 尚未检查，不能据版本号推断设备上所有模块的加载情况。

## 后续记录：2026-10-02 用户加载反馈

用户在本会话提供的设备日志显示，探针名称为 `get_task_ext_probe`、版本为 `0.1.0`，加载器在时间戳 `712.394634` 报 `unknown symbol: kf_get_task_ext`。这是用户提供的真机观察，Developer 未自行操作设备，也未生成 Tester 验收结论。该次加载在未定义符号解析阶段失败，未进入模块 init，显式调用步骤未执行；因此本次证据确认该加载器不能解析这个导入，不验证 getter 的返回值或存储布局。

对应的预期产物身份为上表普通版：完整提交 `06b1d95db7ba6a4dc51aa3eb9c1452b1a1f10f8a`，实例 `get_task_ext_probe-0.1.0+gd8fb87994db8.r14b91adc.kpb51197a.ndk26.3.11579264#1`，SHA-256 `8652d17ed38a79d6f857808c807a8e65f1cf0070f54ebc8049222abb054b55f8`。本地再次复算产物哈希一致；日志模块大小 `1030` 与该文件大小 `0x1030`（4144 字节）一致，但日志未包含设备端文件 SHA-256，设备加载字节与该身份的严格绑定仍未覆盖。

本地复查当前 SDK：`get_task_ext()` 内联封装调用 `kf_get_task_ext()`，`taskob.c` 存在该实现但未通过 `KP_EXPORT_SYMBOL` 导出。用户现有 `re_kernel` 可加载的观察仍成立；旧二进制是否采用早期内联实现，尚无产物证据。

同轮复查 `local/static-baselines-20261002-09/` 的八个静态模块产物，均无 `get_task_ext` / `kf_get_task_ext` 未定义导入。这些产物使用模块自身的 Binder 调用上下文；本项仅为本地依赖检查，不能据此宣称它们已通过真机加载或功能测试。

## 后续记录：2026-10-02 探针退役与历史冻结

依据用户本轮指令删除活动 `get_task_ext_probe/` 目录。探针任务已取得缺失导入的加载反馈，静态模块改用自己的 Binder 调用上下文。原开发报告、身份清单及两份已归档产物保留，删除不撤销历史加载失败证据。源提交 `06b1d95db7ba6a4dc51aa3eb9c1452b1a1f10f8a` 由本地历史引用 `codex/archive-get-task-ext-probe` 保留；当前模块不再作为后续构建对象。
