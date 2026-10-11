# run_cmd 偏移查找精简

Developer；2026-10-10。范围为 `run_cmd_demo/rc_offsets.c`，继续保留 DEV-029 的凭据槽位修复。来源基点 commit 为 `5b3dc4656b9d1653e6a38d497a1dfa78ca905cfa`；本轮修复未提交，`source_dirty=true`。完整输入指纹、普通/debug instance_id、原始与兼容件 SHA-256 见 [自检收据](data/2026-10-10-run-cmd-offset-simplify.json)和 [探索构建清单](data/2026-10-10-run-cmd-offset-simplify-build.json)。自检层级为 Developer Tier-3。

## 复核决定（Decision）

**精简（Simplify）**。沿用当前短入口算法，删除可证明的重复操作。先完成以下复核并宣布决定，再进行实现。

## 挑战

### 有效性

本地 Android13-5.15 的 `kernel/bpf/btf.c` 显示，`btf_resolve_size()` 返回解析类型或 `ERR_PTR`，不返回 NULL。原 `!resolved` 不对应此 API 的失败契约；保留 `IS_ERR()` 和所需宽度、范围核对即可。函数查找仍需要宽度、寄存器链、SID 输出写回和固定窗口，以区分实际目标字段。

### 简洁性

`btf_member_offset()` 改为接收已经查到的类型，复用一次 `kthread_work` 查询，去掉重复的按名称查找。其余结构仍由 `find_btf_struct()` 获取。删除 resolver 返回类型临时变量，直接检查返回错误。CBZ/CBNZ 仅在 op（bit 24）不同，统一该位后共享 sf/Rt 检查，减少重复判定。

比较过项目公共 BTF helper；其嵌套/匿名成员遍历和 API 描述符并非本模块当前字段所需，本次保持局部改动。现有指令链比宽泛匹配有更明确的字段语义；不通过放宽它来追求代码行数。

### 后果

指令 getter 会校验具体指令类型，因此不能直接把 CBNZ 交给 CBZ getter。本次先清除 op 位，将其规范为合法 CBZ 编码，再调用原 getter。高字节全部 256 种、Rt 全部 32 种、目标寄存器全部 32 种共 262144 个组合，旧、新分支识别与接受条件一致；其余立即数字段不参与匹配。既有宿主断言、B2N 和 Sony 入口验证通过。只删除无效 API 空指针分支，保留 BTF 位域/宽度/范围核对及 worker 共同布局检查。

## 更新后的方案

修改已按 `.clang-format` 完成，只有 `rc_offsets.c` 改动。普通/debug 使用统一构建入口生成新的探索 Build ID，旧冻结资产保持哈希一致。后续冻结候选需重新绑定提交、实例与产物哈希；本轮未连接设备。

## 自检与身份

- 原三份宿主/镜像测试文件逐字节保持不变，全部 191 条既有 assert 保留。ASan/UBSan 宿主回归通过。
- B2N Image 使用 Tester 提供的 KP 字段输入：`real_cred=0x7b0`、`cred=0x7a8`。结果 `path=0x28、security=0x78、sid=0x4、worker_size=40`。
- Sony 5.15 使用此前已确认的设备镜像副本和符号表。直接从 `__start_BTF` 到 `__stop_BTF` 取原始 BTF，真实成员查询通过；函数路径结果 `path=0x38、security=0x78、sid=0x4`。
- CBZ/CBNZ 262144 组合等价诊断通过；诊断只写入新的本地目录。
- 普通/debug 构建成功；两份临时旧 KP 兼容件通过既有 ELF/符号索引/指针转接检查。

- 新父实例：`run_cmd_demo-1.2.0+g747a5765e230.r92a93141.kpb51197a.ndk26.3.11579264#1`；来源基点 commit：`5b3dc4656b9d1653e6a38d497a1dfa78ca905cfa`（脏树探索）。父产物 SHA-256：`341ae1eafe08d5fcbf4bf252140fb4537922f67c30a59b3b54974adef1b32d87`；兼容件 SHA-256：`4daa73e6a9ca3ef01a682a95424f0c50c0ab49f4273abd2852efc1567cae7080`。
- 新父实例：`run_cmd_demo-1.2.0_debug+g747a5765e230.ra57081c8.kpb51197a.ndk26.3.11579264#1`；来源基点 commit：`5b3dc4656b9d1653e6a38d497a1dfa78ca905cfa`（脏树探索）。父产物 SHA-256：`7d1a8d556920613d4708c80e69ff4bcb0dca60da9f80aae2263620a15622e8d5`；兼容件 SHA-256：`5339f3e09c4f4a0ab1780af8faeadb88cd5a28c67c78e179895048bb0a6c35e2`。

## 前次自查范围复盘

前次 DEV-029 响应中的 are-you-sure 自查，实际重点是两个凭据槽位能否修复加载失败，以及窗口和 SID 链是否保留；没有逐项检查已有 BTF API 返回契约或重复查找。因此它未发现本次删除的冗余 NULL 判断，原记录对自查范围的概括过宽。此处追加更正，保留历史报告。

这属于技能执行范围和证据记录的遗漏。are-you-sure 要求检查简洁性并比较更简单的可信方案；测试通过不能代替这一项。此次将完整 `rc_offsets.c` 作为复核对象，分别记录有效性、简洁性和后果，API 结论来自内核源码，编码合并来自现有宏定义和等价诊断。

按 no-negative-echo 复读修改代码、报告和生成清单；按 respect-the-oracle 复算测试文件哈希。自检不关闭 DEV-029，也不替代 Auditor 复核和 Tester 真机结论。
