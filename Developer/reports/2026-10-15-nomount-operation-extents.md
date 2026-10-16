# NoMount：补齐三类操作表尺寸

已补齐无BTF动态路径的inode、super、dentry操作表尺寸。两份目标镜像的离线执行分别得到Sony的256／280／192字节和B2N的256／232／128字节，随后全部布局准备通过。新动态KPM及4.4二进制兼容派生件已生成，等待独立审计和Tester实测；`AUD-001`仍开放。

## 实现

`nm_structs.h`增加已核对的末端连续片段，按自然大小表示字段和KABI槽。`nm_offsets.c`从目标取得片段内的末端回调位置，核对同表成员相对关系，再加上片段尾部和完整结构对齐。inode／dentry按64字节对齐，super按8字节对齐；三项范围全部有效后写回。

- set_posix_acl：最多13条入口指令，核对原始inode、i_op、set_acl及空回调检查。
- super_cache_count：最多21条入口指令，从shrinker追踪sb／s_op及nr_cached_objects。它与free_cached_objects连续，使用共同片段计算末端，无需扫描较长的super_cache_scan。
- sdcardfs_ci_dops：仅在两套声明均确认存在的112字节前缀中定位唯一sdcardfs_canonical_path。原生指针及CFI单B跳板复用既有核对逻辑。

两套尾部契约通过getattr→set_acl、drop→nr_cached、drop→evict及init／release→canonical关系共同匹配。支持声明仍是Sony提交`7fc8455b2fa84be76364c2457e6503b867ceb12a`，以及Nokia提交`67c3e103decafc3ff8a361c39f079a0dfce2a23c`的语义参考；后者为4.4.196，目标镜像为4.4.192，原有参考边界保持。未知的追加尾部可能保持相同几何，不能据此宣称任意厂商布局均已支持。

操作表尺寸准备提前执行所需回调探测，避免完整布局校验器先要求尺寸而形成循环依赖。BTF明确不可用才进入本分支；有效BTF错误继续返回。key_type精确尺寸仍未知时沿用已有自建清零容量；复制与比较使用三项所得尺寸，分配和驻留机制保持。

按用户本轮明确要求，已直接更新[偏移技能](../../.agents/skills/kernel-offset-derivation/SKILL.md)，加入末端成员、已确认尾部片段及完整类型对齐的计算方法，说明自然对齐、同表几何与不可观测尾部的边界。模块约定同步至[AGENTS](../../nomount/AGENTS.md)。

## 自检

| 项目 | 结果与边界 |
| --- | --- |
| 两目标函数推导 | 原42项断言保持，新增三项尺寸均符合参考值；后续inode、目录、控制、权限及三组共同ABI布局准备通过 |
| 新边界用例 | 缺符号、入口指令破坏、混合几何及非法范围拒绝；有效BTF错误不回退，有效BTF成功不查询函数 |
| dentry读取边界 | 实际112字节表前缀紧邻保护页；命中、重复回调和无回调三种情况均不读取第15槽 |
| 分配／复制回归 | 原容量用例全部断言通过，精确复制保护页及控制边界通过；仅在私有夹具为新增尺寸准备依赖提供成功空桩，未修改原工具及断言 |
| Sony 5.15真实BTF | 生产查询的46项布局及原有拒绝断言通过；这属于宿主查询回归，没有执行原生函数 |
| 构建与身份 | 干净冻结提交、147项输入、两种ARM64 KPM构建通过；源码、配方、产物、ELF及92字节默认偏移表核验通过，未新增裸libc导入 |
| 静态版 | SHA-256与上一轮完全相同，新增推导只进入动态件 |

新工具`test_operation_extents.py`在原动态准备工具生成编译单元之后追加窗口、BTF路由空桩和新用例。原工具文件及全部既有测试文件保持逐字节一致，原断言一并执行。冻结后的两目标测试使用ASan／UBSan；C变更通过clang-format检查。逐项输入、指令、结果及Oracle核对见[自检数据](data/2026-10-15-nomount-operation-extents.json)。

## 冻结身份与产物

源码：`b4cf78daff053dea0b5ca987b33782f6bbfda552`。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。两件均为exploration；[统一构建清单](handoffs/2026-10-15-nomount-operation-extents.json)已先行提交，维护者可据此导入。

| 模式 | instance_id | SHA-256 |
| --- | --- | --- |
| dynamic | `nomount-2.1.1-20261014+g4b49827eb674.ra2d2c48f.kpb51197a.ndk26.3.11579264#1` | `1db32ea9a394164a6d3fde01d94875c516eafff953a30bd9ced6ea1c8b7e66ea` |
| baselines | `nomount-2.1.1-20261014_baselines+g4b49827eb674.rdaba8f18.kpb51197a.ndk26.3.11579264#1` | `77a5baa38d3072c4fb63da4cb70b286d83d93cf06fa06179b8c4125f9c2bc15a` |

4.4派生件由上述dynamic实例经冻结的patch_offsets.py执行legacy-kp生成，SHA-256为`d9d7d29785961e15f7db03bf1cc589ef48b0a5ecdf3afe621b9545958949ddc6`。文件位于`artifacts/binary-port/nomount/<派生SHA-256>/NoMount_2.1.1-20261014.kpm`，同目录附compat收据；自检数据记录base实例、源码、父哈希、工具哈希、完整命令与派生路径。源码及Makefile保持面向最新KP。

## 复核决定（Decision）

**保留（Retain）**，作为这两套声明契约的探索实现交独立复核。

### 有效性

有界只读辅助复核指出并解决了准备顺序循环和尾部片段重复对齐问题。两目标实际窗口随后通过生产推导及全部布局准备；三项尺寸不再是阻塞项。这里没有原生注册或新实机加载成功的结论。

### 简洁性

尾部用共同结构片段表达，一次核对多个成员关系；复用既有指令宏、回调探测及BTF来源路由。选择更短入口和有证前缀，原表复制／比较及业务实现保持原结构。

### 后果与交接

新件将首次在无BTF路径进入后续原生准备和注册。`AUD-001`所述未知厂商尾部风险仍在；匹配已核对几何不构成任意隐藏扩展不存在的证明。请Auditor复核尾部声明、前缀下界、分配上界和原表复制契约，决定本轮支持范围；Tester在维护者批准的该字节上验证4.19及4.4动态加载与功能，并补5.15回归。独立问题单由对应复核方处理。

本报告为Developer自检与交接，不代替独立审计、实机结果或维护者验收。respect-the-oracle核对了旧测试与断言的保持；no-negative-echo回读源码、技能、约定、清单及本报告。没有改写其他角色报告或关闭问题单。
