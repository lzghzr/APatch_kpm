# NoMount 4.19：原生接口与操作表分配

本轮按用户要求继续移植，生命周期改为与 zram_zstd 一致：成功初始化后常驻到重启。实现原生 RCU、控制载荷拷贝、目录枚举转发和完整操作表分配。文件注入及规则引擎仍在实现，尚未注册 key 类型或发布 VFS 回调。

## 身份与范围

- 源码检查点：`890a0a68cb9dbcf7b8e1876293896b691f4ed45a`。
- NoMount 上游 gitlink：`1ded61dc908c511072162fa0bee44e6ccdb7b4c7`，位于 `nomount/nomount`。
- 目标为 `boot_los23.2.img`；boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 匹配内核源码提交：`7fc8455b2fa84be76364c2457e6503b867ceb12a`，目标仍为 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。
- 本轮产物是两个编译对象及宿主回执；未构建 KPM 候选，没有 Build ID/instance_id，未操作设备。

上一阶段的字段依据见 [布局记录](2026-10-12-nomount-layout.md)。完整操作表尺寸使用该记录的目标源码编译参考；参考源码不参与 KPM 编译输入。

## 采用的接口

`nm_native.c` 显式解析 11 项原生依赖，缺失即返回错误：`__rcu_read_lock`、`__rcu_read_unlock`、`synchronize_rcu`、`call_rcu`、`kfree`、`vzalloc`、`vfree`、`capable`、`memdup_user`、`vfs_setpos`、`iterate_dir`。目标符号表中均在场；用户写回所用的 `seq_buf_to_user` 也在场。

当前 SDK 的 `synchronize_rcu()` 包装调用 `rcu_barrier_tasks_rude`，`kfree_rcu` 映射到 `kvfree_rcu`。本模块使用目标原生 RCU 函数，延迟释放走自己的 `call_rcu` 回调。通用释放封装仅适用于分配起点为 `rcu_head` 的模块私有数组；原生对象引用继续由原生接口管理。

控制协议在 `nm_protocol.h` 中保留原版的 4096 字节载荷、命令编号、规则头及删除头。地址载荷支持 32/64 位，先检查 `CAP_SYS_ADMIN`，再调用原生 `memdup_user` 取得内核快照，处理后核对完整写回长度。正常传输仍返回 `-ECANCELED`，业务结果在 `status` 中返回；拷贝故障保留错误。写回失败不回滚已经执行的业务。

选择 `memdup_user` 是因为[匹配源码的实现](https://github.com/LineageOS/android_kernel_sony_sm8250/blob/7fc8455b2fa84be76364c2457e6503b867ceb12a/mm/util.c)已包含分配和安全用户拷贝，结果由 `kfree` 释放。控制传输因此不依赖 `struct page`、`kmap` 或手工页引用处理。

原版 backing 目录分支直接调用真实 iterate 回调，但外层原生 `iterate_dir` 锁住的是虚拟 inode。新封装先用 `vfs_setpos` 同步位置，再走 `iterate_dir`，保留真实 inode 的锁、权限检查及位置更新。同一 inode 的接管分支直接转发保存的原回调，避免再次获取同一锁。后续业务将分别接入这两个入口。

## 完整表的存储

`nm_offsets.c` 追加五个 int16_t 尺寸字段；BTF 查询留在 `nm_btf.c`。`nm_operations.c` 按目标完整尺寸分配、复制全部字段和尾部，文件操作表的共同 `owner` 字段置 NULL。新表使用原生 `vzalloc`，其页对齐满足本次操作表对齐要求；`vfree` 仅用于发布前失败路径，已发布的表按驻留设计保留。

静态尺寸参考为 file/inode/super/dentry operations 和 key_type 的 296/256/280/192/136 字节。动态准备要求 BTF 提供五个完整类型和有效尺寸；无 BTF 时停止，不以函数推导补猜整表大小。因此这份 4.19 的首个原型使用目标静态配置。回调字段位置及 ABI 尚需逐项完成，取得表尺寸不表示可以发布表。

## Developer 自检

```bash
python3 nomount/tools/test_native.py \
  --symbols local/nomount-port-20261012/inspection-02/symbols.json \
  --reference local/nomount-layout-20261012/ops-reference-02/reference.json \
  --output local/nomount-native-20261012/selfcheck-02

python3 nomount/tools/test_layout.py \
  --image kernel_img/boot_los23.2.img \
  --symbols local/nomount-port-20261012/inspection-02/symbols.json \
  --reference local/nomount-layout-20261012/reference.json \
  --output local/nomount-native-20261012/layout-selfcheck-02
```

两组 ASan/UBSan 自检均通过。原生封装覆盖缺依赖拒绝、RCU 调用路由及延迟释放、backing/original 枚举分流、权限拒绝、载荷快照、32/64 位地址、非法 magic、拷贝失败和短写回。操作表覆盖本次目标的完整复制与尾部保留、零初始化、owner、对齐、非法尺寸及分配失败。

原有七字段自检断言保留；只追加合成 BTF 的五类型尺寸正反例。合成 file_operations 的尺寸是夹具的 256 字节，不是目标的 296 字节；两条证据分别记录。未修改现有 Oracle 的判据。

NDK `26.3.11579264` 对 `nm_native_entry.c` 的动态与静态模式编译均通过。每份对象有两条 SDK 既有 `READ_ONCE`/`WRITE_ONCE` 重定义警告，仅该类别不作为错误，其余使用 `-Wall -Werror`。C 文件通过仓库 clang-format 检查。

| 本地证据（相对 `local/nomount-native-20261012/`） | SHA-256 |
| --- | --- |
| `selfcheck-02/receipt.json` | `6110a1ef77583d8e5d999a4cf9ccedd54ed4a4513bd9698aad98739441a6e09f` |
| `layout-selfcheck-02/receipt.json` | `c5eb22b0fdba3f4b979654d3a7857f28c32ca3d935091ba2f36d3d12910be6b0` |
| `compile-03/receipt.json` | `24cdb762425f1646836cbef8619afdb0f0bd9b9bbe690c6446c9f26c3ae903c3` |
| `compile-03/dynamic.o` | `8a0342b13bb800c6136cb78c5746ec514e97f964933100e0b46a46308b27e1c8` |
| `compile-03/static.o` | `48fb17c72cf9e329cdaac37967ac4a5ab4a53893d13cde13ccab22cc2f7aa7db` |

回执中的源码哈希已与工作树和冻结提交逐项核对。旧探索输出保留，表内为最终证据。

常规仓库门禁为 13 项检查、0 失败、1 个既有警告：历史 zram_zstd 派生交接单缺登记人和时间，本轮未改动该历史文件。

## 复核与后续

`are-you-sure` 的 Developer 第二遍复核先指出 RCU 和 backing 目录锁的差异；实现封装后给出 Retain，追加操作表分配的复核也为 Retain。`no-negative-echo` 已读回实际源码、说明和回执；`respect-the-oracle` 复核确认旧断言保留。这些是开发复核与宿主自检，不能替代 Auditor 独立审计和 Tester 真机事实。

后续接入原版规则引擎、inode/dentry 物化、回调字段与 key 类型注册，并补齐所需原生对象字段。实现形成完整 KPM 后，才进入候选构建和三方交接。
