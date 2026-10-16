# NoMount 4.19：首批布局获取

Developer 已实现文件、inode 和 dentry 的首批布局获取，并在指定镜像上执行生产推导代码。维护者接入的上游子模块位于 `nomount/nomount`，移植代码按该目录位置继续开发。

本轮产出是布局库及自检，不是可加载的 NoMount。VFS 注入、规则管理、完整操作表和 keyring 控制仍需实现；未产生 KPM 候选、Build ID 或 instance_id，未操作真机。

## 冻结输入

- 源码检查点：`1a96e2854ec52efecd896d005347c1a8cecf0a2a`。
- 原版 NoMount gitlink：`1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。
- 目标：`kernel_img/boot_los23.2.img`，版本 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。
- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 按 boot 头边界取得的内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 内核源码参考：[LineageOS/android_kernel_sony_sm8250](https://github.com/LineageOS/android_kernel_sony_sm8250/tree/7fc8455b2fa84be76364c2457e6503b867ceb12a)，完整提交 `7fc8455b2fa84be76364c2457e6503b867ceb12a`，与镜像版本标记一致。

本轮只使用这个目标。参考源码下载保存在 `local/nomount-layout-20261012/native/` 和 `native-more/`，用于核对语义；未作为模块编译输入。

## 实现与结果

共同片段放在 `nomount/nm_structs.h`；偏移缓存、访问器和固定入口窗口放在 `nm_offsets.c`；BTF 放在 `nm_btf.c`。`nm_layout.c` 提供布局准备入口，尚未安装任何原生对象或回调。所有指令解码和 BTF 成员查询复用根目录 `kpm_utils.h`。

| 缓存字段 | 本次目标值（字节） | 推导入口与窗口 | 参考依据 |
| --- | ---: | --- | --- |
| `file_inode_ops` | 32 | `vfs_llseek` 16 条，`iterate_dir` 12 条交叉核对 | 目标 `file` 的相邻 inode/ops 声明及 `__fput` 访存 |
| `file_mapping` | 240 | `generic_file_mmap` 8 条 | `generic_file_llseek` 的独立 mapping 访存 |
| `inode_superblock` | 40 | `generic_fillattr` 8 条 | `inode_init_always` 的独立 sb 写入 |
| `inode_number` | 64 | `generic_fillattr` 32 条 | 目标 `fs.h` 声明及镜像 ACL/security 配置 |
| `inode_nlink` | 72 | `set_nlink` 8 条，`inc_nlink` 16 条交叉核对 | 目标 `inode` 声明 |
| `inode_size` | 80 | `generic_fillattr` 32 条 | `generic_file_llseek` 的独立 size 访存 |
| `dentry_ops` | 96 | `d_set_d_op` 16 条 | 目标 `dcache.h` 前部，含 32 字节内联名称和 lockref |

共同定义只覆盖实际核对的片段，未声明整份 file/inode 的尺寸。偏移写入 `.data.re_offsets` 后由访问器消费，自检逐项检查两条路径。加载准备失败则返回错误，调用方不得启用依赖此表的回调。

目标 `CONFIG_DEBUG_INFO_BTF=n`。函数推导使用真实目标入口；BTF 分派只用合成数据验证。接口缺失或空数据才允许回退。内核错误指针返回的原始 errno 保留，包括 `ERR_PTR(-ENODATA)`，与不可用状态分别处理。

## Developer 自检

```bash
python3 nomount/tools/test_layout.py \
  --image kernel_img/boot_los23.2.img \
  --symbols local/nomount-port-20261012/inspection-02/symbols.json \
  --reference local/nomount-layout-20261012/reference.json \
  --output local/nomount-layout-20261012/selfcheck-03
```

真实入口的七字段、缓存及访问器均与参考一致；ASan/UBSan 未报错。负例覆盖入口缺失、跨锚点布局冲突、入口参数覆盖、XZR/SP 误连、窗口外模式、调用及 BR 后的顺序后继。合成 BTF 覆盖正常查询、成员关系冲突、尺寸解析错误、错误指针和空数据分派。

既有 `re_kernel/tools/test_instructions.c` 原样执行并通过，未修改 Oracle。新增共享宏为 BR、LDP 立即数及 LDR/STR scaled immediate 解码；新增反例在 NoMount 自检中执行。

NDK `26.3.11579264` 的 AArch64 clang 使用当前 KP SDK 编译动态与静态布局对象，均通过。每份对象有两条 SDK 已有宏重定义警告（`READ_ONCE`、`WRITE_ONCE`）；仅该警告类别不作为错误，其余开启 `-Wall -Werror`。最终 C 文件通过仓库 clang-format 检查。

| 本地证据 | SHA-256 |
| --- | --- |
| `reference.json` | `dd8631136835ded9fda25f9cc655f32d360acf1d6c24f900ad0aa2ae758443d8` |
| `selfcheck-03/receipt.json` | `985064644c225d4b31b7c14c14078120fa362bcca5b7774438905f43efee4bd2` |
| `shared-instructions-02/receipt.json` | `9bc1f7016de83c43b01b49150f186ed060fe323b50f457ec546137e5e72e5445` |
| `compile-04/receipt.json` | `ec05ec4e2823e161f8bf2791ba3d2ba5185e6fb065c0582888fccb24592ad81f` |
| `compile-04/dynamic.o` | `168c4d08960a05688ba742ec18eaee28f18c8d1a4e471da48418b3e92b2cf8bb` |
| `compile-04/static.o` | `ca7f789ffcba636dbc24e1284038366274b0431a9b333cf4c78cfdfd9f6bd241` |

表内路径均相对 `local/nomount-layout-20261012/`。回执包含实际源码哈希，读回时与冻结源码逐项相符。此前探索目录保留，最终依据为表内本次证据。

常规仓库门禁为 13 项检查、0 失败、1 个既有警告：历史 zram_zstd 二进制派生交接单缺登记人和时间。本轮未改动该历史文件。

## 完整操作表参考

原版 NoMount 会复制完整 VFS 操作表。匹配目标的 `fs.h` 有 `permission2`、`setattr2`、`get_lower_file` 等扩展和 KABI 保留项，必须核对全表后再安装回调。

已用该提交的声明片段、KABI 宏、arm64 cache 对齐定义和镜像配置生成 ARM64 编译参考。配置为 MMU/QUOTA 开启，LOCKDEP/RANDSTRUCT 未开启。`ops-reference-02/reference.json` 的 SHA-256 为 `f24b17b8533929f7f31d462cc4f8389c17df1d11f302fa0c311998981316d648`。

| 类型 | 编译参考大小 | 对齐 |
| --- | ---: | ---: |
| `file_operations` | 296 | 8 |
| `inode_operations` | 256 | 64 |
| `super_operations` | 280 | 8 |
| `dentry_operations` | 192 | 64 |
| `key_type` | 136 | 8 |

这是目标源码声明与配置的编译参考，尚未实现运行时整表尺寸确认。未把这些数值写入业务实现，后续仍需核对回调字段、ABI、CFI 和对象持有关系。

## 三项复核与边界

- `are-you-sure` 的限范围反例复核先给出 Modify，指出参数覆盖、错误 errno 与不可用状态混同、BR 控制流遗漏。修复并增加反例后，复核给出 Retain；范围仅为七字段布局库。
- `no-negative-echo`：读回源码、README、开发约定和生成回执，说明对应当前实现及必要边界。
- `respect-the-oracle`：既有断言未改动；新代码与宿主夹具按原生语义设计。宿主自检不能证明原生回调、并发安全或实机行为。

下一步完成其余对象字段、完整操作表及控制接口，再实现新增目录、只读文件与 APK 映射。运行端 CFI 支持和实际驻留保护必须在安装回调前确认。候选形成后按完整 commit、instance_id 和 KPM SHA-256 交接，独立审计与真机测试由对应角色完成。
