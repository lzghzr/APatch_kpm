# zram_zstd 源码布局与兼容件生成

Developer；2026-10-11。ZSTD 子模块移至 `zram_zstd/zstd`，普通 KPM 构建后由 Python 生成旧 KP 兼容件。README 按版本选择、开机使用和状态排查整理；生命周期提醒及原有用户注记保留。

本轮是工作树探索，基于 `358a6bae986eab420d7238e0693e79a42a6a7938`。源文件指纹、转换回执、原候选的完整 commit／instance_id／SHA-256 及六份逐字节比较结果见 [自检数据](data/2026-10-11-zram-zstd-layout.json)。这是实现方 Tier-3 自检，不是新的独立审计、实机结论或冻结候选交接。

## 实现与来源

- 子模块提交仍为 `aecf3b479c45affa9fd8ead068e9160253a8ec5c`（ZSTD v1.3.1）。先吸收 Git 对象库，再迁移工作树；保留子模块逻辑名，使历史冻结记录可以继续读取原对象。来源清单的 18 个文件仅更新路径，内容哈希保留。
- 普通 Makefile 保留 dynamic／static 及相应 debug 四种产物。源码固定记录普通 KP 兼容形态；构建后使用 `patch_offsets.py legacy-kp` 完成指针导入转接及已有兼容字段的同步。
- 转换只将唯一的 `kp_compat=modern` 等长改为 `kp_compat=legacy`，不移动元信息节。无字段或已为 legacy 的历史输入保留元信息；重复字段、未知值、未终止或有重定位的元信息拒绝。转换回执捕获新增的六字节范围；静态配套 JSON 同步产物哈希。
- `tools/identity.py` 的历史子模块对象库定位及 `cat-file --filters` 修正按维护者本轮明确授权落地。技术依据及临时仓库复现见 [配套补丁](../proposals/2026-10-11-zram-zstd-layout/README.md)。

## 构建与自检

使用 ndk26.3.11579264，在新空目录 `local/zram-layout-check-20261011-02` 构建，编译日志无 warning／error。构建与转换命令为：

```sh
make -C zram_zstd all debug OUT_DIR=../local/zram-layout-check-20261011-02 LAYOUT_DIR=../local/zram-layout-check-20261011-02
python3 patch_offsets.py legacy-kp local/zram-layout-check-20261011-02/zram_zstd_0.2.0.kpm --output local/zram-layout-check-20261011-02/zram_zstd_0.2.0_legacy.kpm
python3 patch_offsets.py legacy-kp local/zram-layout-check-20261011-02/zram_zstd_0.2.0_debug.kpm --output local/zram-layout-check-20261011-02/zram_zstd_0.2.0_legacy_debug.kpm
```

运行前以 `ANDROID_NDK` 指定上述工具链；公开报告省略本机安装路径。

六份输出均与源提交 `4f2a50487f9f06a8cbbd41108974ed440facb1a6` 的六个候选实例逐字节一致。普通、静态及 debug 构建没有改变模块字节；新转换的兼容普通版和 debug 版分别保持 SHA-256：

```text
dc4d7f7cd2c2c48cb8afa31e9f1748243a927de2fd0a7544e8bcc593b8f7e4f0
238d291f8cdfeba10b5ed679568b26f048fc838d60d544c597ede2d9ba76f901
```

六个旧实例的 candidate 档身份核验均通过，每份冻结来源可读取 251 个 blob，归档产物哈希一致；108 份受保护报告、元数据和归档证据保持原字节。路径迁移改变来源指纹，后续正式候选仍须从新冻结提交受控登记，配方同时捕获普通构建、转换命令及转换工具，不能复用旧实例身份。

strict 仓库门禁 17/17，0 失败、0 警告。自检通过：迁移夹具 6/6，维护者工具判据 26/26，产物门禁自检 47 项；六份当前 KPM 的元信息／命名与两份静态布局核对通过。rek／rekx 的八份实际产物转接回归、含 run_cmd 的十份导入回归通过。新元信息自检覆盖四份普通 KPM、已有指针导入、静态布局、回执范围、输出保护及六个元信息正反例。

## Oracle 范围与技术依据

已有测试文件及断言逐字节保留。原 ABI 转接仍必须保持原节载荷不变；新增元信息转换属于 CLI 在 ABI 转接之后执行的单独步骤。新增 [元信息自检](../tools/test_legacy_kp_metadata.py) 先对纯 ABI 转接调用原有完整 Oracle，再断言最终 CLI 输出与该转接结果仅相差指定的六字节兼容值，其余字节完全相同。没有跳过或缩小原有节区断言；新 CLI 语义仍交 Auditor 独立复核。

原 `test_zram_legacy.py` 在本轮先前单独生成的两份 legacy 输入上复跑通过。当前普通构建流程由新增测试覆盖，不依赖该历史测试要求的专用 `.input`。更早的 `test_legacy_kp.py` 名称替换断言与正确指针转接的已知冲突仍按 [原记录](2026-10-10-legacy-kp-pointer-import.md) 保留，本轮不宣称它通过。

## 自查决策（Decision）

**修改（Modify）**

## 方案挑战

### 有效性

正常编译后使用现有 Python 工具可以满足旧 KP 导入契约；直接调用经 ADRP／LDR／BR 读取原名函数指针，原调用索引保留。真实两份兼容输出与已审计字节一致，新增测试核对兼容字段与回执同步。

### 简洁性

四种普通构建复用同一来源与配方，兼容形态由离线转换取得。只同步已有字段即可完成本模块需求，历史无字段输入无需增加元信息或节区。

### 后果

子模块目录迁移会使依赖旧工作树路径的冻结读取失效；稳定对象库定位及六项反例已核对。新 CLI 元信息同步改变组合输出的字节契约，必须保留纯 ABI Oracle 并追加精确范围测试。实际设备结论继续绑定原实例；本轮未连接或操作设备。

## 修订建议

采用普通构建后 Python 转换的流程，保留转换回执并在未来冻结登记中捕获两段配方。维护者核验新来源身份后，再由对应角色复核本轮工具与文档变更。

按 are-you-sure 完成只读挑战后实施；按 no-negative-echo 回读 README、开发约定及实际回执；按 respect-the-oracle 保留原判据并追加新契约自检。
