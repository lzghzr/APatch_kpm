# 旧 KP 转接工具自动补入原名指针导入

Developer；2026-10-10。用户授权扩展 `patch_offsets.py legacy-kp`，使仅导入 suffix 查找函数的 run_cmd_demo 也能生成临时兼容件。本轮续接 [调用契约修正](2026-10-10-legacy-kp-call-abi.md)，属于工作树探索；来源 commit、parent instance_id、父产物及派生产物 SHA-256、工具与自检文件指纹见 [自检收据](data/2026-10-10-legacy-kp-pointer-import.json)。这是 Developer 离线自检，不是独立审计或实机验收；DEV-028 仍待冻结、独立复核和重新裁定的设备测试。

## 行为

使用方式保持：

```bash
python3 patch_offsets.py legacy-kp local/input.kpm --output local/output-legacy.kpm
```

已有 `kallsyms_lookup_name` 导入时复用原符号。缺少时，在符号表末尾追加一个 global undefined object，在字符串表末尾追加名称；扩大后的表另存到文件末尾，更新新节表中的位置和大小。原符号索引、局部符号边界 `sh_info`、原调用重定位及模块代码保留。suffix 的转接定义写到新的有效符号表中；新增的 ADRP/LDR 重定位指向补入的指针符号，读取 KP 导出变量后 BR 尾调用。

符号字符串与节名字符串共用一个节时，合并生成新字符串表。KP 加载器用第一张 symtab 解释所有重定位，因此此入口只接受单符号表 KPM。`.compat.json` 新增 `pointer_import_added`，分别记录自动补入和复用；配套静态布局、来源哈希及排他输出行为沿用原实现。转换仅依赖 Python 标准库，用户无需 NDK。

这是 KP 兼容问题修复前的临时工具，运行端具备 suffix 导出后使用原始产物；此转换只提供原名查找。

## 自检

新增 `Developer/tools/test_legacy_kp_import.py`，既有两个自检文件逐字节保留。

- 十份冻结父产物复算哈希一致：rek、rekx 各动态/静态普通/debug 四份，run_cmd_demo 普通/debug 两份。十份转换检查通过。
- run_cmd 两份原表均有 98 个符号，追加的指针导入为索引 98，类型为 OBJECT GLOBAL UND；原 `sh_info` 保持。重定位仍按原索引引用既有符号，新转接使用两条 275/286 重定位读取新指针导入。
- rek、rekx 八份 KPM 与上轮转接产物逐字节一致。原 `test_legacy_kp_adapter.py` 八份实际产物、汇编器编码比对与指针解码模型自检通过。
- 合成共享字符串表、原局部符号边界、复制后的函数定义、原有 CALL26 记录保留、输出保护、重复处理与多符号表拒绝检查通过。
- 原静态工具回归通过：JSON/blob、四种配置 ABI、生产业务宿主测试和 ASan/UBSan。
- 普通仓库门禁 16/16，0 失败、0 警告，其中工具判据自检 21/21。其他角色同期修正了此前的公开卫生及报告问题，本轮没有修改其文件。

输出及日志另存于 `local/legacy-import-e223oes3`。原候选、上轮派生件、报告及收据保留。本轮未连接设备，未提交冻结或发布。

## Oracle 边界

`test_legacy_kp.py` 保持原 SHA-256 `cbe4e29e60fe010bfbe2dcbd988cdeffe7b6377dfa94c85caa2991aba2ea022a`；它要求仅替换名称的原断言仍与正确转接方案冲突。原 FAIL 及复核请求见前轮报告，本轮不删改断言、不关闭问题。上述门禁及新增检查通过不表示旧测试已经通过。

## 自查决策（Decision）

**修改（Modify）后保留**。有效性：缺失导入时追加全局对象，并保持原符号与重定位索引；真实 run_cmd 两份产物和共享表反例通过。简洁性：已有导入分支保持字节一致，新增工作集中于工具，不向模块增加无用引用。后果：多符号表不符合 KP 的读取方式而拒绝；原名查找不具备 suffix 兜底，仍需独立复核与真机验证。限范围反例审查识别并核对了共享字符串表及单 symtab 契约。

按 no-negative-echo 回读 CLI、收据、报告与新增自检；按 respect-the-oracle 仅追加测试。技能说明以 [补丁建议](responses/2026-10-10-legacy-kp-pointer-import-skill.patch) 交维护者落地。
