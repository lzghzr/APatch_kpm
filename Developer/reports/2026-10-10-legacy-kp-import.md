# 旧 KP 原名查找的临时移植入口

Developer；2026-10-10。本轮将使用者提供的旧 KP 缺导出方案放入根目录 `patch_offsets.py`，新增显式 `legacy-kp` 子命令。工具修改处于工作树探索状态；工具基准 commit、文件指纹、十份输入的完整 source commit / parent instance_id / 原始与派生 SHA-256 见 [自检收据](data/2026-10-10-legacy-kp-selfcheck.json)。本记录是 Tier-3 离线自检，未做独立审计或真机测试。

## 使用条件与行为

运行端报 `unknown symbol: kallsyms_lookup_name_by_suffix`，且模块需要的目标符号能按原名取得时使用。当前 SDK 两个查找函数的签名均为 `unsigned long (const char*)`；[后缀实现](../../KernelPatch/kernel/base/start.c) 先查原名，失败后才尝试后缀。因此替换可移除这一导入阻断，但会失去后缀兜底；4.4 版本号、缺导出解决及整模块运行兼容性是不同事实。

```bash
python3 patch_offsets.py legacy-kp local/target.kpm --output local/target-legacy.kpm
```

该命令用于静态和动态 ARM64 KPM，解析 SHT_SYMTAB 及其关联字符串表，只把未定义 global/weak 的 `kallsyms_lookup_name_by_suffix` 名称换成 `kallsyms_lookup_name` 并补零。文件长度、节表、符号索引、代码、重定位、模块信息和偏移表保留；相同的 rodata 文本保留。拒绝已定义符号、与其它符号共享的尾部名称、与其它节重叠或分配到运行内存的字符串区域，以及已有输出。

输出新 KPM 与 `.compat.json`，记录源/输出哈希及修改范围。存在配套 `.kpm.json` 时先验证，再生成哈希更新的输出布局；另存的布局可用 `--layout`。动态 KPM 不要求静态偏移表。来源候选、布局、登记及审计报告保持原样；派生产物不是原候选的实机测试结果。

## 临时边界

构建和发布不默认应用，模块源码与 KP 源码保持既有实现。运行端 KP 修复兼容性并具备正常导出后，使用原始产物；`legacy-kp` 入口、专用自检和技能中的临时操作说明可删除。不要将此方案扩展为按 Linux 版本自动改写导入的常驻分支。

## 验证

- 十份实际输入：rek、rekx 各动态/静态普通/debug 四份，run_cmd_demo 普通/debug 两份。只读读取归档，逐项复算来源哈希；输出重新解析导入并逐字节确认仅目标字符串范围变化。
- 四份实际静态布局：偏移表 90 字节及 ABI 不变，输出布局哈希正确，dump/patch 可继续使用；先改偏移再改导入与相反顺序得到相同 KPM 字节。
- 新增 `Developer/tools/test_legacy_kp.py`：覆盖动态 KPM、相同 rodata、已定义/共享名称/分配字符串/节重叠/截断/重复处理拒绝、输出保护和静态布局衔接。测试使用独立的轻量 ELF 读取检查输出；它仍属于 Developer 自检。
- 原 `re_kernel_x/tools/test_static.py` 字节和判据保留，以冻结静态候选运行，JSON/blob、四种释放 ABI、协议与 ASan/UBSan 业务回归通过。

本轮没有分析新的内核镜像、运行设备加载或验证其它 KP 导出；待 Tester 在绑定来源和派生哈希的产物上验证。私有证据位于 `local/legacy-kp-3figbbkb`，十份临时检查件不作为发布候选。

## 自查决策（Decision）

**修改（Modify）后采用**。有效性：精准替换未定义导入并复核真实产物；简洁性：复用已有补丁入口与布局校验，不引入运行时兼容分支；后果：明确原名查找失去后缀能力，保留旧资产和独立派生哈希。按 no-negative-echo 回读最终操作说明；按 respect-the-oracle 保留既有断言，专用自检只追加到 Developer 路径。
