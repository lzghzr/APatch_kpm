# Developer 手册：内核分析 → 偏移推导 → 编码 → 移植

Developer 拥有一切「让功能在目标内核上跑起来」的工作。产出是**可复现候选**，不是结论。

## 0. 先确认目标镜像

`kernel_img/` 下可能同时放着好几台设备/好几个版本的内核镜像。**需求点名了哪一个就只处理哪一个**：

```bash
cd kernel_img/offset_harness
python3 extract_kernel.py --list                      # 有什么：文件名 → 标签（含上次提取的标签）
python3 extract_kernel.py --image B2N-416G_boot.img   # 只提取它（也认 stem / 标签 / 子串）
python3 run.py --image B2N-416G_boot.img              # 只对它跑偏移推导
```

- 没点名而候选有多个时：**先列出候选问清楚**，不要自己挑一个，也不要默默全跑（全量只用于回归）。
- 匹配到多个或零个时工具会报错并列候选，不会替你做决定；`--pick` 可在 TTY 下交互挑。
- 平铺镜像第一次只能按文件名挑；提取过一次后 `local/extracted/index.json` 记住标签，之后可用 `--image 4.14`。
- `offsets_calc.py` 目前只覆盖 `re_kernel` 的偏移集合：为别的模块（如 `dont_kill_freeze`）移植时，
  要先把该模块用到的锚点/字段加进 `offsets_calc.py` / `re_insts.py`，否则 harness 只能做符号存在性核对。

## 1. 内核分析

对每个要支持的内核，先写清楚事实再写代码：

| 要确认的事 | 怎么确认 |
| --- | --- |
| 目标内核范围 | 模块 README 当前声明（`re_kernel`：4.4 ~ 6.6） |
| 需要哪些未导出函数 | 列出符号名、在哪些版本存在、是否被内联/改名 |
| 需要哪些结构体字段 | 字段名、类型、读还是写、是否有锁保护 |
| hook 点与上下文 | 函数是否在持锁/原子上下文被调用；hook 的 `hook_fargsN_t` 参数序 |
| 数据结构归属 | 谁分配、谁释放、并发访问者 |

**禁止**按内核版本号分支（`LINUX_VERSION_CODE`、`utsrelease` 字符串比较）。跨版本差异必须由内容特征（指令模式、字段布局特征、符号存在性）自适应。

## 2. 偏移推导

方法遵循 `.agents/skills/kernel-offset-derivation/SKILL.md`。要点：

1. **头文件优先**：拿得到目标内核 `vmlinux.h`/BTF，且布局跨版本一致 → 编译期 `offsetof()`，零运行时成本。
2. **布局不一致 → 运行时推导**：模块加载时从内核自身推导。
3. **函数锚点选择**：优先控制路径、跨版本都存在、对目标字段有一次明确读写的函数；不选被内联的热路径小函数。
4. **多候选交叉验证**：多个锚点结果不一致时报错或取多数，不静默取其一。
5. **失败即降级**：推导失败走安全默认值或跳过功能；**不要猜偏移**。
6. **哨兵值语义**：`IZERO`/`UZERO` 之类的哨兵必须在注释里写明含义与反向含义（「未设置」vs「全部」），审计会专门检查这类约定。

### 离线语料回归（自检）

```bash
cd kernel_img/offset_harness
python3 extract_kernel.py --list                 # 列出候选
python3 extract_kernel.py --image <目标镜像>      # 提取指定输入（写 local/extracted/）
python3 run.py --image <目标镜像>                 # 目标镜像回归
python3 run.py --kernel 4.4/4.4.192-perf+        # 只跑一个标签
python3 run.py --trace-insn                      # 排错用，输出巨大
```

加新偏移 pattern 的工作流：改 `re_offsets.c` → 把同样的判定逻辑加进 `offsets_calc.py` → 跑全语料看新行的跨版本取值 → 异常版本开 `--trace-insn` 或看锚函数反汇编。

> harness 与设备代码同源，结论只算**自检**。它证明移植一致，不证明推导正确——后者要 Auditor 用独立实现复核。

## 3. 编码

- KPM API 与生命周期见 `.agents/skills/kpm-development/SKILL.md`；模块自带 `KPM_NAME/KPM_VERSION/KPM_LICENSE/KPM_AUTHOR/KPM_DESCRIPTION`。
- `-Wall -O2` 必须干净（现有 KernelPatch 头文件里的 `-Wmacro-redefined` 等历史噪声要在报告中写明，不能新增）。
- **内存上下文**：hook/tracepoint 回调里不要用可睡眠分配（`GFP_KERNEL`、`memdup_user`、`kmalloc` 无 flag 版本）。必须用时先确认调用路径不持锁、不在原子上下文，并在报告里写明判断依据。
- **生命周期**：`kfree`/`proc_remove`/`netlink_kernel_release` 之后立刻把持有它的全局/静态指针置 `NULL`；否则卸载路径会出现释放后使用。
- **用户态入口**：netlink/proc/ioctl 输入必须校验长度、范围，并校验发送方身份（不要假设「只有我的 App 会发」）。
- **并发**：共享状态（UID 过滤表、task local 偏移缓存）要说明是谁在什么上下文读写；无锁读写要写明为什么安全。

## 4. 移植（新内核 / 新功能）

1. 新内核：把 `boot.img` 放进 `kernel_img/<大版本>/<小版本>/`（如 `kernel_img/4.9/miui/boot.img`）；有现成符号表就一起放 `kallsyms.txt`，没有就交给内嵌提取。
2. 先对指定目标镜像回归；用户要求全量回归时再覆盖全部语料；对失败版本先定位是锚点缺失还是模式不匹配。
3. 新功能：先写「要哪些偏移/符号」，再改代码；改动同时更新模块 README 的更新记录。
4. 端到端：`make -C <module> all debug` 产生变体（base / network / debug / network_debug）。

## 5. 必须产出

```bash
make -C re_kernel all debug       # 探索构建
python3 tools/build_candidate.py re_kernel --toolchain "ndk26.3.11579264" --target "all debug"
python3 tools/check_repository.py
```

- 开发报告（[../templates/developer-report.md](../templates/developer-report.md)），含：变更点、自检命令与输出、边界声明、未解决项与降级行为。
- **边界声明原文必须包含**：「本轮结论来自实现方自检（构建 + 离线语料 + 代码走查），不是独立审计，也不是实机结论。」

## 6. 交接给 Auditor 时必须给的

- 完整 commit + instance_id + 产物 SHA-256（`metadata/modules/<module>.json` 已写入）。
- 本轮改动的「意图」：修改了哪些 hook 点/偏移字段/数据结构，哪些是刻意不做的。
- 自检覆盖了什么、没覆盖什么。
- 已知可疑点（自己不确定的地方要主动列出，被审计发现更贵）。
