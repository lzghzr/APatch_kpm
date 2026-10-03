# re_kernel offset harness

离线复现 `re_kernel/re_offsets.c` 的 `calculate_offsets()`：把用户放在 `kernel_img/` 下的
`boot.img` 解包成裸 arm64 Image，在宿主机上解出每个内核的 `struct struct_offset`，输出
「版本 × 偏移」矩阵。用途：给 re_kernel 加新功能（新偏移 pattern）时，不必逐版本人工反编译验证，
一条命令在全部镜像上回归。

> **自检边界**：本工具与设备上的 C 代码同源（`offsets_calc.py` 是 `re_offsets.c` 的逐位移植）。
> 它能证明「移植一致」，不能证明「推导正确」。跨版本正确性要 Auditor 用独立实现复核。

## 目录约定

```text
kernel_img/<major>/<sub>/boot.img      用户放置的原始 img（不进 git，见 ../README.md）
kernel_img/<major>/<sub>/kallsyms.txt  可选：相对 _text 的真实地址符号表
local/extracted/<major>/<sub>/Image    提取出的裸 kernel（不进 git，仓库根 local/）
local/extracted/index.json             标签 → 源 img / 版本 / sha256 索引
local/kernel_offset/<major>/<sub>/trace.log      与 CONFIG_DEBUG logkm 同格式的推导过程
local/kernel_offset/<major>/<sub>/struct_offset.c   该内核的 C 初始化器（re_vmlinux.c 输出格式）
local/kernel_offset/<major>/<sub>/<anchor>.asm   锚函数反汇编（capstone）
local/kernel_offset/<major>/<sub>/kallsyms_extracted.txt  内嵌提取的符号表（若有）
local/kernel_offset/report.md                    状态表 + ver4/5/6 判定标志 + 偏移矩阵
local/kernel_offset/offsets.json                 机器可读结果
```

标签（label）由输入位置推导：目录里的镜像用**目录路径**当标签（`4.9/miui`），平铺文件用**镜像内嵌版本**
（`5.15/5.15.189-android13-8-00016`）。`kernel_img/` 的结构不强制（见 ../README.md），
`local/` 下的目录名同样只是建议——`--local` / `--out` 可改成任何位置与名字。

## 原理

re_kernel 运行时的偏移推导是纯指令模式匹配：通过 kallsyms 找到锚函数（`binder_alloc_init`、
`binder_proc_transaction`、`skb_trim`……），用 `kpm_utils.h` 的 `inst_get_*` 位域解码器扫描指令流。
本工具把这套逻辑 1:1 移植到 Python（`re_insts.py` + `offsets_calc.py`），语义与设备上的 C 代码
逐位一致（包括 IZERO/UZERO 哨兵、回退符号、循环边界、continue/break）。

符号表来源按优先级（`run.py:select_symbols`）：

1. `kernel_img/<major>/<sub>/` 里的符号表（`kallsyms.txt` / `*.kallsyms`）——需要真实地址；
   地址被抹零的 `/proc/kallsyms` dump 只用作名字交叉校验；
2. 镜像内嵌提取（`kallsyms_extract.py`）——直接解析 Image 里的 kallsyms 结构
   （base-relative 与 pre-4.6 absolute 两种模式，容忍字段间零填充、token_index 被抹零、截断镜像）。

## 用法

```bash
cd kernel_img/offset_harness

python3 extract_kernel.py --list          # 有什么（文件名 → 标签，含上次提取的标签）
python3 extract_kernel.py                 # 提取全部：裸 kernel 写到 local/extracted/<标签>/Image
python3 extract_kernel.py --image B2N-416G_boot.img   # 只提取点名的那个（文件名/stem/标签/子串）
python3 extract_kernel.py --pick          # 多个镜像时交互式挑一个（仅 TTY）
python3 extract_kernel.py --img ../x.img --label 4.9/miui   # 单个文件、显式标签
python3 extract_kernel.py --force         # 覆盖已提取文件（默认同哈希则复用）

python3 run.py --list                     # 列出 kernel_img/ 下的条目后退出
python3 run.py                            # 全量回归
python3 run.py --image B2N-416G_boot.img  # 只处理点名的镜像
python3 run.py --image 4.14               # 也可以按上次提取出的标签挑（4.14/4.14.356-Liberty）
python3 run.py --kernel 4.9/miui          # 按标签精确挑选（等价写法）
python3 run.py --pick                     # 多个镜像时交互式挑一个（仅 TTY）
python3 run.py --out /tmp/offset          # 输出改到别处（默认 local/kernel_offset）
python3 run.py --trace-insn               # 每条指令的 trace（巨大，排错用）
```

依赖：Python 3 + capstone（仅反汇编清单用，`pip3 install capstone`，缺了会跳过 `.asm`）。
zstd/lz4 压缩的内核需要 `zstandard` / `lz4`，gzip/xz 用标准库。

## 点名一个镜像的移植任务

"为 `B2N-416G_boot.img` 移植 `dont_kill_freeze`" 这类需求的工作方式：

1. `extract_kernel.py --image B2N-416G_boot.img` 把它的裸 kernel 解到 `local/extracted/`；
2. `run.py --image B2N-416G_boot.img` 看**该模块用到的锚点/偏移**在这个内核上的取值
   （注意 `offsets_calc.py` 目前只覆盖 re_kernel 的偏移集合：为别的模块移植时，先在
   `offsets_calc.py` / `re_insts.py` 里补上该模块用到的锚点与字段，再跑）；
3. 需要"这个内核到底有没有某符号"时，让 Auditor 的产物审计用本地语料核对：
   `python3 Auditor/tools/artifact_audit.py --module <模块>`（语料来源会打印在报告头部）。

## 加一个新内核

1. 按 `kernel_img/README.md` 放好镜像：`kernel_img/<大版本>/<小版本>/boot.img`。
2. `python3 extract_kernel.py` —— 支持 Android boot v0~v4、`UNCOMPRESSED_IMG` 包装、
   裸 Image、gzip/xz/zstd/lz4，厂商头不规范时会在页对齐偏移上扫描签名。
3. `python3 run.py --kernel <标签>` 先跑单个；失败信息在 `out/report.md` 与终端输出里。
4. **本 harness 取不到符号表时状态是 SKIP**（常见于内嵌提取失败；**这不等于内核不含 kallsyms**，
   定性需要独立提取器，见 AUD-018）：该镜像不参与偏移推导，也**不算失败**（`run.py` 退出码仍是 0，
   `report.md` 会写明"本 harness 提取失败"）。
   需要让它参与推导时再补一份带真实地址的符号表：从设备抓 `/proc/kallsyms`（`kptr_restrict=0`），
   把地址换算成相对 `_text` 的偏移，存成 `kernel_img/<大版本>/<小版本>/kallsyms.txt`。
   只有名字没有地址的 dump 不能用于推导。
   也可以直接从设备 dump 出带地址的符号表放到同一目录，优先级高于内嵌提取。

## 输出与命名

- 报告与矩阵在 `local/kernel_offset/report.md`，机器可读结果在 `local/kernel_offset/offsets.json`；
- 每个标签一个子目录 `local/kernel_offset/<major>/<sub>/`，与 `local/extracted/` 一一对应；
- 输出与提取产物都属**用户数据**，统一放在 `local/` 下（`.gitignore` 已忽略，不会公开）；
- 报告里的 `kernel sha256` 是**提取出的裸 kernel** 的哈希，可用于把结论绑定到具体字节。

## 已知事实

- 本仓库不再内置内核语料（原先的 `kernel_test/corpus/` 已移除）；镜像由使用者在
  `kernel_img/` 下提供，因此「哪些内核已验证」取决于本地放了什么，报告里的清单才是事实来源。
- 2026-10-02 实测（3 个镜像）：
  - `4.4/4.4.192-perf+`（gzip 内核，boot v0）→ PASS，143724 个符号，fallback `binder_proc_dec_tmpref`；
  - `5.15/5.15.189-android13-8-00016`（裸 Image，厂商头 page_size 非法、kernel_size 小于 arm64
    头的 image_size）→ PASS，159332 个符号；
  - `4.14/4.14.356-Liberty`（`UNCOMPRESSED_IMG` 包装，声明大小小于 arm64 头 image_size）→
    **SKIP（未覆盖）**：本 harness 的提取方法在该镜像上失败；**尚未定性内核是否含 kallsyms**
    （审计独立抽查发现该镜像里确有 `kallsyms` 相关字节与 NUL 分隔名称表片段，既不能证有也不能证无）。
  - 5.4 / 5.10 / 6.1 / 6.6 等条目来自**已废弃的旧语料**（原 `kernel_test/corpus/`），
    不再要求恢复；跨版本清单以当前 `kernel_img/` 里实际放的内容为准。
- 4.x 的 `binder_proc_is_frozen/outstanding_txns` 为 0（binder freeze 通知 5.4+ 才有），非错误；
  4.4 的 `binder_transaction_buffer_release` ver4/ver5/ver6 全为 UZERO → 运行时走默认 5 参 dispatch。
