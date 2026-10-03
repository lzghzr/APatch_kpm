# kernel_img：用户放置内核镜像的目录

把 `boot.img`（或已经解好的裸 arm64 `Image`、从设备 dump 的符号表）放进这里，
开发者就能离线跑偏移推导回归。

> **这个目录是用户数据**：里面的镜像与符号表都不进 git（`.gitignore` 已排除，见下方"版本库边界"）。
> 仓库只跟踪本说明与 `offset_harness/` 工具。**目录结构怎么放都行，下面的只是一种建议**——
> 工具会自己扫描并推导标签，不需要你按规则摆放。

## 怎么放（建议，不强制）

```text
kernel_img/
├── 4.9/                                  # 建议：第一层按大版本（major.minor）
│   ├── default/boot.img                  #   第二层用子版本/机型/变体
│   └── miui/{boot.img,kallsyms.txt}
├── 4.14/Liberty/boot.img
├── 5.15/boot.img                         # 也可以只分一层
├── boot_flat.img                         # 也可以完全平铺
└── my_device/2024-05/boot.img            # 任意层数、任意目录名都行
```

工具的处理方式：

| 你怎么放 | 得到的标签（label） |
| --- | --- |
| 目录里的镜像（任意层） | 相对 `kernel_img/` 的目录路径，如 `4.9/miui`、`5.15` |
| 同一目录放了多个镜像 | 目录路径 + 文件名，如 `4.9/miui/boot2` |
| 直接平铺在 `kernel_img/` 下 | 解包后取镜像内嵌的内核版本，如 `5.15/5.15.189-android13-8-00016`；取不到版本时用文件名 |
| 只有符号表没有镜像 | 保留为 SKIP 项，可用于跨版本符号核对（不推导偏移） |

> 标签只在**处理之后**才确定（平铺镜像要解包才知道版本），所以第一次只能按**文件名**挑；
> 提取过一次后，`local/extracted/index.json` 会记住"文件名 ↔ 标签"，之后就能用 `--image 4.14` 这样挑。

想固定标签时用显式参数：`python3 extract_kernel.py --img ../x.img --label 4.9/miui`。

### 只处理其中一个（点名的那个）

需求里点名了镜像时（例如"为 `B2N-416G_boot.img` 移植 `dont_kill_freeze`"），只处理它：

```bash
cd kernel_img/offset_harness
python3 extract_kernel.py --list                      # 先看有什么：文件名 → 标签（含上次提取的标签）
python3 extract_kernel.py --image B2N-416G_boot.img   # 只提取它
python3 run.py --image B2N-416G_boot.img              # 只对它跑偏移推导
```

- 选择器支持：文件名、去扩展名的 stem、标签（`4.14/4.14.356-Liberty`）、大小写不敏感子串（`--image 4.14`）。
- 匹配到多个/一个都没匹配到 → 工具报错并**列出候选**，不会自己挑一个。
- 人类在终端里可以让工具问：`--pick`（仅 TTY）会列出候选让你输入编号。
- 没点名又有多个镜像时，**先问清楚用哪个**再动手；只有做全量回归才不加选择器。

符号表（**可选**，建议放在对应镜像同一目录）：`kallsyms.txt`、`*.kallsyms`、`kallsyms_<名字>.txt`。
harness 取不到符号表时该内核会被标为 **SKIP（未覆盖）**，不参与偏移推导，也不是失败
（**SKIP 不等于内核不含 kallsyms**，只是本 harness 的提取方法在这张镜像上没成功）；
需要它参与推导时补一份带真实地址的符号表即可。
镜像内嵌 kallsyms 提取失败的内核（部分厂商 4.14/5.10 内核）需要它才能推导偏移；
地址要相对 `_text`（即镜像内文件偏移）。带真实地址的符号表优先级高于内嵌提取。

## 三步用法

```bash
cd kernel_img/offset_harness
python3 extract_kernel.py                 # 提取裸 kernel 到 local/extracted/<标签>/Image
python3 run.py                            # 推导偏移，输出到 local/kernel_offset/<标签>/
python3 run.py --kernel 4.9/miui          # 只跑指定标签（也可以直接写源文件名）
```

`local/` 不存在时工具会自动创建；里面的目录名只是**建议**，`--local` / `--out` 可以改成任何位置。

详细说明、输出格式与排错见 [offset_harness/README.md](offset_harness/README.md)。

## 版本库边界

| 内容 | 位置 | 进 git？ |
| --- | --- | --- |
| 用户放置的原始 `img` | `kernel_img/**`（`README.md` 与 `offset_harness/` 除外） | **否** |
| 用户放置的符号表 | `kernel_img/**/*.kallsyms`、`kallsyms_*.txt` | **否** |
| 提取出的裸 kernel、索引 | `local/extracted/**` | **否** |
| 分析输出（报告/反汇编/矩阵） | `local/kernel_offset/**` | **否** |
| 工具与说明 | `kernel_img/README.md`、`kernel_img/offset_harness/**` | 是 |

约定：**运行产生的本地文件都放仓库根的 `local/`**（`.gitignore` 整体忽略该目录），主目录保持干净。
检查方式：

```bash
git status --short          # 不应出现 *.img 或 local/ 下的条目
git check-ignore -v kernel_img/4.9/default/boot.img local/extracted/x/Image local/kernel_offset/report.md
```
