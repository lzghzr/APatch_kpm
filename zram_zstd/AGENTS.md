# zram_zstd 开发约定

本模块属于 Developer 路径。源码缩进遵循根目录 `.clang-format`；`upstream/zstd` 子模块中的上游文件保留原有格式和版权声明。

## 接入与生命周期

通过 `crypto_register_alg()` 依次注册 `zstd-kpm`、`lz4-kpm`、`lz4kd-kpm`；cra_name/driver_name相同。注册前使用 SDK `read_tcr(1)` 读取一次 `TCR_EL1.TG1` 并缓存为 `zs_page_size`：2/1/3 分别为 4096/16384/65536，保留编码 0 记为未知。仅缓存为 4096 时注册 LZ4KD；其它结果只跳过该项并记录日志，ZSTD/LZ4 的 Crypto 注册保持。缓存发布前完成赋值，随后两个前端只读，不在逐页路径重复检测。算法版本由加载日志及 `zstd_version` / `lz4_version` / `lz4kd_version` 元信息记录。现有 zram 继续管理压缩页与 CPU 压缩流。模块不改变已经初始化的 zram，也不修改交换空间配置。

嵌入事件使用 `post-kernel-init`，先完成原生初始化，再在 Android 用户空间配置 zram 前注册。`pre-kernel-init` 在任何 Crypto API 调用前拒绝：算法查询可能触发模块请求和原生测试，不能当作单纯只读表查询。

检测到上述任一名字已有算法时，以 `-EEXIST` 结束加载，尚未发布任何模块资源。手动加载仅验证模块接入，不证明开机配置已选择 ZSTD。

`cra_module` 保持 NULL。KPM 的模块对象与原生 LKM 不同，不能填入该字段；使用内置算法的引用语义，模块必须常驻。注册链表本身就持有模块存储，不能仅看当前是否有压缩操作判断可卸载。当前 KP 的退出返回值无法阻止释放，仅给出不可卸载提醒。

算法列表显示放 `zs_display.c`。注册成功后，先 wrap `do_init_module` 的加载完成入口，再检查已有 zram；该入口在目标中保留，避免通知 dispatcher 被 LTO 内联而漏事件。成功返回后再尝试安装 `zcomp_available_show` 的 after 回调，保留原返回值；两种安装路径在原生 `module_mutex` 下串行。地址必须确认属于核内代码或 LIVE 的 LKM，不能把查到符号等同于模块已就绪。`zs_structs.h` 只复用本轮目标已核对的 module state 首字段，未使用 module 的其余布局。用户指定 zram 与 KPM 常驻，本模块的加载和显示 hook 同样常驻。

列表只追加实际注册成功且未出现的三个稳定名，保留其它算法及选中括号。按完整 token 判断已有名字；先计算完整结果长度，容量不足不写；返回长度与结尾换行先检查，NUL 计入容量；写入限于缓冲区当前 4 KiB 子页的剩余空间，兼顾 `recomp_algorithm` 传入的带前缀地址和 ARM64 4/16/64 KiB 页。注册成功后，显示依赖或 hook 失败仅降级为直接写入算法名，不能返回 init 错误让 Crypto API 引用已释放的 KPM。

入口的 `crypto_register_alg`、`vzalloc`、`vfree` 都通过 SDK 的编译器后缀查找解析。
仅对已核对同 ABI 的分配入口增加 `vzalloc` → `vzalloc_noprof` 回退，旧名存在时优先旧名；
`_noprof` 是已确认的分配 API 名，与 SDK 编译器后缀匹配分别处理；释放和注册函数继续使用已确认原名。
必需入口仍缺失时，在分配和注册前返回 `-ENOENT`，日志按名称记录缺项而不打印地址。

## 新版 zram 前端（1.3.0）

`zs_native.c` 接入 `zcomp_ops`，与 Crypto 前端共用编解码核心，但使用独立的真实上下文。
在现有 `module_mutex` / LIVE 检查内，通过 `module_kallsyms_lookup_name("zram:…")` 定位后端与两个 hook 点。
只拦截三个完整 KPM 名字；原生名字继续走原实现。模块 BTF、完整布局、回调原型、对象归属和原生 KCFI 标签均需吻合。
本轮新前端仅支持模块形式的 zram；旧 Crypto 前端的内建及晚加载路径保持。目标依据为 boot_405 的配套 zram.ko。

`zs_native_btf.c` 校验本地结构定义；GFP 位与 CPUHP 状态由真实 base BTF 枚举取得，页大小复用注册前取得的 `zs_page_size`。未知页大小时不开放 native 后端；该路径不再单独检测。
不能按内核版本选布局。新版 LZ4KD 仅在确认 4 KiB 页时开放；16 KiB 实验编码器不进入此候选。
新版前端支持无字典、默认级别或明确的 ZSTD 3 / LZ4 1；其它请求返回 `-EOPNOTSUPP`。

构造器分配 zcomp/per-CPU 存储，交由原生 CPUHP 回调建立每 CPU 上下文及缓冲区；成功后由原生 zcomp_destroy 回收。
CPUHP add 失败已经回滚此前 CPU，不再 remove。先 pin 住原生 zram 模块，再安装 create/available 两个 hook；
只有两个都成功才发布 ready，第二个失败撤回第一个并释放引用。成功后 zram 与 KPM 均常驻。

`zs_native_entry.S` 提供十个带匹配 KCFI type ID、BTI c 和直接尾跳转的入口；C worker 保持 NDK 构建。
加载时核对实际原生回调标签，不依赖 KP 的 CFI 失败处理。二进制自检精确核对入口、前缀及 JUMP26 重定位，
只把验证通过的十个 4 字节前缀计为数据；其余可执行节仍逐条解码，拒绝未识别数据、FP/SIMD/SVE/x18。

新增检查 `tools/test_native.py --btf <base> --module-btf <split> --output <新目录>`，
执行真实 BTF 查询及生产 C，在两 CPU 宿主模型中覆盖构造、清理、参数、选择与页大小边界。
这不替代原生 CPUHP、CFI 和交换空间压力测试。

## 文件与偏移

`zs_structs.h` 保存核对过的共同前缀和成员片段，能够覆盖的字段直接由定义访问；只有未覆盖的名字数组长度、回调区位置及 transform 上下文位置才获取目标偏移。`zram_zstd.c` 保存初始化、编解码和注册逻辑，`zs_offsets.c` 保存配置表、固定窗口函数推导、获取方式调度与公共检查，`zs_btf.c` 独立保存 BTF 查询，`zs_runtime.c` 将编译器生成的内存函数转接到 KP 导出。公共指令宏、BTF 查询使用根目录 `kpm_utils.h`。开始修改前读取 `kpm-development`、`kernel-offset-derivation` 与用户指定的复核技能；先比较目标中的短函数入口，再编写推导。指令识别和解码复用公共宏，缺少的宏在公共头按现有模板补齐。

每个注册名字各用模块持有的 1024 字节清零块，按 128 字节对齐。只填写必要成员，不将本地 `sizeof(struct crypto_alg)` 当作目标布局。BTF 路径核对实际结构大小和被使用的连续成员片段。

动态版按 rek 的契约分层：`calculate_btf_offsets()` 返回 `-ENODATA` 才调用 `calculate_function_offsets()`；有效 BTF 的错误直接返回，成功结果再经过公共存储范围检查。静态版只检查配置表。

短函数路径使用固定窗口：

| 锚点 | 指令窗口 | 字段 |
| --- | --- | --- |
| `crypto_compress` / `crypto_comp_compress` | 前 16 条 | `cra_u.compress.coa_compress` |
| `crypto_check_alg`；缺符号时检查内联调用者 `crypto_register_alg` | 前 16 / 32 条 | `cra_driver_name` |
| `crypto_mod_get` | 前 8 条 | `cra_module`，减 24 得 `cra_init` |
| `lzo_init`；缺符号时检查 `crypto_cts_exit_tfm` 的 child 读取与 `crypto_destroy_tfm` 的 base 参数 | 前 16 / 8 条 | `__crt_ctx` |

`cra_flags`、`cra_ctxsize` 与 `cra_name` 起点由 `zs_structs.h` 的共同前缀覆盖，不再单独扫描注册入口取得 flags。两个名字数组等长；长度由 name/driver_name 的距离确定，已选目标分别为 64 或 128 字节；`cra_ctxsize` 是 flags+8，`cra_name` 是 flags+24。压缩与解压回调相邻；`cra_init` 后依次为 exit、destroy、module。这些关系依据原生声明，BTF 可用时必须核对，不能用版本号猜测。

旧内核自检使用用户选定的 4.4、4.9、4.14 镜像；完整身份、参考锚点和覆盖结果记录在 Developer 报告。入口 MOV 必须同时保留参数与别名，BL/BLR 清除 caller-saved 寄存器；其它目标寄存器写入、pair 第二目标及访存写回使相关别名失效。遇 RET 或无条件 B 停止，扫不到即报错。

目标 4.4 的参考值还由其它实际入口核对：`crypto_check_alg` 读取 flags 邻近字段及名字，`crypto_decompress` 读取解压回调，`crypto_mod_get` 读取 module，`lzo_compress` 读取上下文。不能仅拿同一推导的重复结果当参考。

静态版定义 `CONFIG_KPM_BASELINES`，六个 int16 字段（原五项顺序保留，driver_name 追加）位于 `.data.re_offsets`。基线模板均为 -1，配套 JSON 使用根目录 `patch_offsets.py` 的 schema 3；补丁只改变配置段。运行时符号查询两版共用。

## 算法来源与验证

ZSTD v1.5.7-kernel 通过 `upstream/zstd` Git 子模块固定到 `5d9fb4785030731a155a8abe159e10965d824e4b`。`tools/prepare_codec.py` 保存生成选项，准备源码时核对子模块提交与父仓库记录一致，并要求子模块工作树干净。脚本使用上游 freestanding 工具与官方 kernel `mem.h` 与本模块从官方模板派生的 `zs_zstd_deps.h`，只在新输出目录准备源码并写入生成清单。xxHash 保留子模块中的原字节，通过构建宏提供静态状态声明并禁用库内分配。KPM 从这些源码编译，宿主安装的 libzstd 仅作独立互解自检。兼容头提供类型、非对齐访问、字节交换、64 位除法与标准限值；不依赖目标内核的 ZSTD 或 xxHash 导出。

压缩级别沿用原生 Crypto API 封装的 3；通过 `ZSTD_getParams(3, 0, 0)` 取得未知输入大小的显式参数，不按当前页面大小重新选一套参数。每个原生 transform 独立持有压缩、解压工作区，创建时使用 `ZSTD_estimateCCtxSize_usingCParams(params.cParams)`／`ZSTD_estimateDCtxSize()` 取得单次编解码工作区大小，检查错误后分配，调用 `ZSTD_initStaticCCtx()`／`ZSTD_initStaticDCtx()` 初始化；退出时释放，热路径不分配工作区。

`zstd_encode()` 同时服务注册压缩回调和加载前自检：先 `ZSTD_CCtx_reset(..., ZSTD_reset_session_and_parameters)`，设置本块 pledged size，再用 `ZSTD_CCtx_setParams()` 写入七项压缩参数与三项 frame 参数，最后 `ZSTD_compress2()`。批量 setter 与 Linux 6.6 原生逐字段 setter 的语义由 `tools/native_alignment_fixture.h` 对照；参考来源见 `tools/references/README.md`。每次重置阻断上一个调用的参数或字典状态，编码错误保留调用方 `dlen`。

加载前的页面比对只验证库，不证明注册布局或原生回调路径。`tools/selfcheck.py` 在实际目标入口字节上运行生产 C，并用目标内核页面验证编解码及独立 libzstd 互解。宿主检查不能替代原生注册、并发、内存回收和交换空间压力测试。

编译产物使用新的输出目录。正式交接从冻结提交构建，探索产物不作为验收候选；已冻结资产只读。新增模块的登记与发布由维护者处理。

LZ4 v1.10.0的block源码原字节位于`upstream/lz4/`，提交与BSD-2-Clause见该目录README/许可证及NOTICE。
只编译`lz4.c`，通过`zs_lz4_config.h`启用freestanding、关闭fast decode loop，保留ARM64标量bitcount intrinsic（RBIT/CLZ，不使用SIMD）；
所有代码沿用`-mgeneral-regs-only -ffixed-x18`，实际KPM必须检查零FP/SIMD/SVE、零x18。
transform上下文只有一个工作区指针（ARM64为8字节）；压缩哈希工作区由`LZ4_sizeofState()`取得并在init分配、exit释放，
不把约16KiB哈希表放进内核栈。extState接口每块重置状态，acceleration=1，解压不持有字典/解压上下文。
LZ4 库对象单独追加 `-O3`，与 Linux 6.6 的 `lib/lz4/Makefile` 一致；ZSTD、LZ4KD 和模块入口保持 `-O2`。两者使用同一 NDK 与公共 ARM64 寄存器约束。宿主 sanitizer 自检也单独以 `-O3` 编译 LZ4 对象，其余继续使用原自检优化级别。

依次注册 ZSTD、LZ4、LZ4KD；首项失败时尚未公开资源，直接拒载。ZSTD 成功后模块常驻，后续 LZ4/LZ4KD 失败则关闭该项并记录日志。
不能对已公开算法做失败回滚：旧 Crypto API 注销不等待活跃 transform，可能 BUG；显示层只追加注册成功的名字。不能热卸载。

新增自检：`python3 tools/test_codecs.py --output ../local/<新目录>`（模块目录内运行），
覆盖真实生产注册/部分失败常驻、transform释放、LZ4独立库互解与稳定名显示。

## 内联内存接入与错误判定

`zs_memory.h` 共用三项内存 primitive：小的编译期常量保留 builtin，动态长度与大的常量直接调用 KP 的 `kf_*` 指针。
NDK 标量 O2 的内联选择阈值为 memcpy/memmove 128、memset 256 字节；阈值不限制合法长度，也不增加动态长度分支。
必须在实际 ARM64 产物确认小复制保持内联、库的动态热点没有新增包装调用或小块间接调用循环。
`zs_runtime.c` 的普通符号继续为编译器生成的剩余 libc 调用提供接入，不能直接删除。

LZ4 从现有配置宏接入；ZSTD 通过本模块平台依赖模板接入，上游子模块原字节不变。
`tools/prepare_codec.py` 同时生成只修改两项 primitive 的 LZ4KD private 头，模板不匹配就停止，清单记录生成字节。
宿主驱动链接 `tools/host_memory.c` 为生产适配器提供真实 libc 绑定，不在生产头增加宿主分支。

模块侧 `zs_zstd_config.h` 复用同版上游 `ERR_isError`，保持公开 API 的错误码语义而消除逐页外部判错调用。
原参数 reset、级别、工作区策略及回调签名保持。测试驱动保留原断言，新增内存绑定计数/重叠语义及错误 predicate 等价检查。

## LZ4KD 普通 4 KiB 块

来源固定于 `upstream/lz4kd/README.md` 所记提交，版本为 2022.03.20。KPM 经 `zs_lz4kd_encode.c` 编译上游普通编码器，
`zs_lz4kd_decode.c` 从固定上游解码器派生，保留批量复制与小偏移展开；
`zs_lz4kd.c` 提供共用编解码适配和 Crypto API 回调；三个算法共用现有布局取得、注册与常驻机制，不增加偏移字段。
此算法最多处理 4096 字节，供 4 KiB 内核页的 zram 使用；不增加跨页分块格式。

每个 transform 分配一块 16384 字节工作区：上游 8192 字节哈希表及独立 8192 字节编码 scratch。
热路径不分配内存。短于 32 字节的输入直接生成普通 literal-only 块；上游返回非正值时也生成该块，
仍使用 header=0 的正式格式。调用方声明容量至少 8192 字节时直接编码到输出，跳过 scratch 复制；
更小容量仍在 scratch 完成后核对长度、再复制，失败不改 `dlen` 或输出缓冲区。
直接路径按 8192 字节物理容量门控，不把上游较小的逻辑 out_limit 当作宽写边界。
不做原文冒充编码流的回退。init 分配失败不留指针，exit 清空 workspace 与 scratch。

解码复用上游普通块的 16/32 字节复制与小偏移展开；只在入口检查 header=0、输入上限及输出容量，
去掉按输入长度 8 识别 pattern 的分支，保留正常 8 字节普通块。三处可能重叠的固定 8/16 字节复制
使用显式 builtin memmove，保持上游展开顺序并消除重叠 memcpy 的未定义行为；实际 ARM64 产物应确认其内联。
原始参考解码器仍参与宿主差分；其 length==8 的冲突不作为该长度的参考。
生成的 `zs_lz4kd_private.h` 仅将 `m_copy/m_set` 的内存 primitive 接入本模块内联头；
原始编码器及 private 头字节保持，解码器继续复用同一平台头。
上游派生解码文件保留原格式，局部差异可直接与 `upstream/lz4kd/lz4kd_decode.c` 比较。

`tools/test_codecs.py` 同时复用 `selfcheck_fixture.c` 的列表/晚加载/并发安装检查，覆盖三项精确注册、
全部注册失败组合、独立 transform、1..4096 字节四类数据、容量边界、上游参考解码及畸形流。
新增 `tools/lz4kd_fast_fixture.h` 检查真实 8192 字节输出的直接路径、scratch 未被触及、
与 8191 字节容量的中转路径逐字节一致，以及周期 1..32 和随机输入。
LZ4/ZSTD 的独立库互解继续保留。测试清单迁移依据见 Developer 同轮 Oracle 记录，须 Auditor 复核。

## 控制接口与二进制转接

`ctl0` 沿用 rek 的彩蛋：忽略输入参数，返回含 NUL 的 `_(._.)_` 八字节字符串。先检查输出指针和长度，再检查 `compat_copy_to_user()` 的实际复制长度。

运行端 KP 缺少所需导出时，可在普通 KPM 生成后使用 `patch_offsets.py legacy-kp` 转接。模块元信息记录偏移模式；转换身份通过独立实例和 `.compat.json` 回执追溯，静态版同时更新配套布局 JSON 的产物哈希。直接调用经原名函数指针变量取值，禁止跳到其数据地址。是否需要转接依据运行端 KP 的导出契约，与内核版本号和结构体偏移模式分别判断。

源码与 Makefile 以当前 KernelPatch SDK 构建普通 KPM。转接仅由外部 Python 工具修改已生成的 KPM 字节；保留普通候选的完整身份、转换工具提交及哈希、转换命令、输入／输出哈希和回执，写入独立的新输出目录。

普通候选使用 `--target "all"`，额外捕获 `patch_offsets.py`。Makefile 只使用其 `baseline` 子命令生成静态布局 JSON；静态偏移配置使用 `patch` 子命令，这两项与 KP 版本转接分别处理。构建结束后，单独运行 `Developer/tools/test_legacy_kp_metadata.py` 检查普通 KPM 的二进制转接；需要 Clang 与同目录的 `ld.lld`，推荐使用 NDK 工具链。自检保留历史可选字段夹具，并覆盖实际 KPM 元信息字节保持、直接调用和原名指针导入、精确修改范围、静态布局与输出保护。回执与自检结果作为同轮证据留存。

统一候选构建时显式设置新的 `LAYOUT_DIR=../local/<新目录>`，让生成的 JSON/codec 源码留在 `local/`；KPM 输出仍由统一入口放在模块目录并归档。转接自检用两个 `--kpm <文件名>` 精确列出本轮普通件；不带选择器仍保留历史四件套判据。

## 源码准备与构建

在仓库根目录初始化子模块，再进入模块目录构建。需要 Android NDK 或已配置的 ARM64 交叉工具链。

```sh
git submodule update --init --recursive
cd zram_zstd
make all OUT_DIR=../local/zram-build LAYOUT_DIR=../local/zram-build
python3 ../patch_offsets.py legacy-kp 普通.kpm --output 转换后.kpm
```

每次使用新的空输出目录。`upstream/zstd/` 是本模块的上游源码子模块；父仓库中的子模块逻辑名保持稳定，以便身份工具在目录迁移后读取历史冻结对象。正式候选仍通过统一构建入口从冻结提交登记。

## 构建产物

Makefile默认只生成dynamic/static两种实际偏移模式，不生成单独debug件。当前CONFIG_DEBUG不参与模块行为；初始化偏移与错误日志继续由logkm输出。原有debug归档、审计及测试记录保留，新候选使用target all。


## 开机配置、安装验证与排查

已核对仓库中 4.4～6.6 的内核镜像布局。1.0.0 增加算法列表显示，支持内建 zram 和稍后加载的 `zram.ko`。安装方式自动加载及算法选中已在 4.19 / XQ-AT52 / KP d09 单机验证，5.15 未测，不能外推；详见下方安装说明。模块要求 zram 使用 Crypto API，不能仅凭内核版本判断是否适用。

**嵌入后不要卸载；安装方式加载成功后同样不要热卸载，卸载可能导致内核崩溃。** 要移除模块，嵌入方式先取消嵌入，安装方式先阻止下次目录加载，再重启设备；同时安排开机脚本改用可用的原生算法。

旧 KP 如果提示找不到 `kallsyms_lookup_name_by_suffix`，需要先用 Python 工具转换普通 KPM。转换和静态移植的方法见 [AGENTS.md](AGENTS.md)。

## 怎么启用

1. 先选一种加载方式：下方的“嵌入方式”或“安装方式”。
2. 在设备原有的 zram 开机脚本中，先选择压缩算法，再设置容量、启用交换空间：

   ```sh
   echo zstd-kpm > /sys/block/zram0/comp_algorithm
   ```

   这条命令要放在 zram 初始化之前。如果设备用的不是 `zram0`，换成对应编号。
3. 重启后确认状态：

   ```sh
   cat /sys/block/zram0/comp_algorithm
   cat /proc/crypto
   cat /proc/swaps
   ```

   `comp_algorithm` 里出现 `[zstd-kpm]`、`[lz4-kpm]` 或 `[lz4kd-kpm]`，表示 zram 已经选用了它。`/proc/crypto` 里应能看到 所选主名对应的 `name` 和 `driver`，`/proc/swaps` 中应有目标 zram 交换设备。

只加载模块不会自动切换已经初始化的 zram，还需要开机脚本完成第 2 步。

编译方法和源码说明见 [AGENTS.md](AGENTS.md)。

### 嵌入方式

把 KPM 嵌入启动镜像，加载事件选 `post-kernel-init`，参数留空，使模块在系统配置 zram 前注册算法。本模块拒绝 `pre-kernel-init`，返回 `-EINVAL`。

### 安装方式

需要 APatch/KP 支持目录自动加载。在内核模块页选择“安装”（不是“立即加载”），安装器按管理名称将文件保存为 `/data/adb/ap/kpm/zram_zstd/zram_zstd.kpm`，即 `/data/adb/ap/kpm/<id>/<id>.kpm`；输入文件的版本后缀不影响此路径。启用时应无该目录下的 `disable` 标记，boot 中也不应有同名嵌入件。

重启后，KP 在 `post-fs-data` 的 `before` 事件处理期间读取目录加载，无需设置嵌入用的 `-V`。判定依据为模块版本、`load_source=file`、`load_event=post-fs-data` 及对应目录加载日志 `rc=0`；仅有 `load_source=file` 也可能是手动加载。再按上方步骤确认算法注册、选中状态及 swap。

**已实机验证（含算法被选中）**：结论仅来自 4.19 / XQ-AT52 / KP d09 单机，5.15 未测，不能外推。该次开机从安装文件加载早于 zram 配置，最终为 `[zstd-kpm]` 且 swap 在线；候选身份与记录见 [Tester 报告]。实验以手动复制文件完成，不代表管理器“安装”按钮全流程已实测。

其他目标须确认算法注册早于所选 zram 初始化周期中的算法选择、非零 `disksize` 和 `swapon`。错过该窗口不能靠安装自动切换现有 zram，不要为此在运行中临时 reset。

## 升级流程

上述已验证单机已使用安装方式运行，保持现有 KP、启动链及 zram 配置时，**升级无需重新嵌入**：

1. 保留已知可用 KPM 和开机脚本作为回退，选用已适配目标的新版本。保持 boot 中无同名嵌入件。
2. 替换 `/data/adb/ap/kpm/zram_zstd/zram_zstd.kpm`，确认期望启用且无 `disable` 标记。手工更新时先写同目录临时文件、核对交接哈希和权限/标签，再重命名到固定路径，避免读到半件。此时运行的仍是旧版，不热卸载，也不再加载第二份。
3. 保留有效的开机算法选择流程并重启。
4. 核对新版本、`load_source=file`、`load_event=post-fs-data`、对应目录加载 `rc=0`，以及 `/proc/crypto` 中的所选主名、`comp_algorithm` 中的主名选中括号 和 `/proc/swaps`。核对安装文件哈希与来源，确认新字节实际接管。

更换内核、KP 或启动脚本后须重新确认兼容性与时序。失败且系统仍可用时，恢复已知可用的安装文件并重启；需停用时安排原生算法回退。卡死或无响应时停止重试，保留证据并通知维护者。

## 风险与边界

- 同管理名 `zram_zstd` 冲突返回 `-EEXIST`（-17），不会替换旧实例。嵌入/安装及静态/动态均只选一份。上述任一名字已有算法时也会拒载，改文件名或管理名不能实现热升级。
- `/data/adb/ap/kpm/zram_zstd/disable` **只阻止目录加载**，不卸载当前实例、不改变当前 swap，也不禁用嵌入副本。停用后须重启并核对实际状态；不要使用会触发热卸载的“卸载”按钮。
- 替换已安装文件后需重启才生效。本模块不可热卸载，换版或移除均需重启；即使未选中算法或已 `swapoff`，也不能据此认定可安全卸载。
- 保留 userdata 通常会保留已安装文件，但**不保证 OTA 后兼容**。新 boot 仍须带支持目录加载的 KP，用户态须上报 `before`，并重新核对内核导出、布局/ABI、Crypto/zram 路径及初始化时序；静态偏移不能直接沿用。

## 遇到问题

- 日志中`registration: ...=1`表示该名字注册成功，`=0`表示不可用；再检查zram选中的主名。
- 名字已存在时模块拒绝重复加载；不要热卸载或另加载一份来换版。
- 列表显示 hook 未接入时，可在初始化前直接写入已注册稳定名。
- 找不到符号时检查KP导出，旧KP可能需要二进制派生件；偏移失败时保存日志并适配实际内核。

`/proc/crypto` 显示实际注册成功的稳定名；LZ4KD 仅在确认 4 KiB 页时出现。本轮字节仍需独立审计和真机验证。
