# zram_zstd 开发约定

本模块属于 Developer 路径。源码缩进遵循根目录 `.clang-format`；`zstd` 子模块中的上游文件保留原有格式和版权声明。

## 接入与生命周期

通过 `crypto_register_alg()` 注册 `zstd-kpm`，算法名也为 `zstd-kpm`。现有 zram 继续管理压缩页与 CPU 压缩流。模块不改变已经初始化的 zram，也不修改交换空间配置。

嵌入事件使用 `post-kernel-init`，先完成原生初始化，再在 Android 用户空间配置 zram 前注册。`pre-kernel-init` 在任何 Crypto API 调用前拒绝：算法查询可能触发模块请求和原生测试，不能当作单纯只读表查询。

检测到已有 `zstd-kpm` 算法时，以 `-EEXIST` 结束加载，尚未发布任何模块资源。手动加载仅验证模块接入，不证明开机配置已选择 ZSTD。

`cra_module` 保持 NULL。KPM 的模块对象与原生 LKM 不同，不能填入该字段；使用内置算法的引用语义，模块必须常驻。注册链表本身就持有模块存储，不能仅看当前是否有压缩操作判断可卸载。当前 KP 的退出返回值无法阻止释放，仅给出不可卸载提醒。

算法列表显示放 `zs_display.c`。注册成功后，先 wrap `do_init_module` 的加载完成入口，再检查已有 zram；该入口在目标中保留，避免通知 dispatcher 被 LTO 内联而漏事件。成功返回后再尝试安装 `zcomp_available_show` 的 after 回调，保留原返回值；两种安装路径在原生 `module_mutex` 下串行。地址必须确认属于核内代码或 LIVE 的 LKM，不能把查到符号等同于模块已就绪。`zs_structs.h` 只复用本轮目标已核对的 module state 首字段，未使用 module 的其余布局。用户指定 zram 与 KPM 常驻，本模块的加载和显示 hook 同样常驻。

列表只追加未出现的完整 `zstd-kpm` token；保留 `[zstd-kpm]` 和已有算法。返回长度与结尾换行先检查，NUL 计入容量；写入限于缓冲区当前 4 KiB 子页的剩余空间，兼顾 `recomp_algorithm` 传入的带前缀地址和 ARM64 4/16/64 KiB 页。注册成功后，显示依赖或 hook 失败仅降级为直接写入算法名，不能返回 init 错误让 Crypto API 引用已释放的 KPM。

## 文件与偏移

`zs_structs.h` 保存核对过的共同前缀和成员片段，能够覆盖的字段直接由定义访问；只有未覆盖的名字数组长度、回调区位置及 transform 上下文位置才获取目标偏移。`zram_zstd.c` 保存初始化、编解码和注册逻辑，`zs_offsets.c` 保存配置表、固定窗口函数推导、获取方式调度与公共检查，`zs_btf.c` 独立保存 BTF 查询，`zs_runtime.c` 将编译器生成的内存函数转接到 KP 导出。公共指令宏、BTF 查询使用根目录 `kpm_utils.h`。开始修改前读取 `kpm-development`、`kernel-offset-derivation` 与用户指定的复核技能；先比较目标中的短函数入口，再编写推导。指令识别和解码复用公共宏，缺少的宏在公共头按现有模板补齐。

算法存储为模块持有的 1024 字节清零块，按 128 字节对齐。只填写必要成员，不将本地 `sizeof(struct crypto_alg)` 当作目标布局。BTF 路径核对实际结构大小和被使用的连续成员片段。

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

ZSTD v1.5.7-kernel 通过 `zstd` Git 子模块固定到 `5d9fb4785030731a155a8abe159e10965d824e4b`。`tools/prepare_codec.py` 保存生成选项，准备源码时核对子模块提交与父仓库记录一致，并要求子模块工作树干净。脚本使用上游 freestanding 工具与官方 kernel `mem.h`／`zstd_deps.h`，只在新输出目录准备源码并写入生成清单。xxHash 保留子模块中的原字节，通过构建宏提供静态状态声明并禁用库内分配。KPM 从这些源码编译，宿主安装的 libzstd 仅作独立互解自检。兼容头提供类型、非对齐访问、字节交换、64 位除法与标准限值；不依赖目标内核的 ZSTD 或 xxHash 导出。

压缩级别沿用该 Crypto API 封装的 3。每个原生 transform 独立持有压缩、解压工作区，创建时使用 `ZSTD_estimateCCtxSize(3)`／`ZSTD_estimateDCtxSize()` 取得单次编解码工作区大小，检查错误后分配，调用 `ZSTD_initStaticCCtx()`／`ZSTD_initStaticDCtx()` 初始化；退出时释放，热路径不分配工作区。

加载前的页面比对只验证库，不证明注册布局或原生回调路径。`tools/selfcheck.py` 在实际目标入口字节上运行生产 C，并用目标内核页面验证编解码及独立 libzstd 互解。宿主检查不能替代原生注册、并发、内存回收和交换空间压力测试。

编译产物使用新的输出目录。正式交接从冻结提交构建，探索产物不作为验收候选；已冻结资产只读。新增模块的登记与发布由维护者处理。

## 控制接口与二进制转接

`ctl0` 沿用 rek 的彩蛋：忽略输入参数，返回含 NUL 的 `_(._.)_` 八字节字符串。先检查输出指针和长度，再检查 `compat_copy_to_user()` 的实际复制长度。

运行端 KP 缺少所需导出时，可在普通 KPM 生成后使用 `patch_offsets.py legacy-kp` 转接。模块元信息记录偏移模式；转换身份通过独立实例和 `.compat.json` 回执追溯，静态版同时更新配套布局 JSON 的产物哈希。直接调用经原名函数指针变量取值，禁止跳到其数据地址。是否需要转接依据运行端 KP 的导出契约，与内核版本号和结构体偏移模式分别判断。

源码与 Makefile 以当前 KernelPatch SDK 构建普通 KPM。转接仅由外部 Python 工具修改已生成的 KPM 字节；保留普通候选的完整身份、转换工具提交及哈希、转换命令、输入／输出哈希和回执，写入独立的新输出目录。

普通候选使用 `--target "all"`，额外捕获 `patch_offsets.py`。Makefile 只使用其 `baseline` 子命令生成静态布局 JSON；静态偏移配置使用 `patch` 子命令，这两项与 KP 版本转接分别处理。构建结束后，单独运行 `Developer/tools/test_legacy_kp_metadata.py` 检查普通 KPM 的二进制转接；需要 Clang 与同目录的 `ld.lld`，推荐使用 NDK 工具链。自检保留历史可选字段夹具，并覆盖实际 KPM 元信息字节保持、直接调用和原名指针导入、精确修改范围、静态布局与输出保护。回执与自检结果作为同轮证据留存。

## 源码准备与构建

在仓库根目录初始化子模块，再进入模块目录构建。需要 Android NDK 或已配置的 ARM64 交叉工具链。

```sh
git submodule update --init --recursive
cd zram_zstd
make all OUT_DIR=../local/zram-build LAYOUT_DIR=../local/zram-build
python3 ../patch_offsets.py legacy-kp 普通.kpm --output 转换后.kpm
```

每次使用新的空输出目录。`zstd/` 是本模块的上游源码子模块；父仓库中的子模块逻辑名保持稳定，以便身份工具在目录迁移后读取历史冻结对象。正式候选仍通过统一构建入口从冻结提交登记。

## 构建产物

Makefile默认只生成dynamic/static两种实际偏移模式，不生成单独debug件。当前CONFIG_DEBUG不参与模块行为；初始化偏移与错误日志继续由logkm输出。原有debug归档、审计及测试记录保留，新候选使用target all。
