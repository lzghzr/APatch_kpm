# Genl 短锚点与相邻字段

适用于动态版 `re_kernel` 的 Generic Netlink 偏移推导。优先用独立短函数及已确认的连续字段减少扫描；实际符号和机器码以目标为准。

## 锚点选择

| 字段 | 当前锚点与用途 | 可复用条件 |
| --- | --- | --- |
| `id`、配置段 `hdrsize` | 导出的 `genlmsg_put`，family 从 x3 传入；在第一次调用之前读取两个头部字段 | 短 API，读取用于 nlmsg_put 的消息类型和长度；保留 x3 或 `mov xN,x3` 的一次保存寄存器 |
| `n_mcgrps`、位宽、`mcgrp_offset` | 导出的 `genlmsg_multicast_allns`；入口检查组数，然后加组号偏移 | 外部 API 的职责明确，helper 是否内联不改变入口处的这两个用途 |
| `mcgrps` | 已确认的 u32 连续布局从上面的计数锚点推导；其它形态使用 `genl_unregister_family` 的局部注销模式 | 连续字段依据见下一节，不能只凭计数字段位宽推断任意布局 |
| `net.genl_sock` | `genl_pernet_exit` 的直接读取，然后传给 netlink_kernel_release | 未导出的短回调，但 `.exit = genl_pernet_exit` 使函数地址保留；仍核对 kallsyms 可见性、后缀及入口 |

`genl_family_attrbuf` 在部分目标中是独立、短且导出的函数，可用其 attrbuf 与后续 ops/mcgrps 的连续布局作锚点；五份回归镜像中只有 4.14/4.19 存在，不能作为这一语料范围的唯一入口。保存的 5.15 源码也没有该字段/API。`genl_unregister_mc_groups` 在这五份镜像中没有独立符号，检查内联调用者后再选择局部模式。

`genl_notify` 有导出，所需 socket 读取却经过 `genl_info → net → sock`，还混有 nlhdr 读取与事件处理；当前直接退出回调更短、更明确。导出、实际独立符号、短函数、明确参数对象和入口用途分别核对，不能只满足“导出”就替换锚点。

## 已确认的连续布局

共同头部：`int id; unsigned int hdrsize; char name[16]; unsigned int version; unsigned int maxattr;`。模块配置段从 hdrsize 开始，name/version/maxattr 分别相对 +4/+20/+24。取得 id/hdrsize 后，使用生产 `genl_family_config` 的成员布局，不再跨调用独立读取 version。直接读取困难时，也可从已确认的 name 或 maxattr 相对位置反推配置段。

旧 u32 计数片段：`mcgrps 指针 → unsigned int n_ops → unsigned int n_mcgrps → unsigned int mcgrp_offset`。ARM64 中 mcgrps 位于计数偏移减去指针与一个 unsigned int 大小的位置，即减 12；组号偏移是计数 +4。当前实现同时匹配 u32 计数和这个组号关系，再用已确认片段推导指针。字节计数或组号不相邻时，改走已有局部读取模式，不按内核大版本分支。

片段依据来自三个保存源码的实际声明：deprecated-android-4.19/common、android_kernel_sony_sm8250、kernel_xiaomi_odin；NDK ARM64 编译期断言核对了指针/整数宽度与相对布局。保存的 common-android13-5.15/common 在 mcgrps 前后重新排列计数，已明确不能应用这一片段；其头部配置段仍相同。局部片段证明不能外推为整个结构体固定，更不能用计数字段位宽代替目标声明和机器码核对。

## 固定窗口与局部用途

当前上限：genlmsg_put 20 条、genlmsg_multicast_allns 32 条、genl_pernet_exit 8 条。两个头部或组播入口字段齐备即停止。没有匹配就报错或降级，不扩大到整个函数，也不查询符号长度强求成功。

需要直接查 mcgrps 时，在注销函数指令索引 `[0x30,0x55)` 内接受任意 X 基址；LDR 后 1～4 条的 `add x2,xR,wM,sxtw #4` 必须使用该加载结果，附近 w0=8 对应删除组播组事件。局部匹配受同一窗口限制，调用/返回切断标记，后续 LDR/MOV 覆盖结果时放弃旧候选。这是受限模式识别，不是完整控制流与数据流证明。

不统一跳过函数头：4.19 的组数读取位于第 0 条。也不把首个相同类型 LDR 当作字段语义；窗口只能限制范围，用途和连续布局才能限定所取偏移。

## 验证范围

五份原授权镜像为 kernel_4.4、kernel_4.9、kernel_4.9_miui、kernel_4.14、kernel_4.19。当前真实 u32 路径全部从短锚点推导 35 个字段，缺少注销符号也不影响这一偏移计算。保留的局部指针扫描用合成 u8 计数和非相邻 u32 形态验证，不能称为新版本真实镜像覆盖。

更换锚点或改为相邻推导时，同步调整字段缺失、范围边界、用途不符及跨锚点断言；说明撤销了哪些独立字段读取的验证。失败保持已有 Genl/Binder 缓存，全部成功后更新 `struct_offset`。探索身份及具体判据见 [开发自检汇总](../../../../Developer/reports/2026-10-07-development-selfchecks.md)。这些是实现方主机/离线自检，不能外推为独立审计或 Android 运行结论。
