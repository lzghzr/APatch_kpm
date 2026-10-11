# BTF 布局查询与函数推导衔接

在为 KPM 增加 BTF、核对失败回退、读取嵌套成员或确认函数 ABI 时使用。默认范围和锚点方法见 [偏移获取技能](../SKILL.md)，双版本组织见 [KPM 开发技能](../../kpm-development/SKILL.md)。

## 数据存在与接口可用分别确认

离线从目标 Image 的 BTF 读取字段，不需要运行内核提供查询入口；动态 KPM 则同时需要有效 vmlinux BTF 和可查找的原生接口。镜像有 BTF 不表示 KP 能解析所需符号，也不表示结构体、函数原型及参数名都完整。

rek、rekx 当前查询依赖 `bpf_get_btf_vmlinux`、`btf_find_by_name_kind`、`btf_type_by_id`、`btf_name_by_offset`、`btf_resolve_size`。模块自行解析函数地址并检查 BTF 返回值，不能把这些名字直接当成 KP ELF 导出。`bpf_get_btf_vmlinux` 的 NULL 与 ERR_PTR 分别按原生契约处理。

两模块的 `calculate_offsets()` 首先调用各自的 `calculate_btf_offsets()`：

| 结果 | 处理 |
| --- | --- |
| `0` | 使用已查询的目标字段，结束偏移计算 |
| `-ENODATA`，数据/查询依赖不可用 | 尝试已有固定窗口函数推导 |
| 其它错误 | 保留必要字段、布局或原生接口的具体错误，初始化失败 |

可选字段保持模块自身语义，例如旧 Binder 内核数据指针 `binder_buffer_data=-1` 表示未取得可用 data；不能据此把必需字段都当作可选。确需支持新布局时针对镜像补充实现和证据，不以版本号填模板值。

## 公共查询与模块职责

根目录 [kpm_utils.h](../../../../kpm_utils.h) 提供 `struct kpm_btf`、`kpm_btf_type/member/offset/enum`。模块初始化有效 BTF 与四个查询函数后使用它；字段清单、可选项、表范围、共同布局断言及函数 ABI 保留在本模块。

- `kpm_btf_member` 按名称遍历点分路径和匿名 struct/union，取得最终类型、bit 偏移、位域宽度和尺寸。嵌套偏移逐层累加；处理 BTF kind_flag 的位域编码。
- `kpm_btf_offset` 返回字节偏移，拒绝位域、非整字节位置与指定宽度不符；width=0 只取消尺寸相等检查，不代表接受任意类型错误。
- 位域、枚举值和直接复用的共同结构分别核对。例：`binder_buffer.free` 是位域；`BINDER_WORK_TRANSACTION` 需要实际枚举证据；Genl 配置段及缓冲区容量须与目标类型对应。
- 静态配置表核对完整字段。动态仅查询业务所需字段；共用结构多出的成员不自动成为动态必需依赖。

## 尺寸 API 的缓存契约

vmlinux BTF 的元数据有效不表示已建立所有类型解析缓存。不要直接套用依赖 `resolved_ids/resolved_sizes` 的 `btf_type_id_size`：typedef→pointer、u32→typedef→integer 等链可能访问未建立的缓存。

当前实现使用按类型链解析的 `btf_resolve_size`，核对返回类型、尺寸及 ERR_PTR；使用其它 API 前必须读目标实现的初始化和错误契约。`run_cmd_demo` 的 BTF 经验见 [开发记录](../../../../Developer/reports/2026-10-09-run-cmd-demo.md)中的 DEV-021。

## 函数 ABI 与结构体布局

BTF 类型偏移不代替函数签名。释放函数需查询 FUNC→FUNC_PROTO、参数数量、解析后的参数类型与必要参数名。Binder 五参数版本的 `off_end_offset` 与 `failed_at` 都是整数，单凭数量和宽度无法区分 ABI5/6；参数名缺失时该路径失败，再按明确的目标证据适配。

静态基线将实际调用选择写入 `binder_release_abi`；动态版加载时确认。编号 3/4/5/6 表示签名，不能按内核主版本号选。

## 复核边界

运行生产查询函数的宿主测试可验证真实 BTF 类型链、字段、布局和错误契约，但没有执行目标 ARM64 入口。离线存在查询符号也不证明运行端 KP 能查到它。真机加载、原生函数调用和生命周期仍需绑定产物验证。

本轮 13 份语料的具体范围与结果见 [窗口与新语料自检](../../../../Developer/reports/2026-10-10-rek-offset-windows.md)。6.18 的有效 BTF 缺少当前依赖的 `binder_alloc.buffer`，不能借旧字段推导宣称支持；该目标同时超出当前 KP 支持范围。回归语料范围、偏移可取得与运行端支持分别记录。
