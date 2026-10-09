# rek Genl 字段检查精简

角色：Developer。按使用者确认精简动态版检查。本轮基点为 `9852f7bf8d47305eef55880ace8211d89101b090`，修改尚未提交；产物为探索构建，未登记 instance_id，不作为冻结候选交接。

## 修改

- 三组并行数组合为一张字段表，保存偏移及宽度；使用 sizeof 表达 family 容量和配置段、整数、指针大小。
- 删除直接 LDR/LDRB 字段的重复对齐检查：无符号立即数 LDR 的偏移按访问宽度缩放，配置段普通路径为 id+4，特殊头部路径为 0，字节计数不需要额外对齐。
- mcgrps 可以由 n_mcgrps-12 推导，仍单独检查指针对齐，并与该字段的查找成功判断放在一起。
- 保留范围与成对重叠检查。字段顺序会随实际布局变化，不能用固定排序替代比较；沿用小循环，不新增排序、通用 helper 或内核依赖。没有改变锚点和扫描窗口。

## 自检

八组现有 ASan/UBSan 主机套件通过，包括 Sony/6.1/6.6 的生产 Genl 入口指令。追加组指针位于 family 尾部、越界、覆盖配置段，组数覆盖配置段/组号或越界，以及相邻推导产生四字节对齐指针的场景。新增用例也针对基点提交的原生产代码运行，全部通过。

既有断言未修改或削弱。偏移夹具增加从生产 re_kernel.h 提取 family 定义，以支持生产代码的 sizeof；没有为宿主测试改写生产架构或改变既有参考值。

NDK 26.3.11579264、KP SDK `b51197aaba8f2272dd8a3e30c85698a29aa928c9` 在新的隔离目录构建 all/debug，通过，每变体各 5 条已有 SDK 警告。两份 ELF 的 17 项导入存在于 SDK 导出源码；未发现裸 memset/memcpy 或 FP/SIMD/SVE/x18 操作数。

| 产物 | 字节数 | SHA-256 |
| --- | --- | --- |
| re_kernel_11.7.kpm | 48256 | 1f3c3476a1f61d1ade6e20e7c67a899c5dc315168aa0f61fde87d709e032854d |
| re_kernel_11.7_debug.kpm | 57456 | 3d47a010b278ac9b78c8cfb9233eb40adf7ae2969fc1816469c64dcb686baab8 |

本地证据在 `local/rek-genl-checks-20261009-yic5w4tj/`：host/receipt.json、anchors-original.log、build-check.json、sources.json、protected.json。构建输入副本与工作树源码一致，171 份既有模块产物及归档文件哈希不变。git diff --check 与 .clang-format 核对通过。

## 边界

本轮未重新提取或扫描 kernel_img，没有新的镜像选择或覆盖声明。未执行真机加载、Genl 收发或卸载。以上是实现方自检，不是独立审计或实机结论；现有冻结身份保持原样，本轮修改尚未提交冻结。
