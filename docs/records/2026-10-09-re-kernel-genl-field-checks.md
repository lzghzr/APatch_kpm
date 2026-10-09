# re_kernel Genl 字段检查工程记录

角色：维护者。保存本轮提交整理、源码字节核对和宿主复跑记录。开发说明见 [Genl 字段检查精简](../../Developer/reports/2026-10-09-re-kernel-genl-field-checks.md)。修改阶段基点为 `9852f7bf8d47305eef55880ace8211d89101b090`。

## 源码与测试范围

字段表统一保存偏移和宽度，按生产结构体的 sizeof 核对范围与重叠；组指针的查找与对齐在同一处检查。新增字段边界用例，偏移夹具使用生产头文件的 family 定义。锚点、扫描窗口与原有断言保留。

| 文件 | 本轮 SHA-256 |
| --- | --- |
| `re_kernel/re_offsets.c` | `8c298ffddd3108a94629f2a5824560f159a0ff3293c192fbef3150b1a05f53a7` |
| `re_kernel/tools/test_genl_anchors.c` | `8c9f931717114fc366928d3ce83b46df264640ea56c40f14562a9769cea583af` |
| `re_kernel/tools/test_genl_offsets.py` | `747852da95fbe8836682aba364b7151c0aa73274de84f73f6199dd449bceb35c` |

维护者执行 `python3 re_kernel/tools/test_genl.py --output <新的空目录>`，8 组 ASan/UBSan 宿主套件通过。新增 anchors 用例另外与基点提交的生产偏移代码组合编译运行，通过；原 anchors 断言和离线 main 判据逐字节保留。

复算 Developer 保存的 18 项源码输入、2 份探索产物及 171 份受保护文件，均与其记录一致。维护者执行 `python3 tools/check_repository.py --strict`，16 项检查通过，0 失败、0 警告。复跑回执、命令输出和原始文件副本保留在本地证据目录。

## 产物与结论绑定

本轮构建属于探索产物，尚无登记的 instance_id 和冻结构建事务。已有 builds、MANIFEST、审计、实机测试及问题状态保持原有提交和产物身份；本记录不追加候选、验收或交付绑定。

宿主复跑使用实现方夹具，属于工程自检复现。独立审计和实机结论按各自报告绑定的原始候选核对；本轮源码更新需从冻结提交构建新实例后再交接。本轮没有新增镜像语料覆盖或设备操作。

## 提交组织

工具与 re_kernel_x 的两个签名提交保留。re_kernel 源码更新合入模块源码提交，历史 DEV-011 Oracle 窗口调整继续单独保存；开发报告和本记录随工程记录提交归档。源码基点及原候选冻结提交通过保留引用存续，提交整理不改写其身份。
