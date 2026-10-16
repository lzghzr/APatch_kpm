# NoMount 许可证与署名复核

角色：Developer。复核当前冻结上游与构建输入，未发现GPL-3实现进入GPL-2 KPM的直接冲突；KPM和用户态ZIP分别沿用各自许可证。以下是开发者的来源及发布配套检查，不是独立审计或法律意见。

## 依据与处理

上游固定提交 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7` 的 [README](https://github.com/maxsteeel/nomount/blob/1ded61dc908c511072162fa0bee44e6ccdb7b4c7/README.md#license) 明确kernel为GPL-2、其余部分为GPL-3；仓库实际正文分别在kernel/LICENSE与LICENSE。

KPM来源为kernel/src的内核实现，许可证保持GPL-2.0-only。线协议枚举／载荷／规则头同样定义在kernel/src/nomount.h，已把nm_protocol.h的来源路径写明，并将其SPDX收紧为GPL-2.0-only，避免对上游协议声明额外的升级授权。公共辅助代码的GPL-2.0-or-later部分在整体KPM中按GPL-2使用。

用户态nm、脚本与WebUI作为独立ZIP保持GPL-3.0-only，不与KPM链接；双方通过keyring系统调用交换命令。根据 [GNU GPL FAQ](https://www.gnu.org/licenses/gpl-faq.en.html#MereAggregation)，独立程序的分发与合并代码属于不同问题，通信方式与语义仍须结合实际判断。此结论限于本轮已检查的来源边界，不把GPL-2-only与GPL-3称作可以直接混合链接。

按 [GPL-3正文](https://www.gnu.org/licenses/gpl.en.html) 第1、5、6节核对源码、构建方法、修改通知与许可证。补充随包build-nm.sh、NOTICE.md及WebUI修改日期；ZIP内保留原版nm.c/nm.h、GPL-3全文和源码形式的脚本／WebUI。原版CLI不改，编译器与链接器属于通用构建工具，不随包捆绑。

KPM_AUTHOR及ZIP作者字段均为 `maxsteeel, Codex`，说明原作者与AI开发贡献。署名不作为新增版权归属声明。上游WebUI设计、代码优化、灵感来源和其他贡献者致谢在NOTICE中保留。用户说明见 [NOTICE](../../nomount/module/NOTICE.md) 与 [来源说明](../../nomount/UPSTREAM.md)。

## 新冻结身份

完整源码提交：`bdb9748b164e8157b80d977e26d2fa9172bf87dc`。旧候选及审计报告保留原字节。模块版本仍为0.3.0；本轮内核功能不变。

| 件 | instance_id | SHA-256 |
| --- | --- | --- |
| ZIP | `nomount-zip-0.3.0+g647d561e3cad.ndk26.3.11579264#1` | `31d2300b0af481f6c3bed1df5976bdb06d90451b3c33ee9d6e5f8bef1c1d5764` |
| base | `nomount-0.3.0+g96ece746aa9f.rd0a227b7.kpb51197a.ndk26.3.11579264#1` | `aac6d4e47f788c8b78a1cb93861f091528fdd4585baf692245e41a8b0a49b964` |
| baselines | `nomount-0.3.0_baselines+g96ece746aa9f.r62f2beb9.kpb51197a.ndk26.3.11579264#1` | `e894e19378aa371e9baa02571f155e1281426d4faa9ef003ba1f44a373d0a6ac` |
| baselines_debug | `nomount-0.3.0_baselines_debug+g96ece746aa9f.r8e9f08d8.kpb51197a.ndk26.3.11579264#1` | `9d64260cf29abbc58f80794737241f09445cccc8deae649d9d1e70680e7bd664` |
| debug | `nomount-0.3.0_debug+g96ece746aa9f.r2a0d9e5d.kpb51197a.ndk26.3.11579264#1` | `8922c734803ad58c8cf3eb28e4e5ffa5a9914cfef054f434c2c7869bda04bf8d` |

ZIP路径：`artifacts/companion/nomount/nomount-zip-0.3.0+g647d561e3cad.ndk26.3.11579264#1/nomount-kpm.zip`，大小76983字节。同目录MANIFEST保存冻结输入、工具哈希和配方。KPM交接见 [基础清单](handoffs/2026-10-13-nomount-credits.json)／[目标派生清单](handoffs/2026-10-13-nomount-credits-target.json)，14条记录、10份唯一目标字节均重新生成；旧件不可覆盖。

完整自检数据见 [回执](receipts/2026-10-13-nomount-licenses.json)。四KPM实例candidate档通过。对照前一轮89ea33c源码的四产物，各执行段、数据段、偏移表和重定位逐字节相同；只有.kpm.info作者及.symtab中该信息段符号的大小／位置变化，其余字段不变。首次比较只预期.info变化，随后按真实ELF布局核对信息段符号变化；未修改生产代码或测试断言迎合比较。

ZIP两个独立实例重建字节相同；从最终ZIP提取nm.c/nm.h与build-nm.sh在另一个新目录编译，nm逐字节等于包内6080字节CLI，也等于前版CLI。GPL-3正文等于冻结上游原文；署名、日期和NOTICE、shell／JS语法回读通过。原有15项ZIP宿主控制流用例再次通过，Oracle未改。

## DEV-035（中低，归属Developer）配套ZIP缺少随包编译脚本与改动通知

类别product；发现对象为前轮ZIP实例 `nomount-zip-0.3.0+g1f9ef71469bb.ndk26.3.11579264#1`。文件缺失已确认，频率高频。此前公开发布时需要另提供编译方法和改动通知，不能仅凭现有候选包宣称对应源码配套完整；此处不认定已发生违规传播。

修复提交及新ZIP身份见上表，状态 **fixed(待复核)**。由Auditor独立核对来源、GPL正文、通知和署名，并用随包源码重编译确认；维护者采纳 [问题登记提案](../proposals/2026-10-13-nomount-licenses/issues.json) 后同步关闭。Developer不自行关闭。

## 复核决定（Decision）

**修改（Modify）**

### 有效性

按上游划分GPL-2 KPM和GPL-3 ZIP，协议来源在GPL-2内核头中可见。新包提供完整CLI源码及实际构建脚本，改动通知和作者可见。

### 简洁性

保留已有许可与分开构建方式；直接复用随包脚本进行正式CLI编译，不再另维护一份同样的参数列表。未引入额外许可、发布依赖或运行时机制。

### 后果

作者信息改变KPM产物哈希，因此另建实例和目标派生件；旧独立结论不自动改绑。来源复核与法律授权判断仍有边界，发布配套由Auditor继续独立核验。

## 建议与交接

维护者导入新KPM清单及DEV-035提案，Auditor复核署名和发布配套。Tester可继续核对新ZIP的设备安装与开机流程；本轮未操作设备，不增加实机兼容性结论。
