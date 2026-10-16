# NoMount ZIP：模块计数与路径格式

修正配套ZIP的来源路径格式，使WebUI首页、模块列表和卡片刷新能识别已加载的模块。ZIP仍为0.5.1，使用新的源码指纹和独立构建身份；正在测试的KPM字节继续沿用原冻结候选。

## 身份

本轮源码：`349b684b6eb6bd550992f381102e28dc1a16bc2b`。ZIP实例：`nomount-zip-0.5.1+g98115e4047c4.ndk26.3.11579264#1`；SHA-256：`39b6af17471629345c0291e821a81de216154599649be3bdba6740c8cdd1fec1`。产物路径：`artifacts/companion/nomount/nomount-zip-0.5.1+g98115e4047c4.ndk26.3.11579264#1/nomount-kpm.zip`。完整输入与归档信息见 [ZIP清单](data/2026-10-14-nomount-0.5.1-counts-zip.json)。

KPM继续绑定源码`cfb971d195d997808b68567b8ffc61a4dcd32b90`、[原四基础件](handoffs/2026-10-14-nomount-0.5.1.json) 及 [目标派生](handoffs/2026-10-14-nomount-0.5.1-target.json)。普通静态base实例`nomount-0.5.1_baselines+g17d96f6cff64.rf55be15b.kpb51197a.ndk26.3.11579264#1`，SHA-256`1062ee65515eeed841a423cdab68f7c20de233861266a7f88eb59ccfa628fea8`；Sony5.15普通目标SHA-256`abe50c726bb7c42a4b21edf8485aef89cf98208c3324a49be5d2877166d9d134`。本轮未重建或安装KPM。

## 问题来源

WebUI取自上游冻结提交`7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3`。此前生成副本只适配连接标签与空列表彩蛋，模块计数算法保留原版。原版启动根目录固定为`/data/adb/modules`；KPM配套脚本改为读取APatch的MODULE_DIR，却遗漏末尾斜杠处理。

末尾斜杠与拼接斜杠形成`/data/adb/modules//Example/...`。这是可访问的内核路径，但原版WebUI固定按`split('/')[4]`取模块名，取得空字符串；卡片刷新用单斜杠前缀匹配，也不命中。代码及末尾斜杠夹具能复现这一输入链，属于Developer配套改造的路径约定遗漏。

此前已授权采集的Sony5.15规则列表含42条来源、4个模块，来源根目录具有双斜杠。用这些来源重放实际WebUI：首页、模块列表、卡片刷新原版均为0，修正后均识别4个模块。本轮已授权Sony设备未出现在连接列表，未选择其他设备或重复访问；回放依据既有采集，未宣称取得本次正在测试的实时规则。

关联旧ZIP：源码`cfb971d195d997808b68567b8ffc61a4dcd32b90`，实例`nomount-zip-0.5.1+gd59432122045.ndk26.3.11579264#2`，SHA-256`3c101a96ddb42b6ca1ce33d9d2f17270f918704bcfdf19ee4da64b066c0490e8`。此前采集来源对应0.5.0现场，旧加载脚本在0.5.1仍保持相同字节；当前用户反馈作为0.5.1计数缺陷的复核入口。

## 修改与自检

- metamount.sh去掉MODULE_DIR末尾斜杠，再按原版方式拼接模块目录。规则下发顺序、UID恢复、失败撤销及开机回执保持既有流程。
- 生成WebUI副本新增parseRuleList，仅归一化JSON来源路径中的重复斜杠。首页、模块列表及卡片刷新共用入口，原版计数和状态选择算法继续执行。已有双斜杠规则可以直接统计，错误JSON仍按原版报错。
- 上游gitlink不变。ZIP与旧实例相比只有NOTICE.md、metamount.sh和webroot/index.js三个条目变化；nm二进制、许可证、语言文件及其余资产逐字节一致。四处`_(._.)_`保持完整。

[自检回执](data/2026-10-14-nomount-webui-counts.json) 绑定源码、ZIP及原KPM身份。新增 [test_webui_counts.py](../../nomount/tools/test_webui_counts.py) 在Node VM中执行真实WebUI的首页、模块列表和卡片刷新入口，DOM和exec由宿主夹具提供。覆盖四模块／多规则、原版正常路径、重复斜杠、空列表、单模块、非模块来源、自身来源、缺失字段和错误JSON；既有采集重放包含42条来源，9组检查通过。

原15项ZIP流程Oracle保持原文并运行通过。其宿主夹具上追加MODULE_DIR末尾斜杠回归，来源参数恢复单斜杠。36份已冻结测试脚本、34个C/H/Makefile输入保持原字节，四基础KPM归档哈希4/4一致。归档中的JS与生产adapt_webui输出一致，并通过Node语法检查。

## 方案复核决策（Decision）

**保留（Retain）**。

### 有效性

原版在干净路径上能统计，双斜杠来源使三处统计均失效。修复启动输入与视图解析后，原算法在合成规则及既有42条来源重放中恢复四模块计数。

### 简洁性

一处启动根目录修正，加一个共用解析入口即可覆盖三处展示；无需改动内核协议或重新实现计数。

### 后果

归一化只影响界面自己的JSON对象，规则下发仍执行原有路径脚本。用户侧WebView桥接、实际刷新和新ZIP安装属于实机范围，宿主自检不产生这些结论。

### 修订建议

以本ZIP独立身份审计和复测：四个已加载模块的首页计数、列表文件计数及卡片刷新一致；既有KPM测试继续绑定原产物。关闭条件见 [DEV-037提案](../proposals/2026-10-14-nomount-webui-counts/issues.json)。
