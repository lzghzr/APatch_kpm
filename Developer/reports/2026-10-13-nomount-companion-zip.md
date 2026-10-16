# NoMount KPM 配套 ZIP

角色：Developer。已完成配套元模块脚本和可复现打包。使用流程是先嵌入目标 KPM 并重启，再安装 ZIP；安装通过包内 nm 检查运行中的控制接口。以下为开发者自检，安装、开机注入和应用扫描仍待独立审计及真机验证。

## 冻结身份

| 项目 | 身份 |
| --- | --- |
| 完整源码提交 | `e1062d9bd016afd961bc974655cb7305f39d27e9` |
| ZIP instance_id | `nomount-zip-0.3.0+g1f9ef71469bb.ndk26.3.11579264#1` |
| ZIP SHA-256 | `e432a00cd4c1793bf36d8d5e19d2d41e29d0a5ec3114e2a3520145a2a309f37d` |
| ZIP 大小 | 75070 字节 |
| 上游 NoMount | `1ded61dc908c511072162fa0bee44e6ccdb7b4c7` |

归档路径：`artifacts/companion/nomount/nomount-zip-0.3.0+g1f9ef71469bb.ndk26.3.11579264#1/nomount-kpm.zip`，同目录 MANIFEST.json 保存输入和编译配方。构建与宿主检查回执见 [结构化记录](receipts/2026-10-13-nomount-companion-zip.json)。ZIP 是独立配套件，未作为 KPM 实例导入登记，也没有重建内核候选。

构建命令：`python3 nomount/tools/build_zip.py --ndk <NDK根目录>`。工具链 ndk26.3.11579264，目标 aarch64-linux-android21。编译器与链接器实际文件哈希、完整参数和每个冻结输入均记入回执。第二次构建的 `#2` 实例与 `#1` 的 ZIP 完全相同，两个实例的编译日志均无警告。固定 ZIP 文件时间和权限，已有实例不会覆盖。

## 配套行为

- 自有脚本放 [nomount/module](../../nomount/module/README.md)。用户态 nm、WebUI、metainstall 和 rule-paths 来自冻结子模块；原版源码及 GPL-3 许可证随 ZIP 附带。WebUI 仅在输出副本中把驱动类型展示改为“已连接”。
- 安装使用包内 nm 的版本查询及隔离 UID 状态查询，要求通信成功、版本非空、状态为0或1。内核版本与驱动版本字符串不决定安装；未就绪时提示先嵌入 KPM、重启再安装。
- 元模块挂载入口自行检查接口和停用标记，清规则并恢复 UID／isolated 设置后再加载文件。按原版路径映射处理分区、.replace 和 opaque 标记；跳过 disable/remove/skip_mount 模块，路径以 NUL 分隔，find 与 xargs 各自核对错误。
- 注入失败清空当前规则；.booting 保存本次 boot_id，boot-completed 回执后删除。上一轮未收到回执时暂停注入，不能据此认定 NoMount 导致崩溃。post-fs-data 只检查接口，不再次清空已发布规则。
- 停用后重启停止自动注入；卸载 ZIP 清当前规则、配套数据和属于本模块的快捷入口。ZIP 不加载或卸载内核驱动，KPM 生命周期保持原约定。

启动顺序依据当前 [APatch event.rs](https://github.com/bmax121/APatch/blob/main/apd/src/event.rs)：metamodule::exec_mount_script 位于普通 post-fs-data 脚本之前（访问日期2026-10-13）。因此 UID 设置不能继续等到 service 阶段。用户的实际 APatch／KernelSU 版本及元模块支持仍需 Tester 绑定，当前源码顺序不代表设备侧事实。

## 自检

`python3 nomount/tools/test_zip_module.py --output <新临时目录>`：15项通过。宿主仅重定位固定 Android 路径，CLI 和安装器由夹具代替，覆盖接口缺失／查询错误／错误状态、旧驱动版本、root显式标志优先、架构拒绝、metamount先执行时的UID恢复、空格路径、白标记、跳过模块、规则失败清理、停用、旧开机标记与卸载快捷入口所有权。未改任何已有 Oracle。

最终 ZIP 回读29个文件，逐项核对内容哈希、可执行权限、固定时间、shell／JavaScript语法。nm为6080字节ARM64静态EXEC，入口在可执行段内，无动态加载器；用户态源码、许可证、metainstall和rule-paths逐字节等于冻结上游。ZIP不含KO、KPM或lkmloader。

对照 `89ea33c3c0e7bcdd15c6d464f888807eb2908b0b`，本轮全部 KPM C/H 与 Makefile 无变化，前轮审计和测试字节保持原样。常规仓库门禁13项、0失败、1条历史zram交接字段警告。本轮未操作设备。

## 复核决定（Decision）

**保留（Retain）**

### 有效性

安装及启动检查实际控制接口，UID先于规则发布。只读反例复核发现冻结CLI的列表命令会在通信错误时返回0，已采用返回值可靠的版本和隔离状态查询；列表输出不作为兼容证明。每个写入操作仍检查失败。反例复核属于同一Developer会话，不是独立审计。

### 简洁性

复用原版用户态和WebUI，单独维护必要脚本；KPM嵌入由APatch完成，配套ZIP只管理用户态规则。打包直接用现有NDK编译冻结源码，不增加运行时下载、驱动选择或后台加载机制。

### 后果

宿主自检不能证明元模块安装器、Android shell工具、SELinux、开机扫包和应用启动正常。开机标记只说明缺少完成回执，安全模式在下次开机生效。实际root与KP／boot身份、使用的KPM实例和ZIP实例需要分别记录。

## 建议与交接

先用已到位的4.4或4.19实机验证ZIP：嵌入对应候选并重启、安装ZIP、安装一个包含系统文件的普通模块、再开机检查规则、UID屏蔽、APK资源读取、卸载和安全模式。5.15设备就绪后另行验证，不继承旧内核结论。PackageManager扫描和新应用启动以测试者的实际覆盖为准。

Auditor复核冻结ZIP脚本、原版CLI返回语义、失败清理、配套件身份和重复构建；Tester只做设备验证。模块用户说明见 [配套README](../../nomount/module/README.md)。
