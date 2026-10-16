# NoMount 0.3.0：默认嵌入时机候选

角色：Developer。根据用户要求，嵌入时可保留 APatch 默认加载时机。入口统一执行完整初始化，真实依赖或布局错误仍返回失败。以下为实现方自检，不是独立审计或实机结论。默认 pre 开机加载等待 Tester 验证。

## 变更与范围

生产变更仅删除 `nomount.c` 中对 `pre-kernel-init` 返回 `-EAGAIN` 的两行。非空参数拒绝、依赖与布局核对、原生锁、key type 最后发布和驻留到重启均保留。没有新增延迟注册、重试或自动切换时机。模块版本保持本轮候选 0.3.0。README 与模块 AGENTS 同步当前加载契约。

前一轮源码 `f70894744b10d7aab212d18a9262e905eacef7d9` 的候选、派生件及审计现场保持原字节，本轮使用新实例和新派生路径。历史 post 实机结果不自动适用于本轮 pre 字节。

## 冻结身份

源码完整提交：`89ea33c3c0e7bcdd15c6d464f888807eb2908b0b`。输入指纹：`9fcbefaca5603d0be4d36c6a9fcbf683156ad8d20f3ebb8c8e9c3775c7d0b86b`。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。上游 NoMount gitlink保持 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。

构建命令：`python3 tools/build_candidate.py nomount --toolchain ndk26.3.11579264 --target "all debug" --extra-input patch_offsets.py --handoff Developer/reports/handoffs/2026-10-14-nomount-load-events.json`。实际 NDK、独立布局输出、编译参数及哈希记录在 [候选清单](handoffs/2026-10-14-nomount-load-events.json)；事务 input_unchanged=true、returncode=0。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| base | `nomount-0.3.0+g9fcbefaca560.rd39b79f0.kpb51197a.ndk26.3.11579264#1` | `3ac27117adc63539cf553292544fe71d842c39b9a24f76a5b13deae21930adc5` |
| baselines | `nomount-0.3.0_baselines+g9fcbefaca560.rceec7446.kpb51197a.ndk26.3.11579264#1` | `417c34766283fa17ab94d77960d3c25304073bcab11ebd9d3ea060bbecd2898d` |
| baselines_debug | `nomount-0.3.0_baselines_debug+g9fcbefaca560.rdd52f43a.kpb51197a.ndk26.3.11579264#1` | `1f6a2756ed70b316c513ff5f48994e10a67a6b90db822eef7a9c8122ddf7ebf0` |
| debug | `nomount-0.3.0_debug+g9fcbefaca560.r73bd9792.kpb51197a.ndk26.3.11579264#1` | `d605aba422c9d7817a5a7de74bfc46c31ff3db852b86182aee58d473987f641a` |

## 目标件

[目标派生清单](handoffs/2026-10-14-nomount-load-events-target.json)记录全部 base 实例、源码提交、base／工具／配置／派生哈希、实际命令和回执。共14条目标记录、10份唯一派生字节；相同5.15布局共用字节。派生路径为 `artifacts/binary-port/nomount/<sha>/<文件名>`。B2N另附旧KP二进制转接件，源码与Makefile保持最新KP构建。

| 目标 | 变体 | 变换 | 派生SHA-256 |
| --- | --- | --- | --- |
| `boot_67.2.A.3.178.img` | 普通 | target-layout | `8c0def021038c45818f114b6c2f7a50a49a61c1306f5399ff89934d673051e15` |
| `kernel_android13-5.10` | 普通 | target-layout | `b8efdc4219787a816d3f8e03ff57b676b175c6d5299020bc9776cbb6c1fb6bca` |
| `kernel_android13-5.15` | 普通 | target-layout | `8c0def021038c45818f114b6c2f7a50a49a61c1306f5399ff89934d673051e15` |
| `kernel_android14-5.15` | 普通 | target-layout | `8c0def021038c45818f114b6c2f7a50a49a61c1306f5399ff89934d673051e15` |
| `B2N-416G_boot.img` | 普通 | target-layout | `0de18262d7684ae2cdd17c33c867e0a0120cf534f7991ee666b9f53c9ed74b67` |
| `B2N-416G_boot.img` | 普通 | target-layout-then-legacy-kp | `a76af0f8c7d8dff3b4c8a9d541c332edb19fa6d7538e5030df939534b64f4ecb` |
| `boot_los23.2.img` | 普通 | target-layout | `fe038afbb69a0aabc562e38f52952a1e872afdb203f32df12c66b054b8454b76` |
| `boot_67.2.A.3.178.img` | debug | target-layout | `5ba03fe91c720c3857cf1592b5f2f5f8f796aef6fdf4fb95ab8475400723e829` |
| `kernel_android13-5.10` | debug | target-layout | `688a8a16ac3d1b6e4d3ec222559680109fa08a6094a3d235531800a625d82f98` |
| `kernel_android13-5.15` | debug | target-layout | `5ba03fe91c720c3857cf1592b5f2f5f8f796aef6fdf4fb95ab8475400723e829` |
| `kernel_android14-5.15` | debug | target-layout | `5ba03fe91c720c3857cf1592b5f2f5f8f796aef6fdf4fb95ab8475400723e829` |
| `B2N-416G_boot.img` | debug | target-layout | `3f14865d4a7d29aa8a14b5492a2b266105cafd79ee6d36fa469c816eb6b2a98f` |
| `B2N-416G_boot.img` | debug | target-layout-then-legacy-kp | `ec777eca86b5e802e1c38943111b309bfe944b46e744492d18b6e600f36c8759` |
| `boot_los23.2.img` | debug | target-layout | `a8ad6ef9cb5a3a1ced3b19007fa519aa7337d32d4f9c22a9fbd47a89edfc1828` |

## 自检与断言契约

新增 [test_load_events.py](../../nomount/tools/test_load_events.py)，输入冻结0.3.0的挂载上下文Oracle。原生成源码哈希及源文件逐项绑定冻结提交，当前业务源码亦核对一致；621条assert表达式与顺序保持并完整执行。原24份Oracle脚本逐字节未变。

自检命令：`python3 nomount/tools/test_load_events.py --oracle-output local/nomount-lkm-port-20261014-01/contracts-04 --output local/nomount-load-events-20261014-01/selfcheck-02`。ASan／UBSan通过：三个事件（pre、post、NULL手动加载）下，静态和动态入口均执行准备；非空参数拒绝、依赖ENOENT、动态BTF ENODATA、注册EEXIST、七个分配失败点、短拷贝、状态输出和驻留exit均核对。原生准备与BTF由宿主调用契约夹具代替。

自检回执SHA-256：`69737835be677c2dd5fa5e341663a943701eff59396899ebf09410061f5317ea`。宿主首次执行因新夹具释放模拟注册后未清除fixture的topology状态失败；仅修正新夹具末尾状态清理，生产代码未作适配。

**断言调整范围与技术依据**：历史 `test_kpm.py` 的“pre必须拒绝”断言描述旧加载策略，原文件和归档证据保留；本轮用户明确要求默认嵌入进入初始化，因此新工具独立验证新事件契约，不把该旧断言应用到新候选。新工具先独立提交，再提交入口变更。请 Auditor 复核此契约变化；Developer 不宣称已获独立审计。

四基础实例通过candidate档指纹与产物复算；基础和14条派生记录的ELF、静态布局、SDK导入及完整可执行段反汇编检查通过，未发现FP／SIMD／SVE或x18操作数。全部配置JSON／blob一致且可还原base，修改范围限90字节配置表；旧KP转接另核对其回执范围。常规仓库门禁13项、0FAIL、1条历史zram交接登记警告。

## 复核决定（Decision）

**保留（Retain）**

### 有效性

新入口满足默认嵌入进入准备流程的要求；成功与实际错误由原初始化决定。宿主用例不能证明pre阶段原生依赖与CFI已就绪，须以目标实机检验。

### 简洁性

删除事件名称限制是本轮最小实现，不增加等待任务、分阶段注册或启动重试。

### 后果

pre比既有测试路径更早，宿主检查无法排除启动阶段异常。不能以本轮编译、自检或历史post结果宣称pre兼容；保留新旧候选独立身份。

### 建议

以新候选测试APatch默认嵌入，参数留空。按真实设备／KP／boot绑定字节，确认开机控制接口及实际规则访问；保留post对照，测试结论分别记录。

## 交给审计与测试

维护者可导入本轮两个新交接清单；Auditor复核两行入口变化、新加载契约和对应字节。Tester在准备好的4.4、4.19、5.15实机上验证默认pre嵌入开机，分别记录实际事件、CFI事实、模块状态、`nm version`通信、规则建立／读取／撤销、UID与APK读取。PackageManager开机扫描和应用启动仍按真实覆盖记录。

参数留空，每次选择一种产物，驻留到重启。遇到无响应按仓库设备升级规则停止重试并保留现场；本轮Developer未操作实机。
