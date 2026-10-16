# NoMount 0.4.1：更新上游2.1.1

Developer更新与自检记录，不替代独立审计、真机验证或维护者验收。

## 更新范围

按用户要求将NoMount子模块由1ded61dc908c511072162fa0bee44e6ccdb7b4c7更新到[7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3](https://github.com/maxsteeel/nomount/commit/7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3)。2026-10-14查询时，该提交仍为master最新，元模块v2.1.1；[差异](https://github.com/maxsteeel/nomount/compare/1ded61dc908c511072162fa0bee44e6ccdb7b4c7...7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3)为25提交、23文件。

用户态CLI完整同步上游：列表查询和分页失败返回非零，JSON路径正确转义引号、反斜线及控制字符。WebUI增加模块skip_mount切换和德语翻译，沿用本项目接口连接标签。配套安装／启动／卸载和上游metainstall、rule-paths保持原字节。GPL-2内核／GPL-3用户态许可证不变，协议magic、命令编号及载荷布局不变。

KPM是单独的移植实现。本轮业务和偏移代码与0.4.0逐字节相同，只有协议来源注释和版本字符串更新。现有KPM已具备发布前分配／安装、缓存枚举UID及借用／持有引用分流。上游LKM的规则内联存储、inode与rule解耦、RCU规则退役及整批ADD锁重构涉及原生path寿命和调用上下文，留作另轮移植。UID Bloom、少量子项跳过Bloom与名称查找热路径优化也未改写本轮KPM。这里更新冻结源基线及用户侧，不宣称全部LKM内部重构已移植。

版本登记为0.4.1（ZIP versionCode=401）。原6.1适配保留，用户已明确6.1无实机，只有离线自检；5.15设备暂不可用。4.4／4.19既有真机证据继续绑定旧实例，不外推到本轮字节。

## 自检

新增test_upstream_cli.py保留原版CLI解析和序列化代码，仅将架构入口／syscall换成宿主接口。15项覆盖首个／后续页查询错误、规则及UID空列表、有效列表、JSON特殊路径、跨4096字节输出缓冲区，以及版本和隔离状态探测。宿主ASan／UBSan通过，原版CLI另由NDK生成ARM64静态程序。

旧test_zip_module.py原样运行，15项安装／启动／失败／卸载控制流通过。原生keyring、Android界面交互、CFI和目标VFS行为仍待独立验证。

## 复核决定（Decision）

**保留（Retain）**

### 有效性

更新到指定上游master冻结点，并同步直接消费的用户态及WebUI输入；对协议不变及新增错误／转义行为作有界自检。

### 简洁性

复用现有子模块和打包流程，KPM保留已适配结构及规则生命周期。上游内部对象重构不属于更新依赖必需步骤。

### 后果

新CLI和WebUI为新字节，需独立审计及可用设备验证；缺6.1实机按未执行记录。原已测试实例保留。

### 建议

冻结并交接0.4.1候选及配套ZIP，审计者按完整身份核对；测试者可先使用4.4／4.19设备，5.15待设备恢复，6.1注明未覆盖。

## 冻结候选

源码冻结提交：`17b4c622988eee61af2d029bf95ea594fb8da790`；KernelPatch SDK：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。126项构建输入，指纹`64136fb9c3cde66d17d581545c0cf294b4a317d910cc521ffa6b9ee6b141f493`。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| base | `nomount-0.4.1+g64136fb9c3cd.rc3af2e56.kpb51197a.ndk26.3.11579264#1` | `07af779bb0de25ef0d3cec224a114c339938f9d2f3ac08860ee8fd9689d66c27` |
| baselines | `nomount-0.4.1_baselines+g64136fb9c3cd.r794de74f.kpb51197a.ndk26.3.11579264#1` | `d97a662d0dca8696018ec21c23335a41c00ab17b5f9ac80d3fd4e619b95cb9ec` |
| baselines_debug | `nomount-0.4.1_baselines_debug+g64136fb9c3cd.r99540400.kpb51197a.ndk26.3.11579264#1` | `625204db4a8b63c1463c89e943015f4a2402fecac1ca9ac7ad3174670c2cbf19` |
| debug | `nomount-0.4.1_debug+g64136fb9c3cd.rde995ba2.kpb51197a.ndk26.3.11579264#1` | `8f89950bb2541293ef3b5851efc13b7a415971b0fc2d67796b28b8accc16f51f` |

目标派生16条记录、12份不同KPM字节，覆盖原7份目标配置的普通／debug版及B2N可选旧KP导入转换。源码和Makefile仍面向最新KP；兼容变换仅处理已构建二进制，配置表仍为46项、92字节。每件绑定base实例、base SHA、目标配置、工具SHA、真实命令和派生SHA。

| 6.1派生件 | base instance_id | 派生SHA-256 |
| --- | --- | --- |
| nomount_0.4.1_baselines.kpm | `nomount-0.4.1_baselines+g64136fb9c3cd.r794de74f.kpb51197a.ndk26.3.11579264#1` | `0251da0f85d480f9874e38cb57665fa2addaa898514d7e68258cae09aaf4beca` |
| nomount_0.4.1_baselines_debug.kpm | `nomount-0.4.1_baselines_debug+g64136fb9c3cd.r99540400.kpb51197a.ndk26.3.11579264#1` | `7614f5d5a2a97392f1591f9a95b3229cb10d06ed975119e21b42f3d9b5fe1e20` |

ZIP实例：`nomount-zip-0.4.1+gc60d05a4813e.ndk26.3.11579264#1`，SHA-256：`9ffd3a0df9e0736a8293327b25333c843a26fb29095b9de4c4a4dbc0d9267588`，79468字节、32项。源码同为上述冻结提交；用户态来源为上游7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3。新增德语文件；真实ZIP源码对应当前冻结CLI，WebUI保留skip_mount按钮及API连接标签，语言文件可解析，JS语法检查通过。界面实际点击与Android端安装待独立测试。

候选档核验4/4通过；实际基础／派生ELF导入、寄存器及布局检查通过，无未解析SDK导入和FP/SIMD/SVE/x18操作数。JSON／blob替换一致并可逐字节还原base，配置修改限92字节；旧KP派生另核对收据范围。KPM业务和偏移代码相对0.4.0逐字节不变，因此沿用[0.4.0离线回执](data/2026-10-14-nomount-6.1-selfcheck.json)说明其查询覆盖，未重复不受影响的BTF和目录Oracle。所有此前test_*.py脚本保持原字节，本轮仅新增CLI自检工具。

常规门禁0FAIL、1项既有zram_zstd字段WARN；本轮版本登记为在途。维护者需采纳[版本提案](../proposals/2026-10-14-nomount-0.4.1/README.md)，导入本轮候选并按新身份登记审计／测试。

- [基础候选](handoffs/2026-10-14-nomount-0.4.1.json)
- [目标派生](handoffs/2026-10-14-nomount-0.4.1-target.json)
- [配套ZIP清单](data/2026-10-14-nomount-0.4.1-zip.json)
- [自检回执](data/2026-10-14-nomount-0.4.1-selfcheck.json)

are-you-sure复核决定为Retain；no-negative-echo已核对最终版本、来源说明、README和交接命名；respect-the-oracle已确认现有测试脚本不变，原生接口夹具的结果保持Developer自检层级。
