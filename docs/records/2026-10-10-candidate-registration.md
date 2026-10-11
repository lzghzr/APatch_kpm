# 2026-10-10 冻结候选身份登记（rek 11.7 / rekx 1.6-20261008 / run_cmd_demo / hosts_redirect / dont_kill_freeze / cgroupv2_freeze）

维护者；2026-10-10。本记录保存本轮 13 份冻结候选的登记结果、维护者复算命令、证据索引与未决项。
登记对象是 [Developer 冻结候选构建报告](../../Developer/reports/2026-10-10-frozen-candidate-build.md)（报告哈希
`27d75761a81ff38c6d35cae0bacf7d27c696c92fad3273aec2bd85fe8e7a2b17`）产出的实例；实现方自检结论的来源是 Developer，
本记录只登记身份与复算事实，**不构成验收或交付**。

## 冻结输入

| 项 | 值 |
| --- | --- |
| source_commit | `2257f2291e2be77c8809c266393da9d9d093d7b4`（登记时的 HEAD） |
| KernelPatch commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9` |
| 工具链 | NDK 26.3.11579264 |
| 产物 | 13 份，全部落在 `artifacts/<instance_id>/` |

## 候选身份（13 份）

| 模块 / 变体 | instance_id | 产物 SHA-256 | 字节 | 归档路径 |
| --- | --- | --- | --- | --- |
| `re_kernel` / `base` | `re_kernel-11.7+g63a3af7d7034.r3efcc29a.kpb51197a.ndk26.3.11579264#1` | `3ddb8fc9a69010bd87092f0d6b3d0af4e313585b1630d9c64f8a4517f2f86482` | 80600 | `artifacts/re_kernel-11.7+g63a3af7d7034.r3efcc29a.kpb51197a.ndk26.3.11579264/re_kernel_11.7.kpm` |
| `re_kernel` / `baselines` | `re_kernel-11.7_baselines+g63a3af7d7034.ra3221655.kpb51197a.ndk26.3.11579264#1` | `eb5d252c45603a23305ea6526d58339549ae92b861fc4ce92477b020c270d60b` | 34760 | `artifacts/re_kernel-11.7_baselines+g63a3af7d7034.ra3221655.kpb51197a.ndk26.3.11579264/re_kernel_11.7_baselines.kpm` |
| `re_kernel` / `baselines_debug` | `re_kernel-11.7_baselines_debug+g63a3af7d7034.rdfb99af0.kpb51197a.ndk26.3.11579264#1` | `3f28328078a41807b1eb969d608b8c2621ef51e672a16355fc3bd85147c495c1` | 35552 | `artifacts/re_kernel-11.7_baselines_debug+g63a3af7d7034.rdfb99af0.kpb51197a.ndk26.3.11579264/re_kernel_11.7_baselines_debug.kpm` |
| `re_kernel` / `debug` | `re_kernel-11.7_debug+g63a3af7d7034.rfd66d6af.kpb51197a.ndk26.3.11579264#1` | `3dba88b800871dac66e8a78ae84775213b0d967aa444d652fa6846065f6895c9` | 85440 | `artifacts/re_kernel-11.7_debug+g63a3af7d7034.rfd66d6af.kpb51197a.ndk26.3.11579264/re_kernel_11.7_debug.kpm` |
| `re_kernel_x` / `base` | `re_kernel_x-1.6-20261008+gc98feee61782.r05be2926.kpb51197a.ndk26.3.11579264#1` | `151ef48c73afe7703c13778cbaffccf0c5b900bd1e6b98aea2d483933b33030f` | 93744 | `artifacts/re_kernel_x-1.6-20261008+gc98feee61782.r05be2926.kpb51197a.ndk26.3.11579264/re_kernel_x_1.6-20261008.kpm` |
| `re_kernel_x` / `baselines` | `re_kernel_x-1.6-20261008_baselines+gc98feee61782.rfed0f482.kpb51197a.ndk26.3.11579264#1` | `2933c90f15c4ec66872fce0e6f2222e10fd314dfe31a69d7ca998df60201144a` | 42360 | `artifacts/re_kernel_x-1.6-20261008_baselines+gc98feee61782.rfed0f482.kpb51197a.ndk26.3.11579264/re_kernel_x_1.6-20261008_baselines.kpm` |
| `re_kernel_x` / `baselines_debug` | `re_kernel_x-1.6-20261008_baselines_debug+gc98feee61782.r70edd8bb.kpb51197a.ndk26.3.11579264#1` | `ed6f97dcf8cdaf8498d22ecc5de410a4887e3492e38aa585f2ffded091ad8b0a` | 41728 | `artifacts/re_kernel_x-1.6-20261008_baselines_debug+gc98feee61782.r70edd8bb.kpb51197a.ndk26.3.11579264/re_kernel_x_1.6-20261008_baselines_debug.kpm` |
| `re_kernel_x` / `debug` | `re_kernel_x-1.6-20261008_debug+gc98feee61782.rafb02aeb.kpb51197a.ndk26.3.11579264#1` | `e6ce734b2ad7c60290b495c86244a988e8180462711a63fb57e88cbecdd73304` | 98968 | `artifacts/re_kernel_x-1.6-20261008_debug+gc98feee61782.rafb02aeb.kpb51197a.ndk26.3.11579264/re_kernel_x_1.6-20261008_debug.kpm` |
| `run_cmd_demo` / `base` | `run_cmd_demo-1.2.0+g9669c80f9942.r2e72bd0b.kpb51197a.ndk26.3.11579264#1` | `d1ebd33b0675d4a6c655348615ffdd209a2910fc12d76c57574e7658a44eb1b7` | 27016 | `artifacts/run_cmd_demo-1.2.0+g9669c80f9942.r2e72bd0b.kpb51197a.ndk26.3.11579264/run_cmd_demo_1.2.0.kpm` |
| `run_cmd_demo` / `debug` | `run_cmd_demo-1.2.0_debug+g9669c80f9942.r534a6113.kpb51197a.ndk26.3.11579264#1` | `a1a78b752d4638e3decce97088aa9df49f2384f7315127289258037c4a938cfc` | 27016 | `artifacts/run_cmd_demo-1.2.0_debug+g9669c80f9942.r534a6113.kpb51197a.ndk26.3.11579264/run_cmd_demo_1.2.0_debug.kpm` |
| `hosts_redirect` / `debug` | `hosts_redirect-2.0.0_debug+gc645a901ca7a.rb04db02f.kpb51197a.ndk26.3.11579264#1` | `b5c8cb51e95e92168c639fe353da49311f9e3684a5be9bbce54a2f6ed1a23767` | 12328 | `artifacts/hosts_redirect-2.0.0_debug+gc645a901ca7a.rb04db02f.kpb51197a.ndk26.3.11579264/hosts_redirect_2.0.0_debug.kpm` |
| `dont_kill_freeze` / `debug` | `dont_kill_freeze-1.0.2_debug+g66d4b596b2ea.r26ef28f9.kpb51197a.ndk26.3.11579264#1` | `396ddf38cd0c98587a8d2903cb2d4f1618f652a440960dbf3a74859837d3bb68` | 11808 | `artifacts/dont_kill_freeze-1.0.2_debug+g66d4b596b2ea.r26ef28f9.kpb51197a.ndk26.3.11579264/dont_kill_freeze_1.0.2_debug.kpm` |
| `cgroupv2_freeze` / `debug` | `cgroupv2_freeze-1.0.12_debug+gbb3cbdfdb1cd.rbfff8154.kpb51197a.ndk26.3.11579264#1` | `f570ae2d81ff2c2d7050e34098eaa2f9faae6de59fedf136d96627e33281f0c2` | 34336 | `artifacts/cgroupv2_freeze-1.0.12_debug+gbb3cbdfdb1cd.rbfff8154.kpb51197a.ndk26.3.11579264/cgroupv2_freeze_1.0.12_debug.kpm` |

完整构建条目（源码清单、配方指纹、编译器字节、构建事务）见 [re_kernel](../../metadata/modules/re_kernel.json)、
[re_kernel_x](../../metadata/modules/re_kernel_x.json)、[run_cmd_demo](../../metadata/modules/run_cmd_demo.json)、
[hosts_redirect](../../metadata/modules/hosts_redirect.json)、[dont_kill_freeze](../../metadata/modules/dont_kill_freeze.json)、
[cgroupv2_freeze](../../metadata/modules/cgroupv2_freeze.json)。

## 登记动作

- `re_kernel`、`re_kernel_x` 的 8 个实例由 Developer 经统一候选构建入口 `tools/build_candidate.py` 受控追加；维护者只复算，未改写。
- 其余 4 个模块本轮首次建档（此前不在 `metadata/modules/`），随后用 `tools/identity.py import-manifest` 导入交接清单，
  保留清单中的 `instance_id` 与归档路径，未重新编号：

  | 交接清单 | 清单 SHA-256 | 导入实例 |
  | --- | --- | --- |
  | `Developer/reports/handoffs/run_cmd_demo-20261010-frozen-candidate.json` | `d4e803d99202f07210e848fab737905b3e72b2876487f06542e70f6133eae03f` | `run_cmd_demo-1.2.0…`、`run_cmd_demo-1.2.0_debug…` |
  | `Developer/reports/handoffs/hosts_redirect-20261010-frozen-candidate.json` | `b4a50074b14b2bfb9ece1c2da0ff77c86c6ffad66ded385299ef5a808ca0b3fd` | `hosts_redirect-2.0.0_debug…` |
  | `Developer/reports/handoffs/dont_kill_freeze-20261010-frozen-candidate.json` | `c97a1fe25a83540d5f18f9bb44cbacceb818ef447b86eb3b29fc1384e264448e` | `dont_kill_freeze-1.0.2_debug…` |
  | `Developer/reports/handoffs/cgroupv2_freeze-20261010-frozen-candidate.json` | `c46ea1f8ff7fe10ea6c09cce3cc3e2d352e12792175830cc151873cb48a31f8e` | `cgroupv2_freeze-1.0.12_debug…` |

  版本声明取自各模块 `Makefile`：`run_cmd_demo` 1.2.0、`hosts_redirect` 2.0.0、`dont_kill_freeze` 1.0.2、`cgroupv2_freeze` 1.0.12。

## 维护者复算

```bash
for m in re_kernel re_kernel_x run_cmd_demo hosts_redirect dont_kill_freeze cgroupv2_freeze; do
  python3 tools/identity.py verify --module "$m" --instance-id '<上表 instance_id>' --profile candidate
done
```

13 份实例逐条 `verify[candidate]` 0 处问题：源码按绑定提交 blob 逐文件核验（rek 25 / rekx 15 / run_cmd_demo 11 /
cgroupv2_freeze 8 / hosts_redirect 7 / dont_kill_freeze 6 个文件）、配方指纹可重算、有效编译参数已捕获、
`source_dirty=false`、产物哈希与归档一致。`import-manifest` 在写入前另行核验归档产物的在场与哈希。
本轮未缩小任何断言、用例或检查范围。

## 未决项与范围

| 项 | 状态 |
| --- | --- |
| 独立审计（Auditor） | 未执行；本轮 13 份实例都没有独立重编译/字节解析结论 |
| 真机测试（Tester） | 未执行；未操作设备、未接触 superkey |
| `acceptances[]` / `deliveries[]` | 未追加；6 个模块状态保持 `candidate` |
| 静态基线布局 `*.kpm.json` | 4 份已归档进 `artifacts/<instance_id>/` 并登记 `maintainer_records[].baseline_layouts`；约定已写入流程文档 |
| 6.12 / 6.18 函数推导、kernel_4.14.186、boot-250514.img | 按 Developer 报告记为未执行/未覆盖 |

### 静态基线布局的归档

布局 JSON 在构建期输出到模块目录之外的 `LAYOUT_DIR`（`.json` 属于构建输入，写进模块目录会触发输入一致性拒绝），
本轮先落在 `local/post-freeze-candidate-20261010-09383f4c/`。维护者按上一轮约定把这 4 份随其 `.kpm` 归档进
`artifacts/<instance_id>/`（新增文件，未改动任何已封存字节与 `MANIFEST.json`），并登记进
`maintainer_records[].baseline_layouts`：

| 布局文件（归档后） | 对应实例 | 内嵌 kpm SHA-256 | 布局文件 SHA-256 | 字节 |
| --- | --- | --- | --- | --- |
| `re_kernel-11.7_baselines+g63a3af7d7034.ra3221655.kpb51197a.ndk26.3.11579264/re_kernel_11.7_baselines.kpm.json` | `re_kernel-11.7_baselines+g63a3af7d7034.ra3221655…` | `eb5d252c45603a23305ea6526d58339549ae92b861fc4ce92477b020c270d60b` | `030ffb67620534e48b3b93f93e39f647f3b0101afbe5a167e0cfaf46171dadeb` | 3076 |
| `re_kernel-11.7_baselines_debug+g63a3af7d7034.rdfb99af0.kpb51197a.ndk26.3.11579264/re_kernel_11.7_baselines_debug.kpm.json` | `re_kernel-11.7_baselines_debug+g63a3af7d7034.rdfb99af0…` | `3f28328078a41807b1eb969d608b8c2621ef51e672a16355fc3bd85147c495c1` | `174e5c2d5f0300ecf2f865c4d67267ebffb6ab0eef70b2cb5f5dfdd44ebd5853` | 3082 |
| `re_kernel_x-1.6-20261008_baselines+gc98feee61782.rfed0f482.kpb51197a.ndk26.3.11579264/re_kernel_x_1.6-20261008_baselines.kpm.json` | `re_kernel_x-1.6-20261008_baselines+gc98feee61782.rfed0f482…` | `2933c90f15c4ec66872fce0e6f2222e10fd314dfe31a69d7ca998df60201144a` | `241dc70d8c222c230962c2d6eb6efe3a17f9aa91315bec574f9a97b1e85d8496` | 3087 |
| `re_kernel_x-1.6-20261008_baselines_debug+gc98feee61782.r70edd8bb.kpb51197a.ndk26.3.11579264/re_kernel_x_1.6-20261008_baselines_debug.kpm.json` | `re_kernel_x-1.6-20261008_baselines_debug+gc98feee61782.r70edd8bb…` | `ed6f97dcf8cdaf8498d22ecc5de410a4887e3492e38aa585f2ffded091ad8b0a` | `a7a4884773a0e69b005d6248d15e6b00b74896ef8a35281c59749405b3a4b2a2` | 3093 |

每份布局 JSON 内嵌其目标 `.kpm` 的 SHA-256，与上表实例的产物哈希一致，可独立对应到实例；归档副本与 `local/` 原件
逐字节一致。该约定已写入 [身份与可追溯性](../process/01-identity.md) 的产物目录一节与 [一轮完整流程](../process/03-round-flow.md)
的交接步骤，供后续轮次遵循。

## 范围声明

> 本记录只登记身份、版本声明与维护者复算事实，不产生验收或交付结论。静态、权限与生命周期安全、真机可用性
> 分别由 Auditor 与 Tester 出具；在这些证据到位前，13 份实例保持 `candidate`，不得作为交付字节引用。
