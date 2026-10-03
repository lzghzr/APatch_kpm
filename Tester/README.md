# Tester（真机测试）

真机是唯一能给出「功能可用」结论的环境，但它**不可靠**。本目录的规则与工具都服务于两件事：把观察变成可复核的证据；在环境失控时及时交回维护者。

- 手册：`docs/process/tester-handbook.md`
- **真机死机/卡死升级流程：`docs/process/07-escalation-device.md`（必读）**
- 授权与边界（A1–A6 开放 / C1–C7 约束）：`docs/process/02-roles.md`「Tester 授权与边界」
- 报告模板：`docs/templates/tester-report.md`、`docs/templates/escalation.md`

## 工具

```bash
export SUPERKEY=<本机 superkey>      # 只放环境变量，不写进任何提交的文件
bash Tester/tools/preflight.sh       # 预检 + 环境事实 + 加载前基线（所有 adb 调用带看门狗）
bash Tester/tools/run_test.sh --kpm artifacts/<instance_id>/re_kernel_8.0.0.kpm \
     --module re_kernel --timeout 120 --tool-freeze-commit '<完整冻结工具 SHA>' \
     --instance-id '<build_id>#<n>'   # instance_id 必填；冻结基线建议显式传入
bash Tester/tools/collect_evidence.sh --build-id <instance_id> --module re_kernel
bash Tester/tools/selftest_scripts.sh   # 离线自检：mock 设备驱动上面三个脚本的分支与退出码
```

`run_test.sh` 的退出码：

| 码 | 含义 | 下一步 |
| --- | --- | --- |
| 0 | 强证据判据通过 | 写实机报告（补功能判据与未覆盖），交维护者验收 |
| 1 | 判据失败（设备仍可用） | 记录现象与归属，交 Developer 或 Tester 修复 |
| 2 | 用法/环境错误（缺 SUPERKEY、产物不存在、**身份不符**：`--instance-id` 未在册或产物哈希与登记不一致） | 修环境/换正确实例，不算产品缺陷 |
| 3 | **前置条件未满足**（pstore 残留 / 基线采不到） | 停下问维护者（C4），不得"先加载再说" |
| **90** | **设备无响应/崩溃/重启** | **停止重试，走升级流程并通知维护者** |

## 硬约束（摘要，全文在 `02-roles.md`）

1. **主判据是"设备存活"**（`boot_id` 不变 + `uptime` 单调 + adb 持续响应，强证据）；
   `dmesg` 无崩溃特征只是**弱证据**，只能写"未观察到"，不能写"没有发生"（C1）。
2. **加载前必须记录基线四项**：`boot_id`、`uptime`、pstore 是否残留旧崩溃、已加载模块；
   pstore 非空就停下问维护者（C4）。
3. **判据脚本要绑定**：报告写 `Tester/tools/*.sh` 的路径 + `sha256`；脚本改了旧结论不继承（C5）。
4. **加载入口绑定在册实例**（MNT-008）：`--instance-id` **必填**，必须是 `metadata/modules/<module>.json`
   里登记的实例，且产物字节哈希与登记值一致，否则**在加载前**以退出码 2 拒绝。报告与升级单会写明
   在册 `instance_id`、候选 `source_commit`、模块登记文件 SHA-256、工具冻结基线 commit、报告生成 HEAD、
   仪器集合路径与 SHA-256、工具冻结状态。
5. **工具冻结范围**（MNT-010）：比较 `Tester/tools`、共享判据工具、相关规则/模板及静态身份配置，
   直接读取工作树字节并与完整基线提交对照。报告、升级单、`docs/records/` 和动态模块登记只作为
   本次运行证据输入，不会让仪器因后续记录或状态追加而误报变化；报告绑定仪器集合基线哈希和
   本次使用的模块登记文件 SHA-256。未传 `--tool-freeze-commit` 时以运行入口解析到的 HEAD 为基线，
   并在报告中单列完整 commit；已有冻结基线时应显式传入。
6. **每次运行唯一**：报告/日志/升级单用 `<日期>-<模块>-<产物基名>#<n>`，同一产物同日重跑**不覆盖**旧证据（MNT-008）。
7. **加载类操作人在环**；死机后**零重试**（含跨会话）（C3）。
8. **设备操作白名单**：`adb shell/push/pull/getprop/dmesg/reboot`、`adb reboot bootloader`、
   `fastboot devices/getvar/reboot`。**黑名单**：`fastboot flash/erase/-w`、`adb shell rm -rf`、
   清 pstore、改 superkey、卸载/重装 APatch、刷机、进 recovery 清数据（A1）。
9. **恢复通道**：软件通道优先——`adb reboot` **至多一次**，且必须已记录基线、基线 pstore 干净；
   物理动作（长按电源、进 fastboot、拔插、换机）由维护者执行，用升级单的
   「需要维护者执行的物理动作」发起、维护者用「动作回执」回填（A2/A5）。
10. **结论上限**：只对「该字节在该机型/该内核/该次加载下存活 N 秒且 X/Y 条强证据判据通过」负责（C2）。
11. 公开文件不写设备序列号、superkey、抓包原文；序列号只保留 `sha256(serial)[:8]`。
   **原始证据**（可能含序列号的 dmesg/pstore 全文）放 `local/tester-raw/`（gitignore），入库只放脱敏摘要（A4）。

## 目录

```text
Tester/tools/                 preflight.sh / run_test.sh / collect_evidence.sh
                              selftest_scripts.sh / mock_device.sh（离线自检用 mock 设备）
Tester/reports/environments/  环境事实 + 加载前基线
Tester/reports/runs/          实机报告（自动判据骨架 + 人工补全）
Tester/reports/escalations/   升级单（死机/卡死现场）
local/tester-raw/             原始证据与离线自检产物（gitignore，不入库）
```

> `selftest_scripts.sh` 用 mock 设备验证脚本逻辑与退出码（含"设备无响应必须 90"的回归）。
> **mock 通过不是真机结论**：它不能替代设备复验，也不得写进实机报告当结论。

## 铁律

1. 一次只加载**一个**变体；一次只验证一组判据。
2. 预检不通过就停，不带着不稳定设备测试。
3. 死机/卡死**不自救**：不重复加载、不改偏移、不刷机；只采集证据并通知维护者。
4. 公开文件不写设备序列号、superkey、抓包原文；序列号只保留 `sha256(serial)[:8]`。
5. 报告必须写清**未覆盖**部分、每项**未采集原因**（C7）与失败归属（实现缺陷 / 测试缺陷 / 环境事实）。
