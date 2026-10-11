# 升级证据：re_kernel / re_kernel-11.7_debug+g74820b6486a2.r58923f37.kpb51197a.ndk26.3.11579264

- 采集时间：2026-10-10T08:44:22-0700
- 采集工具：`Tester/tools/collect_evidence.sh`
- 流程：`docs/process/07-escalation-device.md`
- 升级单模板：`docs/templates/escalation.md`

## 文件清单

| 文件 | 内容 | 采集结果 |
| --- | --- | --- |
| `dmesg-crash-lines.txt` | | 有内容 |
| `dmesg-tail.txt` | | 有内容 |
| `env.txt` | | 有内容 |
| `last-kmsg.txt` | | 采不到 |
| `modules-list.txt` | | 采不到 |
| `pstore-console-ramoops.txt` | | 采不到 |
| `pstore-dmesg-ramoops.txt` | | 采不到 |
| `uptime-btime.txt` | | 有内容 |

## 未做（必须确认）

- [x] 未重复加载同一 `.kpm`
- [x] 未修改代码或偏移
- [x] 未刷机 / 未进 recovery / 未清 pstore
- [ ] 是否强制重启过设备：______（若重启过，写明时间，pstore 仍在）

## 下一步

1. 用 `docs/templates/escalation.md` 写升级单（本目录），补全现象与请求事项。
2. **通知维护者**（会话 @维护者，或提 issue），附本目录相对路径。
3. 在维护者裁决前不要继续测试。

## 维护者证据整理（2026-10-10）

原始 dmesg 全文转存本地维护者证据目录，公开同名文件保存脱敏摘录和原件 SHA-256。其余采集失败输出作为环境事实保留。升级单中重启原因与 KERNEL_PANIC 的技术记录保留；本摘要不扩大 Tester 原结论范围。
