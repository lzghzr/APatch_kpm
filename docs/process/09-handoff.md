# 交接流程

适用：换机器、新会话、他人接手、长期中断后恢复。

## 一、必读清单（按顺序）

| 顺序 | 文件 | 读它为了 |
| --- | --- | --- |
| 1 | `AGENTS.md` | 仓库硬规则与常用入口 |
| 2 | `docs/README.md` | 流程总览与索引 |
| 3 | `docs/process/02-roles.md` | 角色分工、路径所有权、维护者的裁决职责 |
| 4 | `docs/process/03-round-flow.md` | 一轮的步骤与顺序（含不可并行项） |
| 5 | `docs/process/01-identity.md` | 身份三要素与「身份登记不入库」 |
| 6 | `docs/process/05-maintainer-acceptance.md` | 验收清单与交付绑定 |
| 7 | `docs/process/08-review-economics.md` | 复核成本口径与门禁摩擦处理 |
| 8 | 本文件 | 交接动作与核对清单 |
| 9 | 对应角色手册与技能 `SKILL.md` | 该角色的判据细节 |

## 二、仓库内容边界

**在版本库内**：模块源码与构建器（`nomount/`、`zram_zstd/`、`hosts_redirect/`、`re_kernel*/` 等）、
`tools/`（门禁、身份、构建）、`docs/process/`、`docs/templates/`、`.github/workflows/`、
`kernel_img/offset_harness/`、`.agents/skills/`。

**不在版本库内**（由 `.gitignore` 排除，口径见 `01-identity.md`「身份登记不入库：接手时自建」）：

- `metadata/`（构建登记、`identity.json`、`checks/`、`handoffs/`）
- `docs/records/`（裁定、授权、常驻记录）、`docs/proposals/`
- 三方目录下的 `reports/`、`proposals/`、`patches/`
- `local/`：目标配置（`nomount/local/configs/`）、构建产物（`artifacts/`）、原始日志与备份

因此克隆得到的仓库**能构建、能跑门禁、能读流程**，但**没有身份登记与历史记录**。

## 二·五、随交接转移的材料（克隆不包含）

只拿到仓库时，能读源码与流程，但**无法复算身份、验收与交付**。交出方必须一并转移：

| 材料 | 用途 | 缺失后果 |
| --- | --- | --- |
| `artifacts/<build_id>#<n>/` | 复算产物哈希 | 无法执行 `verify --profile candidate/delivery` |
| `metadata/modules/*.json` | 构建登记、验收、问题单 | 同上；且版本一致性检查无依据 |
| `metadata/identity.json` | 角色分离与判据约定 | 门禁 `metadata_schema` 失败 |
| `docs/records/` | 授权、验收、交付回执 | 交付无法自证 |
| `Auditor/reports/`、`Tester/reports/` | 审计与实机证据 | 验收结论无来源 |
| 工具链标签（如 NDK 版本） | 复现构建 | 产物字节不可复现 |

克隆侧可先跑 `python3 tools/bootstrap_local.py` 建骨架，再用
`python3 tools/check_repository.py --portable` 自检公开部分（跳过身份、验收与交付检查）。

## 三、接手动作

1. **读**：完成上表。
2. **定位**：写清三件事——承担哪个角色、本轮对象（文件 / 提交 / 实例）、本轮不做的越权项。
3. **重建本地材料**：按 `01-identity.md` 的五步自建
   `metadata/modules/*.json`、`metadata/identity.json`、`metadata/checks/`、`docs/records/`；
   目标配置放 `nomount/local/configs/`，产物核对用 `artifacts/`。
4. **自检**：
   ```bash
   python3 tools/check_repository.py --strict
   python3 tools/selftest_tools.py
   ```
   逐项补齐差异；补不齐说明产物或记录被改动，按问题单处理。
5. **复算**：`python3 tools/identity.py verify --module <模块> --profile candidate`，
   核对 `source_commit`、`instance_id` 与产物哈希。
6. **记录**：按下节写一份交接记录。

## 四、交接记录（本地，不入库）

写清七项：

```text
HEAD 与分支、与 origin 的关系
门禁与自检结果（原样输出）
本轮改动范围（提交列表）
自建的本地材料（路径 + 份数）
缺口清单（缺失的配置 / 对象 / 提交及其影响）
未完成项与下一步
签名与推送状态（哪些提交待签、哪些待推）
```

## 五、交出方核对清单

交接前确认：

- [ ] 工作树干净；`git status` 无未提交改动
- [ ] 待签 / 待推提交已列清，签名与推送由用户执行
- [ ] 门禁与自检输出已贴进交接记录
- [ ] 本地材料（`metadata/`、`docs/records/`、`nomount/local/configs/`）已有备份路径
- [ ] 未完成项写明触发条件与建议下一步
