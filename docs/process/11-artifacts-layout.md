# 产物目录契约（artifacts/）

`artifacts/` 不入库，但**布局是身份的一部分**：元数据 `builds[].artifacts[].path` 与
`binary_ports[].derived.path` 直接按路径索引，报告也按路径引用证据。

## 一、实例目录

```
artifacts/<module>-<version>+g<source7>.r<recipe8>.kpb<kp7>.ndk<ver>[#n]/
```

- 目录名必须是**完整 instance_id**，与 `metadata/modules/<module>.json` 的 `builds[].instance_id` 逐字一致；
- 目录内保持产物原名：`<Module>_<version>.kpm`、同名 `.kpm.json`（静态基线布局）、`MANIFEST.json`；
- **禁止按模块再分层**（写成 `artifacts/<module>/<instance>/…` 会让所有 `verify` 与 `delivery` 核验失效）。

## 二、两个合法子目录

| 路径 | 内容 | 身份登记位置 |
| --- | --- | --- |
| `artifacts/binary-port/<模块>/<派生件 sha256>/<派生件名>` | 二进制派生件（`patch_offsets.py` 产出） | `binary_ports[]`（base 实例 + 工具哈希 + 命令 + 派生哈希） |
| `artifacts/companion/<模块>/<实例>/` | 配套 ZIP 等附属产物 | 交接清单与回执 |

## 三、不可覆盖

同一 Build ID 的产物**不得重建覆盖**；重建使用新的空输出目录并产生新 Build ID。
已归档产物与 `MANIFEST.json` 一律不可覆盖。

## 四、未引用目录

元数据未引用的实例目录（历史 debug 构建、试验件）仍是证据，**不要删除**。
需要腾空间时：先确认 `docs/records/`、`Tester/reports/`、`Auditor/reports/`、`Developer/reports/`、`metadata/`
中都没有该路径引用，再整体移动（不是删除）。

## 五、工作目录（非产物）

构建树、抽取的内核、临时脚本**不要放进 `artifacts/`**——那会被当产物误引用。
它们属于本机工作区（`local/` 下按轮次命名），只在需要登记产物时才把最终字节落到 `artifacts/`。
