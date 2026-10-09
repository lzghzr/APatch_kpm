# re_kernel 8.0.0 Genl 兼容性修复候选交接

角色：Developer。本轮仅本地交接，候选身份交维护者登记，审计和真机结论由对应角色独立给出。

问题编号：DEV-011、DEV-012、DEV-014 的实现修复待复核；DEV-013 转交 Tester 核对实际加载字节。未关闭问题单。

修复范围：Sony 5.15 的 Genl 固定前缀、6.1/6.6 的组播寻址及配置段、6.6 Binder from、新顺序 kallsyms 离线提取。BTF 用于离线核对，运行时 BTF 查询方案尚未加入模块。

自检证据与边界：

- [Sony Genl 修复和 Oracle 调整说明](../responses/2026-10-08-DEV-011-genl-loading.md)。测试边界调整单独提交，待 Auditor 复核。
- [6.1/6.6 与 BTF 核对](../responses/2026-10-08-DEV-012-6.1-6.6-coverage.md)。各 37/37 字段一致，原八份成功语料输出保持一致；原 290 项反例与新增六轮 ASan/UBSan 自检通过。
- KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；NDK 26.3.11579264；release/debug 构建通过，17 项 ELF 导入保持一致，每变体 5 项已有 SDK 警告。
- 未验证本候选的真机加载/卸载、Genl 收发、Binder 清理及应用行为。旧困难 4.14 输入保持未覆盖。

维护者可用统一清单或每个新归档目录内的 MANIFEST 导入，不使用先前 exploration 身份。旧归档和当前模块目录 KPM 均未覆盖。Oracle 与生产代码是两个独立提交；源码冻结完成后本次只追加交接记录。

## 冻结身份补充（2026-10-08）
修复 commit：`f80c9a270c27d611b0147729e11c30d1f25577a1`。Oracle 边界独立提交：`fce5d75ef8e1a3c70921b5afa8e847dab751e707`；均为 Developer 无签名提交。
以下候选由干净冻结工作树经统一构建入口产生，产物字节与前述探索自检一致。Build ID / instance_id / SHA-256：

- base Build ID：`re_kernel-8.0.0+g9c1ce4ad97c0.r96eac7cd.kpb51197a.ndk26.3.11579264`。
- instance_id：`re_kernel-8.0.0+g9c1ce4ad97c0.r96eac7cd.kpb51197a.ndk26.3.11579264#1`。
- 产物 SHA-256：`931aca2529acfad4953ba62b024312b9e88fd6da037f891930a189f8d4485234`，47216 字节。

- debug Build ID：`re_kernel-8.0.0_debug+g9c1ce4ad97c0.r0a32e256.kpb51197a.ndk26.3.11579264`。
- instance_id：`re_kernel-8.0.0_debug+g9c1ce4ad97c0.r0a32e256.kpb51197a.ndk26.3.11579264#1`。
- 产物 SHA-256：`f9cb3b639e906f4f2053e508393bd682026ac3e752fc77c5a2d6d089f8b19322`，56472 字节。

证据：本地 `local/rek-freeze-20261008-tkmm64yd/candidate-verification.json` 的两项 candidate 核验均 `problems=[]`，源码按提交 blob 核验；新归档清单与产物在场且哈希一致。

[统一交接清单](re_kernel-8.0.0-20261008-genl.json) 已准备，维护者导入元数据后交 Auditor / Tester 独立复核。本轮结论来自实现方自检（构建 + 离线语料 + 代码走查），不是独立审计，也不是实机结论。
