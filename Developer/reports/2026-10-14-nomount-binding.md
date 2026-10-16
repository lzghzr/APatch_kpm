# NoMount 0.5.0 inode独立绑定

两阶段Developer冻结候选。第一阶段0.4.3优化私有小对象分配，第二阶段0.5.0包含前一阶段实现并解耦inode与管理规则。分别保留提交、产物和自检；本报告不产生独立审计或实机通过结论。

## 身份

本轮源码：`773385757fcaaa6588e7946862e6784842c1901c`。上游7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3、SDK b51197aaba8f2272dd8a3e30c85698a29aa928c9保持冻结。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| base | `nomount-0.5.0+g6e270f8a5698.r7ab13a25.kpb51197a.ndk26.3.11579264#1` | `00fbddf01297ab2118dc734f09ac21d8036930cb50ed79632618485a21e00202` |
| baselines | `nomount-0.5.0_baselines+g6e270f8a5698.r71a1a5a7.kpb51197a.ndk26.3.11579264#1` | `fd5340662be4a36cb4bb63c86e33754d79a63aea23ac3fed3ae032e02eee3b9d` |
| baselines_debug | `nomount-0.5.0_baselines_debug+g6e270f8a5698.ree81fe8f.kpb51197a.ndk26.3.11579264#1` | `3467637b554e70251bee65cbe3f92d1735c1cf9afbe58b245774d77bf2d67e32` |
| debug | `nomount-0.5.0_debug+g6e270f8a5698.r44281ec1.kpb51197a.ndk26.3.11579264#1` | `9c7c6125d440e9871a1b83e5f132aac615f4b1ec4c924d1e0fe6717f18b68289` |

[基础交接](handoffs/2026-10-14-nomount-0.5.0.json)、[七目标派生](handoffs/2026-10-14-nomount-0.5.0-target.json)、[ZIP身份](data/2026-10-14-nomount-0.5.0-zip.json)、[自检回执](data/2026-10-14-nomount-0.5.0-selfcheck.json)。第一阶段见[0.4.3记录](2026-10-14-nomount-memory.md)。0.5.0可作为本轮完整实现候选，0.4.3用于拆分复核。

ZIP instance_id=`nomount-zip-0.5.0+g3294dedbfe67.ndk26.3.11579264#1`，SHA-256=`b6271dde3dda3ff2e1edf1330add61add12d03457ee6aa4b4cc73a8ea44100e3`，79475字节。相比0.4.2，32个条目中仅module.prop改变，31个条目逐字节相同；安装、用户态与WebUI运行行为沿用原版。

## 实现及生命周期

nm_inode_info持独立path、目录节点、类型及初始化状态。调用者持有规则引用期间复制path并执行原生path_get；普通文件在new_inode成功后取引用，目录候选在iget前取path/node。新inode接收候选，缓存命中及iget失败释放候选引用。inode不持管理规则引用；撤销规则后可释放规则对象，已打开文件继续从独立path执行源权限检查及读取。

getattr、open、backing子项与自动父目录继承使用独立path。evict先结束页映射借用，清理本inode的i_data，再在进程上下文释放path/node，RCU回调只释放info内存。规则数组及批次退役保持原语义。

目录按node散列，比较mount、dentry、node及类型；完成初始化后同时核对共同nm_inode_owner_prefix中的mode/uid/gid。私有initialized使用acquire/release，避免为I_NEW增加原生偏移；在原生iget等待新inode初始化后才能访问它。匹配从调用者保活的path取得源inode，退役info只用于比较指针及私有字段。dentry还核对虚拟ino，inherit_backing且父有来源时的强制重查保留。

46项92字节配置、七目标范围及加载时机保持。原生path_get声明使用const path指针，目标函数符号7/7齐全，五个有BTF目标的path_get／新分配接口参数与返回类型均核对。4.4／4.19使用原有共同path声明及目标函数符号，实机调用仍待Tester。

## 自检与覆盖

- int/bool完整宿主Oracle在ASan/UBSan下通过。每种保留原有693条用例位置：673条断言表达式保持，20条按新引用契约逐项迁移；新增独立绑定用例。原有34份测试脚本逐字节保持。
- 验证规则真正释放后open/read仍成功，cache hit的候选引用归还，同来源不同规则复用inode，mount/node/flags不匹配拒绝，mode/uid/gid变化拒绝旧缓存并重建，新inode未初始化状态、alias失败、所有旧分配失败点、UID／ACL调用、继承来源切换及path/node总引用平衡。
- /new来源替换夹具原来把所有名字折叠到同一path。本轮给/new独立dentry，保留来源更改后失效的原断言；另加同绑定替换的正例。此夹具变化及20条迁移需Auditor独立复核。
- 四份ARM64候选构建、candidate指纹复算、ELF导入、布局及寄存器检查通过；七目标16条派生记录对应12份字节。静态JSON/blob一致，仅替换92字节并能还原基础件，B2N附可选旧KP二进制转换。
- ZIP31条目一致，故不重复运行未改变的用户态／安装Oracle。宿主来源及权限函数是API夹具，未执行Android实机、真实CFI/ACL/并发或性能测量。5.15设备暂时不可用，6.1无实机；既有设备报告不覆盖新字节。

## 方案复核

决定：保留（Retain）。有效性：管理规则释放与inode来源引用分离，完整用例验证旧文件可用与缓存刷新。简洁性：直接使用原生path_get/put和已有节点引用，属性读共同结构片段，新增状态仅属私有info；没有新内核偏移。后果：同来源规则允许复用目录inode，属性变化会产生新视图；引用释放点和缓存候选清理均需独立审计，实机压力与并发覆盖由Tester提供。本阶段不改变控制批次顺序或规则存储容器。

版本登记提案见[0.5.0配套提案](../proposals/2026-10-14-nomount-0.5.0/README.md)。维护者可登记完整候选，Auditor复核代码及以下Oracle迁移，Tester再以确切基础实例或派生哈希执行设备验证。

## Oracle迁移明细

索引从0开始，两种actor ABI有相同20处。第38/164/169/193/399项不再增加规则refs；第44/45/199项直接确认规则释放与独立path释放；第126/362项改node散列；其余将旧rule字段访问改为独立绑定字段，365项额外要求initialized。其他断言保持原表达式及顺序，没有删除旧用例。

### 原断言 38

```c
assert(!nm_materialize_file(parent,(void*)1234,rule,42) && rule->refs==2 && created);
```

改为：

```c
assert(!nm_materialize_file(parent,(void*)1234,rule,42) && rule->refs==1 && created);
```

### 原断言 44

```c
assert(rule->refs==1 && !path_puts);
```

改为：

```c
assert(binding_freed_rules==freed_before+1 && path_puts==1);
```

### 原断言 45

```c
assert(path_puts==1 && pending_rcu && truncates==1 && clears==1);
```

改为：

```c
assert(path_puts==2 && pending_rcu && truncates==1 && clears==1);
```

### 原断言 126

```c
assert(super==(void*)&sb && hash==(unsigned long)((struct nm_inode_info*)data)->rule && !rcu_depth && !hash_depth);
```

改为：

```c
assert(super==(void*)&sb && hash==(unsigned long)((struct nm_inode_info*)data)->dir_node && !rcu_depth && !hash_depth);
```

### 原断言 164

```c
assert(first&&rule->refs==2&&child_node->refs==2&&unlock_calls==new_before+1&&set_calls==new_before+1);
```

改为：

```c
assert(first&&rule->refs==1&&child_node->refs==2&&unlock_calls==new_before+1&&set_calls==new_before+1);
```

### 原断言 169

```c
assert(cached_directory==first&&directory_refs==2&&rule->refs==2&&child_node->refs==2&&set_calls==new_before+1&&unlock_calls==new_before+1);
```

改为：

```c
assert(cached_directory==first&&directory_refs==2&&rule->refs==1&&child_node->refs==2&&set_calls==new_before+1&&unlock_calls==new_before+1);
```

### 原断言 193

```c
assert(PTR_ERR(nm_directory_lookup(parent,(void*)nested_dentry,0))==-ELOOP&&directory_refs==before&&rule->refs==2&&child_node->refs==2);
```

改为：

```c
assert(PTR_ERR(nm_directory_lookup(parent,(void*)nested_dentry,0))==-ELOOP&&directory_refs==before&&rule->refs==1&&child_node->refs==2);
```

### 原断言 199

```c
assert(rule->refs==1&&!nm_dentry_revalidate((void*)virtual_dentry,0));
```

改为：

```c
assert(binding_freed_rules==retired_before+1&&!nm_dentry_revalidate((void*)virtual_dentry,0));
```

### 原断言 362

```c
assert(!rcu_depth&&!spin_depth&&!hash_depth&&hash==(uintptr_t)((struct nm_inode_info*)data)->rule);
```

改为：

```c
assert(!rcu_depth&&!spin_depth&&!hash_depth&&hash==(uintptr_t)((struct nm_inode_info*)data)->dir_node);
```

### 原断言 365

```c
assert(info&&info->rule&&info->dir_node);
```

改为：

```c
assert(info&&info->initialized&&info->dir_node);
```

### 原断言 399

```c
assert(root_inode&&nm_is_directory_inode(root_inode)&&!nm_directory_proxy(nm_inode_ops(root_inode))&&root_rule->refs==2);
```

改为：

```c
assert(root_inode&&nm_is_directory_inode(root_inode)&&!nm_directory_proxy(nm_inode_ops(root_inode))&&root_rule->refs==1);
```

### 原断言 416

```c
assert(first_info->rule->published&&first_info->rule->refs==1&&first_info->rule->r_path.dentry==source_file_dentry);
```

改为：

```c
assert(first_info->initialized&&first_info->flags==0&&first_info->r_path.dentry==source_file_dentry);
```

### 原断言 418

```c
assert(((struct nm_inode_info*)nm_inode_private(replacement_file))->rule->r_path.dentry==source_new_dentry&&first_info->rule->r_path.dentry==source_file_dentry);
```

改为：

```c
assert(((struct nm_inode_info*)nm_inode_private(replacement_file))->r_path.dentry==source_new_dentry&&first_info->r_path.dentry==source_file_dentry);
```

### 原断言 451

```c
assert(info&&info->rule->r_path.dentry==tree_dentry[source_index]&&info->dir_node==node);
```

改为：

```c
assert(info&&info->r_path.dentry==tree_dentry[source_index]&&info->dir_node==node);
```

### 原断言 470

```c
assert(!nm_backing_open_permission(&((struct nm_inode_info*)nm_inode_private(deep_a))->rule->r_path)&&tree_reads==1);
```

改为：

```c
assert(!nm_backing_open_permission(&((struct nm_inode_info*)nm_inode_private(deep_a))->r_path)&&tree_reads==1);
```

### 原断言 476

```c
assert(pure&&!((struct nm_inode_info*)nm_inode_private(pure))->rule->r_path.dentry);
```

改为：

```c
assert(pure&&!((struct nm_inode_info*)nm_inode_private(pure))->r_path.dentry);
```

### 原断言 485

```c
assert(((struct nm_inode_info*)nm_inode_private(injected))->rule->r_path.dentry==tree_dentry[6]);
```

改为：

```c
assert(((struct nm_inode_info*)nm_inode_private(injected))->r_path.dentry==tree_dentry[6]);
```

### 原断言 486

```c
assert(((struct nm_inode_info*)nm_inode_private(nm_dentry_inode(view_dentry[12])))->rule->r_path.dentry==tree_dentry[7]);
```

改为：

```c
assert(((struct nm_inode_info*)nm_inode_private(nm_dentry_inode(view_dentry[12])))->r_path.dentry==tree_dentry[7]);
```

### 原断言 571

```c
assert(((struct nm_inode_info*)nm_inode_private(sub))->rule->r_path.dentry==tree_dentry[1]);
```

改为：

```c
assert(((struct nm_inode_info*)nm_inode_private(sub))->r_path.dentry==tree_dentry[1]);
```

### 原断言 572

```c
assert(deep&&((struct nm_inode_info*)nm_inode_private(deep))->rule->r_path.dentry==tree_dentry[2]);
```

改为：

```c
assert(deep&&((struct nm_inode_info*)nm_inode_private(deep))->r_path.dentry==tree_dentry[2]);
```
