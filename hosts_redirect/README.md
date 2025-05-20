# hosts_redirect
## 模块作用
重定向 `/system/etc/hosts` 文件到 `/data/adb/hosts/{name}`<br />
可使通过 `参数` 或 `kpatch` 更改 `{name}` 值<br />
例如 `kpatch $SUPERKEY kpm ctl0 hosts_redirect adblock` 重定向到 `/data/adb/hosts/adblock`

## 更新记录
### 2.0.0
变更重定向文件路径为 `/data/adb/hosts/{name}`
### 1.2.0
支持相对路径
### 1.1.0
支持使用 `kpatch` 动态调整重定向
### 1.0.0
练手模块, 灵感来源于 [hosts_file_redirect](https://github.com/AndroidPatch/kpm/tree/main/src/hosts_file_redirect)
