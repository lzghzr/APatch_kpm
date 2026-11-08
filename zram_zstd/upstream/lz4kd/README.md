# LZ4KD 普通块源码

来源：[2108282/hyperos-lz4kd](https://github.com/2108282/hyperos-lz4kd/tree/e58761a19874b18c6534810212c66f3140435573/lz4kd_module)，
固定提交 `e58761a19874b18c6534810212c66f3140435573`，访问日期 2026-11-05。
算法自报版本为 `2022.03.20`，版权为 Huawei Technologies Co., Ltd. 2022。

本目录保留 `lz4kd.h`、`lz4kd_encode.c`、`lz4kd_decode.c`、`lz4kd_private.h`、
`lz4kd_encode_private.h` 的上游字节。两个 C 文件声明 `Dual BSD/GPL`；本模块选择 GPL，
许可证全文见仓库根目录 [LICENSE](../../../../LICENSE)。上游未提供独立的 BSD 许可证文本。

普通编码器最多接受 4096 字节。KPM 编译原始编码器，平台配置在 `zs_lz4kd_config.h`，
Crypto API 封装在 `zs_lz4kd.c`。`zs_lz4kd_decode.c` 是此处解码器的派生文件，
保留上游批量复制和小偏移展开；入口移除 pattern 启发式，三处可能重叠的固定宽度复制改用 builtin memmove。
本目录原始解码器继续保留用于开发差分自检，源文件字节不变。
zram 各页独立压缩，不使用 delta 的跨页字典。

KPM 使用 header 为 0 的普通块格式，包括不可压缩数据的 literal-only 块。
原始解码器把任意 8 字节输入识别成 pattern，与正常的 8 字节普通块冲突；
KPM 按普通块语法解析，不实现该启发式 pattern 扩展。来源仓库的 Crypto 包装层不参与构建。
