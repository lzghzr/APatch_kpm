/* SPDX-License-Identifier: GPL-2.0-only */
/* Typed ARM64 KCFI veneers. Hashes are verified against normalized Clang output
 * and native backend callbacks; the direct tail branch preserves the C ABI. */
.section .text.zs_kcfi,"ax",%progbits
.macro zs_entry name, hash
  .p2align 2
  .word \hash
  .global \name
  .type \name, %function
\name:
  .inst 0xd503245f /* bti c */
  b \name\()_impl
  .size \name, .-\name
.endm
zs_entry zs_native_compress, 0x6cfa6c9d
zs_entry zs_native_decompress, 0x6cfa6c9d
zs_entry zs_native_create_zstd, 0x99e4d7cb
zs_entry zs_native_create_lz4, 0x99e4d7cb
zs_entry zs_native_create_lz4kd, 0x99e4d7cb
zs_entry zs_native_destroy, 0x719f1be7
zs_entry zs_native_setup_zstd, 0x819d5c54
zs_entry zs_native_setup_lz4, 0x819d5c54
zs_entry zs_native_setup_lz4kd, 0x819d5c54
zs_entry zs_native_release, 0xef7e90ea
.section .note.GNU-stack,"",%progbits
