.text
.global reloc_probe
reloc_probe:
.L263: movz x0, #0
.reloc .L263, R_AARCH64_MOVW_UABS_G0, external
.L264: movk x0, #0
.reloc .L264, R_AARCH64_MOVW_UABS_G0_NC, external
.L265: movz x0, #0, lsl #16
.reloc .L265, R_AARCH64_MOVW_UABS_G1, external
.L266: movk x0, #0, lsl #16
.reloc .L266, R_AARCH64_MOVW_UABS_G1_NC, external
.L282: b external
.L287: movz x0, #0
.reloc .L287, R_AARCH64_MOVW_PREL_G0, external
.L299: ldr q0, [x1]
.reloc .L299, R_AARCH64_LDST128_ABS_LO12_NC, external
.L311: adrp x0, :got:external
.L312: ldr x0, [x0, :got_lo12:external]
.L313: ldr x0, [x1]
.reloc .L313, R_AARCH64_LD64_GOTPAGE_LO15, external
.section .data.probe,"aw",%progbits
.L314: .word 0
.reloc .L314, R_AARCH64_PLT32, external
