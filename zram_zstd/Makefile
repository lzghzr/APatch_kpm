MYKPM_VERSION := 1.3.0
KP_DIR ?= ../KernelPatch

include ../kpm_toolchain.mk

OUT_DIR ?= .
LAYOUT_DIR ?= $(OUT_DIR)
PYTHON ?= python3
CFLAGS = -Wall -O2 -fno-strict-aliasing -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin
INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

ZSTD_ROOT := upstream/zstd/lib
CODEC_DIR := $(LAYOUT_DIR)/out/codec
GENERATED_DIR := $(CODEC_DIR)/generated
CODEC_FLAGS := -DXXH_NO_STDLIB -DXXH_STATIC_LINKING_ONLY= -I. -Icompat -I$(GENERATED_DIR) -I$(GENERATED_DIR)/common
codec := $(filter-out $(ZSTD_ROOT)/common/pool.c $(ZSTD_ROOT)/common/threading.c $(ZSTD_ROOT)/compress/zstdmt_compress.c,$(wildcard $(ZSTD_ROOT)/common/*.c $(ZSTD_ROOT)/compress/*.c $(ZSTD_ROOT)/decompress/*.c))
codec_rel := $(patsubst $(ZSTD_ROOT)/%,%,$(codec))
codec_objs := $(addprefix $(CODEC_DIR)/,$(codec_rel:.c=.o))
kpm := $(OUT_DIR)/zram_zstd_$(MYKPM_VERSION)
kpms := $(kpm).kpm $(kpm)_baselines.kpm

all: dynamic static
dynamic: $(kpm).kpm
static: $(kpm)_baselines.kpm
baselines: static

$(GENERATED_DIR)/MANIFEST.json: tools/prepare_codec.py zs_zstd_deps.h zs_memory.h upstream/lz4kd/lz4kd_private.h $(wildcard $(ZSTD_ROOT)/*.[chS] $(ZSTD_ROOT)/*/*.[chS]) upstream/zstd/contrib/freestanding_lib/freestanding.py upstream/zstd/contrib/linux-kernel/mem.h upstream/zstd/contrib/linux-kernel/zstd_deps.h
	$(PYTHON) tools/prepare_codec.py --output $(GENERATED_DIR)

$(addprefix $(GENERATED_DIR)/,$(codec_rel)): $(GENERATED_DIR)/MANIFEST.json

$(CODEC_DIR)/%.o: $(GENERATED_DIR)/%.c $(GENERATED_DIR)/MANIFEST.json $(wildcard compat/linux/*.h compat/asm/*.h) Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAG) $(CODEC_FLAGS) -c $< -o $@

LZ4_OBJ := $(CODEC_DIR)/lz4.o
$(LZ4_OBJ): upstream/lz4/lz4.c upstream/lz4/lz4.h zs_lz4_config.h zs_memory.h Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAG) -O3 -include zs_lz4_config.h -c $< -o $@

LZ4KD_OBJ := $(CODEC_DIR)/lz4kd_encode.o $(CODEC_DIR)/lz4kd_decode.o
$(CODEC_DIR)/lz4kd_encode.o: zs_lz4kd_encode.c upstream/lz4kd/lz4kd_encode.c $(GENERATED_DIR)/MANIFEST.json zs_memory.h $(wildcard upstream/lz4kd/*.h) zs_lz4kd_config.h Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAG) -I. -Icompat -I$(GENERATED_DIR) -include zs_lz4kd_config.h -c $< -o $@

$(CODEC_DIR)/lz4kd_decode.o: zs_lz4kd_decode.c $(GENERATED_DIR)/MANIFEST.json zs_memory.h $(wildcard upstream/lz4kd/*.h) zs_lz4kd_config.h Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAG) -I. -Icompat -I$(GENERATED_DIR) -include zs_lz4kd_config.h -c $< -o $@

$(kpm)_baselines.kpm: MODE_FLAGS += -DCONFIG_KPM_BASELINES

NATIVE_ENTRY_OBJ := $(CODEC_DIR)/zs_native_entry.o
$(NATIVE_ENTRY_OBJ): zs_native_entry.S Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAG) -c $< -o $@

# Compiler libcalls are separate from the upstream codec objects.
RUNTIME_OBJ := $(LAYOUT_DIR)/out/kpm_runtime.o
$(RUNTIME_OBJ): ../kpm_runtime.c Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) -DKPM_RUNTIME_COPY -c $< -o $@

$(kpms): zram_zstd.c $(RUNTIME_OBJ) zs_structs.h zs_offsets.c zs_btf.c zs_display.c zs_memory.h zs_zstd_config.h zs_lz4kd.c zs_native.h zs_native.c zs_native_btf.c $(NATIVE_ENTRY_OBJ) $(codec_objs) $(LZ4_OBJ) $(LZ4KD_OBJ) zs_lz4_config.h ../kpm_utils.h ../patch_offsets.py Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p $(OUT_DIR) $(LAYOUT_DIR)
	@test ! -e $@
	$(CC) $(CFLAGS) $(CFLAG) $(MODE_FLAGS) -DMYKPM_VERSION=\"$(MYKPM_VERSION)\" $(INCLUDE_FLAGS) $(CODEC_FLAGS) zram_zstd.c $(RUNTIME_OBJ) $(NATIVE_ENTRY_OBJ) $(codec_objs) $(LZ4_OBJ) $(LZ4KD_OBJ) -r -o $@
	$(if $(filter %_baselines.kpm,$@),$(PYTHON) ../patch_offsets.py baseline $@ --source zs_offsets.c --output $(LAYOUT_DIR)/$(notdir $@).json)

.PHONY: all dynamic static baselines
