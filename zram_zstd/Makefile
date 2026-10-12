MYKPM_VERSION := 1.0.0
KP_DIR ?= ../KernelPatch

OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
HOST_TAG = $(OS_NAME)-$(MACHINE)
ifeq ($(HOST_TAG), darwin-arm64)
    HOST_TAG = darwin-x86_64
endif
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(HOST_TAG)/bin
ifdef ANDROID_NDK_LATEST_HOME
    NDK_PATH ?= $(ANDROID_NDK_LATEST_HOME)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK
    NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)
endif
ifdef TARGET_COMPILE
    CC := $(TARGET_COMPILE)gcc
    LD := $(TARGET_COMPILE)ld
else ifdef NDK_PATH
    CC := $(NDK_PATH)/aarch64-linux-android31-clang
    LD := $(NDK_PATH)/ld.lld
endif

OUT_DIR ?= .
LAYOUT_DIR ?= $(OUT_DIR)
PYTHON ?= python3
CFLAGS = -Wall -O2 -fno-strict-aliasing -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin
INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

ZSTD_ROOT := zstd/lib
CODEC_DIR := $(LAYOUT_DIR)/out/codec
GENERATED_DIR := $(CODEC_DIR)/generated
CODEC_FLAGS := -DXXH_NO_STDLIB -DXXH_STATIC_LINKING_ONLY= -Icompat -I$(GENERATED_DIR) -I$(GENERATED_DIR)/common
codec := $(filter-out $(ZSTD_ROOT)/common/pool.c $(ZSTD_ROOT)/common/threading.c $(ZSTD_ROOT)/compress/zstdmt_compress.c,$(wildcard $(ZSTD_ROOT)/common/*.c $(ZSTD_ROOT)/compress/*.c $(ZSTD_ROOT)/decompress/*.c))
codec_rel := $(patsubst $(ZSTD_ROOT)/%,%,$(codec))
codec_objs := $(addprefix $(CODEC_DIR)/,$(codec_rel:.c=.o))
kpm := $(OUT_DIR)/zram_zstd_$(MYKPM_VERSION)
kpms := $(kpm).kpm $(kpm)_debug.kpm $(kpm)_baselines.kpm $(kpm)_baselines_debug.kpm

all: dynamic static
debug: dynamic_debug static_debug
dynamic: $(kpm).kpm
static: $(kpm)_baselines.kpm
dynamic_debug: $(kpm)_debug.kpm
static_debug: $(kpm)_baselines_debug.kpm
baselines: static static_debug

$(GENERATED_DIR)/MANIFEST.json: tools/prepare_codec.py $(wildcard $(ZSTD_ROOT)/*.[chS] $(ZSTD_ROOT)/*/*.[chS]) zstd/contrib/freestanding_lib/freestanding.py zstd/contrib/linux-kernel/mem.h zstd/contrib/linux-kernel/zstd_deps.h
	$(PYTHON) tools/prepare_codec.py --output $(GENERATED_DIR)

$(addprefix $(GENERATED_DIR)/,$(codec_rel)): $(GENERATED_DIR)/MANIFEST.json

$(CODEC_DIR)/%.o: $(GENERATED_DIR)/%.c $(GENERATED_DIR)/MANIFEST.json $(wildcard compat/linux/*.h compat/asm/*.h) Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAG) $(CODEC_FLAGS) -c $< -o $@

$(kpm)_baselines.kpm $(kpm)_baselines_debug.kpm: MODE_FLAGS += -DCONFIG_KPM_BASELINES
$(kpm)_debug.kpm $(kpm)_baselines_debug.kpm: MODE_FLAGS += -DCONFIG_DEBUG
$(kpm)_debug.kpm $(kpm)_baselines_debug.kpm: MYKPM_VER := _d

$(kpms): zram_zstd.c zs_structs.h zs_offsets.c zs_btf.c zs_display.c zs_runtime.c $(codec_objs) ../kpm_utils.h ../patch_offsets.py Makefile
	@mkdir -p $(OUT_DIR) $(LAYOUT_DIR)
	@test ! -e $@
	$(CC) $(CFLAGS) $(CFLAG) $(MODE_FLAGS) -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\" $(INCLUDE_FLAGS) $(CODEC_FLAGS) zram_zstd.c zs_runtime.c $(codec_objs) -r -o $@
	$(if $(filter %_baselines.kpm %_baselines_debug.kpm,$@),$(PYTHON) ../patch_offsets.py baseline $@ --source zs_offsets.c --output $(LAYOUT_DIR)/$(notdir $@).json)

.PHONY: all debug dynamic static dynamic_debug static_debug baselines
