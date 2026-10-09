MYKPM_VERSION := 1.6-20261008

ifndef KP_DIR
	KP_DIR = ../KernelPatch
endif

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

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := re_kernel.c re_runtime.c
headers := re_kernel.h re_structs.h re_utils.h re_offsets.c ../kpm_utils.h

all: base
debug: base_debug

base: $(OUT_DIR)/re_kernel_x_$(MYKPM_VERSION).kpm

base_debug: CFLAGS += -DCONFIG_DEBUG
base_debug: MYKPM_VER := _d
base_debug: $(OUT_DIR)/re_kernel_x_$(MYKPM_VERSION)_debug.kpm

$(OUT_DIR)/re_kernel_x_$(MYKPM_VERSION).kpm: ${objs} ${headers}
	@mkdir -p $(OUT_DIR) $(LAYOUT_DIR)
	@test ! -e $@
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@
	$(PYTHON) tools/patch_offsets.py baseline $@ --output $(LAYOUT_DIR)/$(notdir $@).json

$(OUT_DIR)/re_kernel_x_$(MYKPM_VERSION)_debug.kpm: ${objs} ${headers}
	@mkdir -p $(OUT_DIR) $(LAYOUT_DIR)
	@test ! -e $@
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@
	$(PYTHON) tools/patch_offsets.py baseline $@ --output $(LAYOUT_DIR)/$(notdir $@).json

# 同一基线通过配置表选择 Binder 释放调用方式。
baselines: base base_debug

.PHONY: all debug base base_debug baselines clean
clean:
	rm -rf *.kpm *.kpm.json
	find . -name "*.o" | xargs rm -f
