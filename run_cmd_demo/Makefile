MYKPM_VERSION := 1.3.0

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

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := run_cmd.c
headers := run_cmd.h rc_offsets.c rc_utils.h ../kpm_utils.h ../patch_offsets.py

kpm := $(OUT_DIR)/run_cmd_demo_$(MYKPM_VERSION)
kpms := $(kpm).kpm $(kpm)_baselines.kpm

all: static dynamic
base: all
baselines: static

static: $(kpm)_baselines.kpm
dynamic: $(kpm).kpm

$(kpm)_baselines.kpm: CFLAGS += -DCONFIG_KPM_BASELINES

$(kpms): ${objs} ${headers} Makefile
	@mkdir -p $(OUT_DIR) $(LAYOUT_DIR)
	@test ! -e $@
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@
	$(if $(filter %_baselines.kpm,$@),$(PYTHON) ../patch_offsets.py baseline $@ --source rc_offsets.c --output $(LAYOUT_DIR)/$(notdir $@).json)

.PHONY: all base baselines static dynamic clean
clean:
	rm -f *.kpm *.kpm.json *.o
