MYKPM_VERSION := 11.7

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

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := re_kernel.c re_runtime.c
headers := re_kernel.h re_utils.h re_offsets.c ../kpm_utils.h

all: base
debug: base_debug

base: re_kernel_$(MYKPM_VERSION).kpm

base_debug: CFLAGS += -DCONFIG_DEBUG
base_debug: MYKPM_VER := _d
base_debug: re_kernel_$(MYKPM_VERSION)_debug.kpm

re_kernel_$(MYKPM_VERSION).kpm: ${objs} ${headers}
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@

re_kernel_$(MYKPM_VERSION)_debug.kpm: ${objs} ${headers}
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@

.PHONY: all debug base base_debug clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
