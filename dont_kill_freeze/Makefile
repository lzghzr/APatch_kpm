MYKPM_VERSION := 1.0.2

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

include ../kpm_toolchain.mk

.DEFAULT_GOAL := all

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := dont_kill_freeze.c

all: base
ci: all

base: dont_kill_freeze_$(MYKPM_VERSION).kpm

debug: CFLAGS += -DCONFIG_DEBUG
debug: MYKPM_VER := _d
debug: dont_kill_freeze_$(MYKPM_VERSION)_debug.kpm

dont_kill_freeze_$(MYKPM_VERSION).kpm: ${objs} Makefile $(KPM_TOOLCHAIN_MK)
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@

dont_kill_freeze_$(MYKPM_VERSION)_debug.kpm: ${objs} Makefile $(KPM_TOOLCHAIN_MK)
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@

.PHONY: all base ci debug clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
