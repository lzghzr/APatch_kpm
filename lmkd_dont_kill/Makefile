MYKPM_VERSION := 1.0.0

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

include ../kpm_toolchain.mk

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := lmkd_dont_kill.c

all: base

base: lmkd_dont_kill_$(MYKPM_VERSION).kpm

debug: CFLAGS += -DCONFIG_DEBUG
debug: MYKPM_VER := _d
debug: lmkd_dont_kill_$(MYKPM_VERSION)_debug.kpm

lmkd_dont_kill_$(MYKPM_VERSION).kpm: ${objs} Makefile $(KPM_TOOLCHAIN_MK)
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@

lmkd_dont_kill_$(MYKPM_VERSION)_debug.kpm: ${objs} Makefile $(KPM_TOOLCHAIN_MK)
	${CC} $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o $@

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
