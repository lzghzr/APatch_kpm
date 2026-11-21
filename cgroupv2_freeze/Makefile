MYKPM_VERSION := 1.1.0

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

include ../kpm_toolchain.mk

OUT_DIR ?= .
LAYOUT_DIR ?= $(OUT_DIR)
PYTHON ?= python3

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := cgroupv2_freeze.c ../kpm_runtime.c cfv2_uid_mount.c
headers := cgroupv2_freeze.h cfv2_utils.h cfv2_offsets.c ../kpm_utils.h

kpm := $(OUT_DIR)/cgroupv2_freeze_$(MYKPM_VERSION)
layout := $(LAYOUT_DIR)/$(notdir $(kpm))_baselines.kpm.json

.DEFAULT_GOAL := base
.DELETE_ON_ERROR:

all: dynamic static
base: dynamic
baselines: static
dynamic: $(kpm).kpm
static: $(kpm)_baselines.kpm $(layout)

$(kpm).kpm: $(objs) $(headers) Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p "$(OUT_DIR)"
	$(CC) $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o "$@"

$(kpm)_baselines.kpm: $(objs) $(headers) Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p "$(OUT_DIR)"
	@test ! -e "$@"
	$(CC) $(CFLAGS) -DCONFIG_KPM_BASELINES $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o "$@"

$(layout): $(kpm)_baselines.kpm ../patch_offsets.py cfv2_utils.h
	@mkdir -p "$(LAYOUT_DIR)"
	$(PYTHON) ../patch_offsets.py baseline "$<" --source cfv2_utils.h --output "$@"

.PHONY: all base baselines dynamic static clean
clean:
	rm -f *.kpm *.kpm.json
	find . -name "*.o" | xargs rm -f
