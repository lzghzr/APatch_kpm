MYKPM_VERSION := 2.3.0-20261114
KP_DIR ?= ../KernelPatch

include ../kpm_toolchain.mk

# NoMount's warning policy is local to this module.
ifeq ($(TOOLCHAIN),ndk)
    WARN_FLAGS := -Wall -Werror -Wno-error=macro-redefined -Wno-unused-function
else
    WARN_FLAGS := -Wall -Wno-unused-function
endif

OUT_DIR ?= .
LAYOUT_DIR ?= $(OUT_DIR)
PYTHON ?= python3
CFLAGS = $(WARN_FLAGS) -O2 -fno-strict-aliasing -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin
INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))
kpm_sources := nomount.c ../kpm_runtime.c
headers := $(wildcard nm*.[ch]) ../kpm_utils.h ../patch_offsets.py
kpm := $(OUT_DIR)/NoMount_$(MYKPM_VERSION)
kpms := $(kpm).kpm $(kpm)_baselines.kpm

all: dynamic static
dynamic: $(kpm).kpm
static: $(kpm)_baselines.kpm
baselines: static

$(kpm)_baselines.kpm: MODE_FLAGS += -DCONFIG_KPM_BASELINES

$(kpms): $(kpm_sources) $(headers) Makefile $(KPM_TOOLCHAIN_MK)
	@mkdir -p $(OUT_DIR) $(LAYOUT_DIR)
	@test ! -e $@
	$(CC) $(CFLAGS) $(CFLAG) $(MODE_FLAGS) -DMYKPM_VERSION=\"$(MYKPM_VERSION)\" $(INCLUDE_FLAGS) $(kpm_sources) -r -o $@
	$(if $(filter %_baselines.kpm,$@),$(PYTHON) ../patch_offsets.py baseline $@ --source nm_offsets.c --output $(LAYOUT_DIR)/$(notdir $@).json)

.PHONY: all dynamic static baselines
