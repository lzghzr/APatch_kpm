MYKPM_VERSION := 2.3.0-20261114
KP_DIR ?= ../KernelPatch

include ../kpm_toolchain.mk

.DEFAULT_GOAL := all

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
layout_asm := $(OUT_DIR)/out/kpm-layout.S
link_kpm = $(CC) $(CFLAGS) $(CFLAG) $(MODE_FLAGS) -DMYKPM_VERSION=\"$(MYKPM_VERSION)\" $(INCLUDE_FLAGS) $(kpm_sources)

.DELETE_ON_ERROR:

all: dynamic static
ci: all
	@for file in "$(kpm).kpm" "$(kpm)_baselines.kpm" "$(LAYOUT_DIR)/$(notdir $(kpm))_baselines.kpm.json"; do \
	  test -f "$$file" || { printf 'Missing CI artifact: %s\n' "$$file" >&2; exit 1; }; \
	done

dynamic: $(kpm).kpm
static: $(kpm)_baselines.kpm
baselines: static

$(layout_asm): nm_offsets.c ../patch_offsets.py
	@mkdir -p "$(dir $@)"
	$(PYTHON) ../patch_offsets.py layout-asm --source "$<" > "$@.tmp" && mv "$@.tmp" "$@"

$(kpm).kpm $(kpm)_baselines.kpm: $(kpm_sources) $(headers) Makefile $(KPM_TOOLCHAIN_MK)

$(kpm).kpm:
	@mkdir -p "$(OUT_DIR)"
	@test ! -e "$@"
	$(link_kpm) -r -o "$@"

$(kpm)_baselines.kpm: MODE_FLAGS += -DCONFIG_KPM_BASELINES
$(kpm)_baselines.kpm: $(layout_asm)
	@mkdir -p "$(OUT_DIR)" "$(LAYOUT_DIR)"
	@test ! -e "$@"
	$(link_kpm) "$(layout_asm)" -r -o "$@"
	$(PYTHON) ../patch_offsets.py baseline "$@" --output "$(LAYOUT_DIR)/$(notdir $@).json"

.PHONY: all ci dynamic static baselines
