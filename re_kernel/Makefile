MYKPM_VERSION := 11.7-20261109

ifndef KP_DIR
	KP_DIR = ../KernelPatch
endif

include ../kpm_toolchain.mk

.DEFAULT_GOAL := all

OUT_DIR ?= .
LAYOUT_DIR ?= $(OUT_DIR)
PYTHON ?= python3

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := re_kernel.c ../kpm_runtime.c
headers := re_kernel.h re_utils.h re_offsets.c ../kpm_utils.h ../patch_offsets.py
headers += re_structs.h re_btf.c re_vendor_btf.c

kpm := $(OUT_DIR)/re_kernel_$(MYKPM_VERSION)
dynamic_kpms := $(kpm).kpm $(kpm)_debug.kpm
static_kpms := $(kpm)_baselines.kpm $(kpm)_baselines_debug.kpm
layout_asm := $(OUT_DIR)/out/kpm-layout.S

.DELETE_ON_ERROR:

all: static dynamic
ci: all debug
	@for file in "$(kpm).kpm" "$(kpm)_baselines.kpm" "$(LAYOUT_DIR)/$(notdir $(kpm))_baselines.kpm.json"; do \
	  test -f "$$file" || { printf 'Missing CI artifact: %s\n' "$$file" >&2; exit 1; }; \
	done

debug: static_debug dynamic_debug
base: all
base_debug: debug
baselines: static static_debug

static: $(kpm)_baselines.kpm
dynamic: $(kpm).kpm
static_debug: $(kpm)_baselines_debug.kpm
dynamic_debug: $(kpm)_debug.kpm

$(layout_asm): re_offsets.c ../patch_offsets.py
	@mkdir -p "$(dir $@)"
	$(PYTHON) ../patch_offsets.py layout-asm --source "$<" > "$@.tmp" && mv "$@.tmp" "$@"

$(static_kpms): CFLAGS += -DCONFIG_KPM_BASELINES
$(kpm)_baselines_debug.kpm $(kpm)_debug.kpm: CFLAGS += -DCONFIG_DEBUG
$(kpm)_baselines_debug.kpm $(kpm)_debug.kpm: MYKPM_VER := _d

$(dynamic_kpms) $(static_kpms): $(objs) $(headers) Makefile $(KPM_TOOLCHAIN_MK)

$(dynamic_kpms):
	@mkdir -p "$(OUT_DIR)"
	@test ! -e "$@"
	$(CC) $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) -r -o "$@"

$(static_kpms): $(layout_asm)
	@mkdir -p "$(OUT_DIR)" "$(LAYOUT_DIR)"
	@test ! -e "$@"
	$(CC) $(CFLAGS) $(CFLAG) $(INCLUDE_FLAGS) $(objs) "$(layout_asm)" -r -o "$@"
	$(PYTHON) ../patch_offsets.py baseline "$@" --output "$(LAYOUT_DIR)/$(notdir $@).json"

.PHONY: all ci debug base base_debug baselines static dynamic static_debug dynamic_debug clean
clean:
	rm -f *.kpm *.kpm.json *.o
