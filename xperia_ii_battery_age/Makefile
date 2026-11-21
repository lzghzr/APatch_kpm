MYKPM_VERSION := 1.1.2

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

include ../kpm_toolchain.mk

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := xperia_ii_battery_age.o

all: xperia_ii_battery_age_$(MYKPM_VERSION).kpm

xperia_ii_battery_age_$(MYKPM_VERSION).kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c Makefile $(KPM_TOOLCHAIN_MK)
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
