MYKPM_VERSION := 2.0.2

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

include ../kpm_toolchain.mk

CFLAGS = -Wall -O2 -mgeneral-regs-only -ffixed-x18 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := hosts_redirect.o

all: hosts_redirect_$(MYKPM_VERSION).kpm

hosts_redirect_$(MYKPM_VERSION).kpm: ${objs}
	${CC} -r -o $@ $^

hosts_redirect.o: hr_utils.h ../kpm_utils.h

%.o: %.c Makefile $(KPM_TOOLCHAIN_MK)
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
