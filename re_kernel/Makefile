MYKPM_NAME := re_kernel
MYKPM_VERSION := 1.3.6.3

ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

CFLAGS = -Wall -O2 -DMYKPM_NAME=\"$(MYKPM_NAME)\" -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := $(MYKPM_NAME).o

all: $(MYKPM_NAME)_$(MYKPM_VERSION).kpm

debug: CFLAGS += -DDEBUG
debug: MYKPM_VER := _d
debug: $(MYKPM_NAME)_$(MYKPM_VERSION)_debug.kpm

quiet: CFLAGS += -DQUIET
quiet: MYKPM_VER := _q
quiet: $(MYKPM_NAME)_$(MYKPM_VERSION)_quiet.kpm

$(MYKPM_NAME)_$(MYKPM_VERSION).kpm: ${objs}
	${CC} -r -o $@ $^

$(MYKPM_NAME)_$(MYKPM_VERSION)_debug.kpm: ${objs}
	${CC} -r -o $@ $^

$(MYKPM_NAME)_$(MYKPM_VERSION)_quiet.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -T../demo.lds -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
