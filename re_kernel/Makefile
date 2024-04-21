RK_VERSION := 1.1.0

ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

CFLAGS = -Wall -O2 -DRK_VERSION=\"$(RK_VERSION)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := re_kernel.o

all: re_kernel_$(RK_VERSION).kpm

debug: CFLAGS += -DDEBUG
debug: re_kernel_$(RK_VERSION)_debug.kpm

re_kernel_$(RK_VERSION).kpm: ${objs}
	${CC} -r -o $@ $^

re_kernel_$(RK_VERSION)_debug.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -T../demo.lds -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
