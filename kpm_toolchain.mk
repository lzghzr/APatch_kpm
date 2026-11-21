# SPDX-License-Identifier: GPL-2.0-or-later
# Shared toolchain selection; module Makefiles own flags, sources and targets.
# GCC 12.2.rel1 is the default. Select NDK explicitly with TOOLCHAIN=ndk.
KPM_TOOLCHAIN_MK := $(lastword $(MAKEFILE_LIST))
TOOLCHAIN ?= gcc

OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
HOST_TAG = $(OS_NAME)-$(MACHINE)
ifeq ($(HOST_TAG), darwin-arm64)
    HOST_TAG = darwin-x86_64
endif
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(HOST_TAG)/bin
ifdef ANDROID_NDK_LATEST_HOME
    NDK_PATH ?= $(ANDROID_NDK_LATEST_HOME)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK
    NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)
endif

ifeq ($(TOOLCHAIN),gcc)
    ifdef TARGET_COMPILE
        GCC_PREFIX := $(TARGET_COMPILE)
    else ifdef AARCH64_NONE_ELF_DIR
        GCC_PREFIX := $(AARCH64_NONE_ELF_DIR)/bin/aarch64-none-elf-
    else
        GCC_ON_PATH := $(shell command -v aarch64-none-elf-gcc 2>/dev/null)
        ifeq ($(GCC_ON_PATH),)
            $(error 找不到 aarch64-none-elf GCC：未设置 TARGET_COMPILE / AARCH64_NONE_ELF_DIR，且 PATH 上没有 aarch64-none-elf-gcc。安装 Arm GNU Toolchain 12.2.rel1 的 aarch64-none-elf 发行版后取其一：① export AARCH64_NONE_ELF_DIR=<工具链根目录>；② export TARGET_COMPILE=<工具链根目录>/bin/aarch64-none-elf-；③ 把 <工具链根目录>/bin 加入 PATH。确需 NDK clang 时显式 make TOOLCHAIN=ndk)
        endif
        GCC_PREFIX := $(dir $(GCC_ON_PATH))aarch64-none-elf-
    endif
    CC := $(GCC_PREFIX)gcc
    LD := $(GCC_PREFIX)ld
    ifeq ($(shell command -v $(CC) 2>/dev/null),)
        $(error 解析出的编译器不存在：$(CC)（检查 TARGET_COMPILE / AARCH64_NONE_ELF_DIR 指向的工具链根目录是否正确）)
    endif
else ifeq ($(TOOLCHAIN),ndk)
    ifndef NDK_PATH
        $(error TOOLCHAIN=ndk 缺少 NDK 路径：设置 ANDROID_NDK 或 ANDROID_NDK_LATEST_HOME，或 make NDK_PATH=<ndk>/toolchains/llvm/prebuilt/<host-tag>/bin)
    endif
    CC := $(NDK_PATH)/aarch64-linux-android31-clang
    LD := $(NDK_PATH)/ld.lld
    ifeq ($(wildcard $(CC)),)
        $(error TOOLCHAIN=ndk 找不到 clang：$(CC)（NDK 路径不对或未解包）)
    endif
else
    $(error 未知 TOOLCHAIN=$(TOOLCHAIN)：只支持 gcc（默认）与 ndk)
endif
