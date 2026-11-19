# SPDX-License-Identifier: Apache-2.0
#
# Copyright © 2017-2021 WireGuard LLC. All Rights Reserved.

BUILDDIR ?= $(CURDIR)/build
DESTDIR ?= $(CURDIR)/out

NDK_GO_ARCH_MAP_x86 := 386
NDK_GO_ARCH_MAP_x86_64 := amd64
NDK_GO_ARCH_MAP_arm := arm
NDK_GO_ARCH_MAP_arm64 := arm64
NDK_GO_ARCH_MAP_mips := mipsx
NDK_GO_ARCH_MAP_mips64 := mips64x

CLANG_FLAGS := --target=$(ANDROID_LLVM_TRIPLE) --gcc-toolchain=$(ANDROID_TOOLCHAIN_ROOT) --sysroot=$(ANDROID_SYSROOT)
CLANG_LDFLAGS := -X golang.zx2c4.com/wireguard/ipc.socketDirectory=/data/data/$(ANDROID_PACKAGE_NAME)/cache/wireguard
# Go's build cache doesn't hash headers from outside the package (jni.c's netguard ones): their hash in the flags does.
export CGO_CFLAGS := $(CLANG_FLAGS) $(CFLAGS) -DNETGUARD_HEADERS_HASH=$(shell cat ../netguard/include/* | cksum | cut -d' ' -f1)
export CGO_LDFLAGS := $(CLANG_FLAGS) $(LDFLAGS) -L$(DESTDIR) -lnetguard -Wl,-soname=libwg-go.so
export CC := $(ANDROID_C_COMPILER)
export GOARCH := $(NDK_GO_ARCH_MAP_$(ANDROID_ARCH_NAME))
export GOOS := android
export CGO_ENABLED := 1

default: $(DESTDIR)/libwg-go.so

# jni.c includes netguard's headers: a change to one must rebuild the library.
$(DESTDIR)/libwg-go.so: $(wildcard *) $(wildcard ../netguard/include/*)
	 go build -tags android -ldflags="$(CLANG_LDFLAGS)" -v -trimpath -o "$@" -buildmode c-shared

.DELETE_ON_ERROR:
