# SPDX-License-Identifier: GPL-2.0
#
# Makefile — Build system for XDP Layer-2 Security
#
# Targets:
#   make              Build everything (BPF object, skeleton, daemon)
#   make clean        Remove build artifacts
#   make install      Copy binary to /usr/local/bin
#   make uninstall    Remove binary from /usr/local/bin
#
# Requirements:
#   - clang >= 11 (with BPF target support)
#   - libbpf-dev
#   - bpftool
#   - linux-headers (for vmlinux.h generation)
#

# ── Toolchain ────────────────────────────────────────────────────────────
CLANG       ?= clang
LLC         ?= llc
BPFTOOL     ?= bpftool
CC          ?= gcc

# ── Architecture detection ───────────────────────────────────────────────
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# ── Paths ────────────────────────────────────────────────────────────────
OUTPUT      := build
SRC_DIR     := .
INSTALL_DIR := /usr/local/bin

# ── Source files ─────────────────────────────────────────────────────────
BPF_SRC     := $(SRC_DIR)/xdp_l2_security.bpf.c
BPF_OBJ     := $(OUTPUT)/xdp_l2_security.bpf.o
BPF_SKEL    := $(OUTPUT)/xdp_l2_security.skel.h
DAEMON_SRC  := $(SRC_DIR)/l2_security_daemon.c
DAEMON_BIN  := $(OUTPUT)/l2_security_daemon
VMLINUX_H   := $(SRC_DIR)/vmlinux.h

# ── Compiler flags ───────────────────────────────────────────────────────
BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS      := -g -O2 -Wall -Wextra -I$(OUTPUT) -I$(SRC_DIR)
LDFLAGS     := -lbpf -lelf -lz

# Allow threshold overrides from command line:
#   make FLOOD_THRESHOLD=200 RATE_LIMIT=10
ifdef FLOOD_THRESHOLD
  BPF_CFLAGS += -DFLOOD_THRESHOLD=$(FLOOD_THRESHOLD)
  CFLAGS     += -DFLOOD_THRESHOLD=$(FLOOD_THRESHOLD)
endif
ifdef RATE_LIMIT
  BPF_CFLAGS += -DRATE_LIMIT=$(RATE_LIMIT)
  CFLAGS     += -DRATE_LIMIT=$(RATE_LIMIT)
endif

# ── Targets ──────────────────────────────────────────────────────────────
.PHONY: all clean install uninstall vmlinux

all: $(DAEMON_BIN)

# Generate vmlinux.h from the running kernel's BTF
$(VMLINUX_H):
	@echo "  VMLINUX  $@"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(SRC_DIR)/xdp_l2_security.h $(VMLINUX_H) | $(OUTPUT)
	@echo "  BPF      $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ) | $(OUTPUT)
	@echo "  SKEL     $@"
	$(BPFTOOL) gen skeleton $< > $@

# Compile user-space daemon
$(DAEMON_BIN): $(DAEMON_SRC) $(BPF_SKEL) $(SRC_DIR)/xdp_l2_security.h | $(OUTPUT)
	@echo "  CC       $@"
	$(CC) $(CFLAGS) -I$(OUTPUT) $< -o $@ $(LDFLAGS)

$(OUTPUT):
	@mkdir -p $(OUTPUT)

vmlinux: $(VMLINUX_H)

clean:
	@echo "  CLEAN"
	rm -rf $(OUTPUT)
	rm -f $(VMLINUX_H)

install: $(DAEMON_BIN)
	@echo "  INSTALL  $(INSTALL_DIR)/l2_security_daemon"
	install -m 0755 $(DAEMON_BIN) $(INSTALL_DIR)/l2_security_daemon

uninstall:
	@echo "  REMOVE   $(INSTALL_DIR)/l2_security_daemon"
	rm -f $(INSTALL_DIR)/l2_security_daemon

# ── Help ─────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo "XDP Layer-2 Security — Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       (default) Build BPF object + daemon"
	@echo "  clean     Remove build artifacts"
	@echo "  install   Install daemon to $(INSTALL_DIR)"
	@echo "  uninstall Remove daemon from $(INSTALL_DIR)"
	@echo "  vmlinux   Generate vmlinux.h from running kernel BTF"
	@echo ""
	@echo "Options:"
	@echo "  FLOOD_THRESHOLD=N   MAC flood detection threshold (default: 100)"
	@echo "  RATE_LIMIT=N        ARP rate limit per unknown IP (default: 5)"
	@echo ""
	@echo "Example:"
	@echo "  make FLOOD_THRESHOLD=200 RATE_LIMIT=10"
