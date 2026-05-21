#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# install_deps.sh — Install All Dependencies on the Ubuntu Server VM
#
# Run this FIRST on the Ubuntu Server VM (switch) before building.
#
# Usage: sudo ./install_deps.sh
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Installing Dependencies for XDP Layer-2 Security System   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Update package lists ────────────────────────────────────────────
info "Updating package lists..."
apt-get update -qq
ok "Package lists updated"

# ── Install build essentials ────────────────────────────────────────
info "Installing build tools..."
apt-get install -y -qq \
    build-essential \
    clang \
    llvm \
    gcc \
    make \
    pkg-config
ok "Build tools installed"

# ── Install libbpf and BPF tools ────────────────────────────────────
info "Installing libbpf and BPF tools..."
apt-get install -y -qq \
    libbpf-dev \
    linux-tools-common \
    linux-tools-$(uname -r) \
    linux-headers-$(uname -r) \
    libelf-dev \
    zlib1g-dev
ok "libbpf and BPF tools installed"

# ── Install bpftool ─────────────────────────────────────────────────
info "Checking bpftool..."
if command -v bpftool &>/dev/null; then
    BPFTOOL_VER=$(bpftool version 2>/dev/null | head -1)
    ok "bpftool already installed: $BPFTOOL_VER"
else
    # bpftool comes with linux-tools
    if [[ -f /usr/lib/linux-tools/$(uname -r)/bpftool ]]; then
        ln -sf /usr/lib/linux-tools/$(uname -r)/bpftool /usr/local/bin/bpftool
        ok "bpftool symlinked"
    else
        warn "bpftool not found. Try: apt install linux-tools-$(uname -r)"
    fi
fi

# ── Install bridge utilities ────────────────────────────────────────
info "Installing bridge utilities..."
apt-get install -y -qq \
    bridge-utils \
    ethtool \
    net-tools \
    iproute2 \
    arping \
    tcpdump
ok "Bridge and network utilities installed"

# ── Verify kernel BTF support ───────────────────────────────────────
info "Checking kernel BTF support..."
if [[ -f /sys/kernel/btf/vmlinux ]]; then
    ok "Kernel BTF is available at /sys/kernel/btf/vmlinux"
else
    echo -e "${RED}[WARN]${NC} Kernel BTF not found at /sys/kernel/btf/vmlinux"
    echo "  Your kernel may not have CONFIG_DEBUG_INFO_BTF=y"
    echo "  This is required for CO-RE (Compile Once, Run Everywhere)"
    echo "  You may need to rebuild your kernel or use a newer version."
fi

# ── Check VirtIO driver for native XDP support ──────────────────────
info "Checking VirtIO (virtio_net) driver for native XDP..."
if lsmod | grep -q virtio_net; then
    ok "virtio_net driver is loaded (supports native XDP)"

    # List VirtIO network interfaces
    VIRTIO_IFACES=$(ls /sys/class/net/ | while read iface; do
        driver=$(readlink /sys/class/net/$iface/device/driver 2>/dev/null | xargs basename 2>/dev/null)
        if [[ "$driver" == "virtio_net" ]]; then
            echo "$iface"
        fi
    done)

    if [[ -n "$VIRTIO_IFACES" ]]; then
        ok "VirtIO interfaces found: $VIRTIO_IFACES"
        echo "  These support native XDP mode!"
    fi
else
    echo -e "${CYAN}[INFO]${NC} virtio_net driver not loaded"
    echo "  Make sure your Proxmox VM uses VirtIO NICs (not E1000/rtl8139)"
fi

# ── Verify clang BPF target ────────────────────────────────────────
info "Checking clang BPF target..."
if clang --print-targets 2>/dev/null | grep -q bpf; then
    ok "clang supports BPF target"
else
    err "clang does not support BPF target. Install clang >= 11"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              All Dependencies Installed                     ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Next steps:                                                ║"
echo "║  1. Generate vmlinux.h:  make vmlinux                      ║"
echo "║  2. Build everything:    make                               ║"
echo "║  3. Set up the bridge:   sudo ./setup_bridge.sh <ifaces>   ║"
echo "║  4. Run the daemon:      sudo ./build/l2_security_daemon \\ ║"
echo "║                            --iface <if1> --iface <if2>     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Show system info
echo "System Info:"
echo "  Kernel:  $(uname -r)"
echo "  Arch:    $(uname -m)"
echo "  clang:   $(clang --version 2>/dev/null | head -1)"
echo "  bpftool: $(bpftool version 2>/dev/null | head -1 || echo 'not found')"
echo ""
