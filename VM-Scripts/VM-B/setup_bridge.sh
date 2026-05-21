#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# setup_bridge.sh — Configure the Ubuntu Server VM as a Layer-2 Bridge
#
# This script sets up the Ubuntu Server VM to act as a software switch.
# ALL traffic from Attacker, Client and DHCP Server VMs must transit
# through this bridge, where the XDP program will inspect packets.
#
# Prerequisites:
#   - Ubuntu Server VM with at least 3 virtual NICs (one per connected VM)
#   - Each NIC connected to a separate Proxmox vmbr or directly to a VM
#   - bridge-utils and iproute2 installed
#
# Usage:
#   sudo ./setup_bridge.sh <iface1> <iface2> <iface3>
#
# Example:
#   sudo ./setup_bridge.sh ens1f0 ens1f1 ens2f0
#
# The script will:
#   1. Create a Linux bridge (br0)
#   2. Add all specified interfaces as bridge ports
#   3. Bring everything up for pure Layer-2 forwarding
#   4. Disable IP on the bridge ports (pure L2 mode)
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

BRIDGE_NAME="br0"
BRIDGE_IP=""   # Leave empty for pure L2 bridging, or set for management

# ── Color output ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Root check ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo)"
fi

# ── Argument validation ─────────────────────────────────────────────
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <iface1> <iface2> [iface3] ..."
    echo ""
    echo "Available interfaces:"
    ip -br link show | grep -v "lo\|br\|veth\|docker" || true
    exit 1
fi

INTERFACES=("$@")

# ── Verify interfaces exist ─────────────────────────────────────────
for iface in "${INTERFACES[@]}"; do
    if ! ip link show "$iface" &>/dev/null; then
        err "Interface '$iface' does not exist!"
    fi
    info "Found interface: $iface"
done

# ── Install dependencies ────────────────────────────────────────────
if ! command -v brctl &>/dev/null; then
    info "Installing bridge-utils..."
    apt-get update -qq && apt-get install -y -qq bridge-utils
fi

# ── Remove existing bridge if present ────────────────────────────────
if ip link show "$BRIDGE_NAME" &>/dev/null; then
    warn "Bridge $BRIDGE_NAME already exists, removing..."
    ip link set "$BRIDGE_NAME" down 2>/dev/null || true
    for iface in "${INTERFACES[@]}"; do
        brctl delif "$BRIDGE_NAME" "$iface" 2>/dev/null || true
    done
    brctl delbr "$BRIDGE_NAME" 2>/dev/null || true
    ok "Old bridge removed"
fi

# ── Create the bridge ───────────────────────────────────────────────
info "Creating bridge $BRIDGE_NAME..."
brctl addbr "$BRIDGE_NAME"
ok "Bridge $BRIDGE_NAME created"

# ── Configure bridge properties ──────────────────────────────────────
# Disable STP (not needed for our small topology)
brctl stp "$BRIDGE_NAME" off

# Set forwarding delay to 0 for immediate forwarding
brctl setfd "$BRIDGE_NAME" 0

# ── Add interfaces to the bridge ─────────────────────────────────────
for iface in "${INTERFACES[@]}"; do
    info "Adding $iface to $BRIDGE_NAME..."

    # Flush any existing IP configuration (pure L2 mode)
    ip addr flush dev "$iface" 2>/dev/null || true

    # Disable any offloading that interferes with XDP
    ethtool -K "$iface" rx off tx off sg off tso off gso off gro off lro off 2>/dev/null || true

    # Set interface to promiscuous mode (required for bridging)
    ip link set "$iface" promisc on

    # Bring interface up
    ip link set "$iface" up

    # Add to bridge
    brctl addif "$BRIDGE_NAME" "$iface"
    ok "$iface added to $BRIDGE_NAME"
done

# ── Bring bridge up ─────────────────────────────────────────────────
ip link set "$BRIDGE_NAME" up

# optional: assign IP to bridge for management access
if [[ -n "$BRIDGE_IP" ]]; then
    ip addr add "$BRIDGE_IP" dev "$BRIDGE_NAME"
    info "Management IP $BRIDGE_IP assigned to $BRIDGE_NAME"
fi

# ── Enable IP forwarding (needed for bridge) ─────────────────────────
echo 1 > /proc/sys/net/ipv4/ip_forward

# ── Disable bridge netfilter (let XDP handle everything) ─────────────
# This prevents iptables from interfering with bridged traffic
if [[ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
    echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables
    echo 0 > /proc/sys/net/bridge/bridge-nf-call-ip6tables
    echo 0 > /proc/sys/net/bridge/bridge-nf-call-arptables
    info "Bridge netfilter disabled (XDP handles security)"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Bridge Configuration Complete                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Bridge: $BRIDGE_NAME                                              ║"
echo "║  Ports:  ${INTERFACES[*]}"
echo "║  STP:    disabled                                           ║"
echo "║  Mode:   Layer-2 forwarding                                 ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  NEXT STEPS:                                                ║"
echo "║  1. Build the XDP program:                                  ║"
echo "║       make                                                  ║"
echo "║  2. Start the daemon with the bridge port interfaces:       ║"
echo "║       sudo ./build/l2_security_daemon \\                     ║"
for iface in "${INTERFACES[@]}"; do
echo "║           --iface $iface \\                                  ║"
done
echo "║           --verbose                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Show bridge status ──────────────────────────────────────────────
brctl show "$BRIDGE_NAME"
echo ""
ip addr show "$BRIDGE_NAME"
