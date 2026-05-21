#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# benchmark.sh — XDP Performance Benchmarking Suite
#
# Measures throughput, PPS, and latency through the XDP-protected bridge.
# Run this on VM-C (client) with VM-D or VM-A as the iperf3 server.
#
# Usage:
#   ./benchmark.sh <server_ip> <interface> <label>
#
# Example:
#   ./benchmark.sh 192.168.100.1 eth0 "With XDP"
#   # Then disable XDP and run again:
#   ./benchmark.sh 192.168.100.1 eth0 "Without XDP"
#
# Prerequisites:
#   sudo apt install iperf3 -y    (on BOTH VMs)
#   On server VM: iperf3 -s       (start iperf3 server)
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

SERVER_IP="${1:?Usage: $0 <server_ip> <interface> <label>}"
IFACE="${2:-eth0}"
LABEL="${3:-Test}"
DURATION=10
RESULTS_FILE="benchmark_results_$(date +%Y%m%d_%H%M%S).txt"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info() { echo -e "${CYAN}[BENCH]${NC} $*"; }
header() { echo -e "${BOLD}$*${NC}"; }

# ── Check dependencies ──────────────────────────────────────────────
if ! command -v iperf3 &>/dev/null; then
    echo "Installing iperf3..."
    sudo apt install -y iperf3
fi

echo ""
header "╔══════════════════════════════════════════════════════════════╗"
header "║           XDP Performance Benchmark                        ║"
header "║           Label: $LABEL"
header "║           Server: $SERVER_IP                               ║"
header "║           Duration: ${DURATION}s per test                          ║"
header "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Write header to results file ────────────────────────────────────
{
    echo "═══════════════════════════════════════════════════════"
    echo "  XDP Benchmark Results — $LABEL"
    echo "  Date: $(date)"
    echo "  Server: $SERVER_IP | Interface: $IFACE"
    echo "═══════════════════════════════════════════════════════"
    echo ""
} > "$RESULTS_FILE"

# ════════════════════════════════════════════════════════════════════
# TEST 1: TCP Throughput (Bandwidth)
# ════════════════════════════════════════════════════════════════════
info "Test 1/6: TCP Throughput (single stream, ${DURATION}s)..."
echo "── TCP Throughput (Single Stream) ──" >> "$RESULTS_FILE"
iperf3 -c "$SERVER_IP" -t "$DURATION" -f m 2>&1 | tee -a "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
sleep 2

# ════════════════════════════════════════════════════════════════════
# TEST 2: TCP Throughput (parallel streams)
# ════════════════════════════════════════════════════════════════════
info "Test 2/6: TCP Throughput (4 parallel streams, ${DURATION}s)..."
echo "── TCP Throughput (4 Parallel Streams) ──" >> "$RESULTS_FILE"
iperf3 -c "$SERVER_IP" -t "$DURATION" -P 4 -f m 2>&1 | tee -a "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
sleep 2

# ════════════════════════════════════════════════════════════════════
# TEST 3: UDP Throughput (max bandwidth test)
# ════════════════════════════════════════════════════════════════════
info "Test 3/6: UDP Throughput (target 10Gbps, ${DURATION}s)..."
echo "── UDP Throughput (Target 10 Gbps) ──" >> "$RESULTS_FILE"
iperf3 -c "$SERVER_IP" -t "$DURATION" -u -b 10G -f m 2>&1 | tee -a "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
sleep 2

# ════════════════════════════════════════════════════════════════════
# TEST 4: UDP PPS (small packets = maximum packets per second)
# ════════════════════════════════════════════════════════════════════
info "Test 4/6: UDP PPS (64-byte packets, ${DURATION}s)..."
echo "── UDP Packets Per Second (64-byte) ──" >> "$RESULTS_FILE"
iperf3 -c "$SERVER_IP" -t "$DURATION" -u -b 1G -l 64 -f m 2>&1 | tee -a "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
sleep 2

# ════════════════════════════════════════════════════════════════════
# TEST 5: Latency (Ping RTT)
# ════════════════════════════════════════════════════════════════════
info "Test 5/6: Latency (100 ICMP pings)..."
echo "── Latency (ICMP Ping) ──" >> "$RESULTS_FILE"
ping -c 100 -i 0.05 "$SERVER_IP" 2>&1 | tail -5 | tee -a "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
sleep 1

# ════════════════════════════════════════════════════════════════════
# TEST 6: Latency under load
# ════════════════════════════════════════════════════════════════════
info "Test 6/6: Latency under load (ping during iperf3)..."
echo "── Latency Under Load ──" >> "$RESULTS_FILE"

# Start iperf3 in background
iperf3 -c "$SERVER_IP" -t 15 -P 4 &>/dev/null &
IPERF_PID=$!

sleep 2  # Let traffic ramp up

# Measure ping during load
ping -c 50 -i 0.1 "$SERVER_IP" 2>&1 | tail -5 | tee -a "$RESULTS_FILE"

# Wait for iperf to finish
wait $IPERF_PID 2>/dev/null || true
echo "" >> "$RESULTS_FILE"

# ════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════
echo ""
header "╔══════════════════════════════════════════════════════════════╗"
header "║           Benchmark Complete — $LABEL"
header "╠══════════════════════════════════════════════════════════════╣"
header "║  Results saved to: $RESULTS_FILE"
header "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Results file: $RESULTS_FILE${NC}"
echo ""
echo "To compare, run this script twice:"
echo "  1. With XDP running on VM-B"
echo "  2. Without XDP (stop the daemon, detach XDP)"
echo "Then diff the results files."
