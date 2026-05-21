#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# packet_lifecycle.sh — Nanosecond Response Time & Lifecycle Profiler
# 
# This script measures two key latency metrics:
# 1. XDP Execution Time (Response time to identify & drop an attack)
# 2. Kernel Stack Traversal Time (Lifecycle of a legitimate packet)
#
# Run this on VM-B while generating traffic from VM-A and VM-C.
# ═══════════════════════════════════════════════════════════════════════

set -uo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m'

# Ensure dependencies
if ! command -v bpftrace &> /dev/null || ! command -v jq &> /dev/null; then
    echo -e "${CYAN}Installing dependencies (bpftrace, jq)...${NC}"
    sudo apt-get update && sudo apt-get install -y bpftrace jq bc &>/dev/null
fi

echo -e "${BOLD}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          Packet Lifecycle & Response Time Benchmarker              ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ───────────────────────────────────────────────────────────────────────
# Phase 1: XDP Execution Time (eBPF subsystem stats)
# ───────────────────────────────────────────────────────────────────────
echo -e "${CYAN}▶ PHASE 1: Measuring XDP Response Time (Nanosecond Precision)${NC}"
echo "  Enabling kernel BPF statistics..."
sudo sysctl -w kernel.bpf_stats_enabled=1 > /dev/null

PROG_ID=$(sudo bpftool prog list | grep -i xdp_l2 | awk '{print $1}' | tr -d ':' | head -n 1)

if [ -z "$PROG_ID" ]; then
    echo "Error: XDP program 'xdp_l2_security' not found. Is the daemon running?"
    exit 1
fi

echo "  Target XDP Program ID: $PROG_ID"
echo "  Collecting baseline stats..."

# Snapshot 1
STATS1=$(sudo bpftool prog show id $PROG_ID -p)
RUNS1=$(echo "$STATS1" | jq '.run_cnt')
TIME1=$(echo "$STATS1" | jq '.run_time_ns')

echo "  Sampling for 10 seconds. > Please run macof attacks or iperf3 now <..."
sleep 10

# Snapshot 2
STATS2=$(sudo bpftool prog show id $PROG_ID -p)
RUNS2=$(echo "$STATS2" | jq '.run_cnt')
TIME2=$(echo "$STATS2" | jq '.run_time_ns')

sudo sysctl -w kernel.bpf_stats_enabled=0 > /dev/null

DIFF_RUNS=$((RUNS2 - RUNS1))
DIFF_TIME=$((TIME2 - TIME1))

echo ""
if [ -n "$DIFF_RUNS" ] && [ "$DIFF_RUNS" -gt 0 ]; then
    AVG_NS=$((DIFF_TIME / DIFF_RUNS))
    echo -e "${GREEN}  ✔ XDP Average Execution Time: ${BOLD}${AVG_NS} nanoseconds${NC}"
    echo "    (Calculated over $DIFF_RUNS packets sampled)"
else
    echo "  No packets traversed the XDP hook during the sample."
fi
echo ""

# ───────────────────────────────────────────────────────────────────────
# Phase 2: Kernel Bridge Traversal Time (bpftrace)
# ───────────────────────────────────────────────────────────────────────
echo -e "${CYAN}▶ PHASE 2: Measuring Kernel Bridge Traversal Time${NC}"
echo "  Tracing lifecycle: netif_receive_skb -> net_dev_xmit"
echo "  (Measures how long a legitimate packet spends traversing VM-B)"
echo ""
echo "  > Please generate legitimate iperf3 traffic from VM-C to VM-D <"
echo "  > Press Ctrl+C to stop tracing and view the distribution <"
echo ""

# Create bpftrace script
cat << 'EOF' > lifecycle.bt
#!/usr/bin/bpftrace

BEGIN {
    printf("  Tracing active... (hit Ctrl+C to finish)\n");
}

// Packet enters Linux networking stack (after passing XDP)
tracepoint:net:netif_receive_skb
{
    @start[args->skbaddr] = nsecs;
}

// Packet is queued to leave physical interface
tracepoint:net:net_dev_xmit
/@start[args->skbaddr]/
{
    $latency = nsecs - @start[args->skbaddr];
    @bridge_latency_ns = hist($latency);
    @total_ns += $latency;
    @count += 1;
    delete(@start[args->skbaddr]);
}

END {
    clear(@start);
    printf("\n\n");
    printf("────────────────────────────────────────────────\n");
    if (@count > 0) {
        $avg = @total_ns / @count;
        printf("  Total Legitimate Packets Traced: %d\n", @count);
        printf("  Average Kernel Traversal Time:   %d nanoseconds (%d us)\n", $avg, $avg / 1000);
    } else {
        printf("  No legitimate packets traced.\n");
    }
    printf("────────────────────────────────────────────────\n");
    clear(@total_ns);
    clear(@count);
}
EOF

sudo bpftrace lifecycle.bt

rm lifecycle.bt
echo -e "\n${BOLD}Done. Compare the XDP nanoseconds vs Kernel nanoseconds to prove XDP efficiency!${NC}"
