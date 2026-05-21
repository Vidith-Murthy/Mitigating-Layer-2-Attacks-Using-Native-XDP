#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# run_latency_bench.sh — End-to-End Latency Benchmarking Script
#
# Runs on VM-B (the switch running XDP).
# Builds the profiler, attaches it to a bridge interface, waits for
# attack traffic from VM-A, collects per-packet timing data, and
# produces a summary report.
#
# Usage:
#   sudo ./run_latency_bench.sh <interface> [duration_secs]
#
# Example:
#   sudo ./run_latency_bench.sh ens19 30
#
# Prerequisites:
#   - make, clang, bpftool, libbpf-dev must be installed
#   - Run attack traffic from VM-A during the collection window
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

IFACE="${1:?Usage: $0 <interface> [duration_secs]}"
DURATION="${2:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CSV_FILE="latency_${IFACE}_${TIMESTAMP}.csv"
REPORT_FILE="latency_report_${IFACE}_${TIMESTAMP}.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[LATENCY]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       XDP Latency Profiling — Packet Lifecycle Timing      ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Interface: ${IFACE}                                             ║${NC}"
echo -e "${BOLD}║  Duration:  ${DURATION}s                                             ║${NC}"
echo -e "${BOLD}║  CSV:       ${CSV_FILE}${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Build the latency profiler ──────────────────────────────
info "Building latency profiler..."
if make latency 2>&1; then
    ok "Build successful"
else
    fail "Build failed. Ensure clang, bpftool, and libbpf-dev are installed."
fi

# ── Step 2: Check that interface exists ─────────────────────────────
if ! ip link show "$IFACE" &>/dev/null; then
    fail "Interface $IFACE not found. Available interfaces:"
    ip -br link show
fi

# ── Step 3: Detach any existing XDP program ─────────────────────────
info "Detaching any existing XDP program from $IFACE..."
ip link set dev "$IFACE" xdp off 2>/dev/null || true

# ── Step 4: Run the collector ───────────────────────────────────────
info "Starting latency collection for ${DURATION}s..."
info ">>> Send attack traffic from VM-A now! <<<"
echo ""

./build/latency_collector --iface "$IFACE" --duration "$DURATION" --csv "$CSV_FILE" \
    2>&1 | tee "$REPORT_FILE"

# ── Step 5: Post-process CSV with awk ───────────────────────────────
if [ ! -f "$CSV_FILE" ] || [ ! -s "$CSV_FILE" ]; then
    warn "No data collected. Ensure attack traffic was sent during the window."
    exit 1
fi

SAMPLE_COUNT=$(tail -n +2 "$CSV_FILE" | wc -l)
ok "Collected $SAMPLE_COUNT samples"

echo ""
echo -e "${BOLD}── Per-Verdict Breakdown (from CSV) ──${NC}"
echo ""

# Use awk to compute per-verdict stats from CSV
tail -n +2 "$CSV_FILE" | awk -F',' '
{
    verdict = $7
    total   = $5
    parse   = $2
    phase1  = $3
    phase2  = $4

    count[verdict]++
    sum_total[verdict] += total
    sum_parse[verdict] += parse
    sum_phase1[verdict] += phase1
    sum_phase2[verdict] += phase2

    if (!(verdict in min_total) || total < min_total[verdict])
        min_total[verdict] = total
    if (total > max_total[verdict])
        max_total[verdict] = total
}
END {
    printf "  %-18s %8s %10s %10s %10s %10s %10s\n", \
        "Verdict", "Count", "Avg(ns)", "Min(ns)", "Max(ns)", "Phase1", "Phase2"
    printf "  %-18s %8s %10s %10s %10s %10s %10s\n", \
        "──────────────────", "────────", "──────────", "──────────", \
        "──────────", "──────────", "──────────"

    for (v in count) {
        avg = sum_total[v] / count[v]
        avg1 = sum_phase1[v] / count[v]
        avg2 = sum_phase2[v] / count[v]
        printf "  %-18s %8d %10.0f %10d %10d %10.0f %10.0f\n", \
            v, count[v], avg, min_total[v], max_total[v], avg1, avg2
    }
}
'

echo ""

# Per-protocol breakdown
echo -e "${BOLD}── Per-Protocol Breakdown ──${NC}"
echo ""
tail -n +2 "$CSV_FILE" | awk -F',' '
{
    proto = $8
    total = $5
    count[proto]++
    sum[proto] += total
    if (!(proto in minv) || total < minv[proto]) minv[proto] = total
    if (total > maxv[proto]) maxv[proto] = total
}
END {
    printf "  %-10s %8s %10s %10s %10s\n", "Protocol", "Count", "Avg(ns)", "Min(ns)", "Max(ns)"
    printf "  %-10s %8s %10s %10s %10s\n", "──────────", "────────", "──────────", "──────────", "──────────"
    for (p in count) {
        printf "  %-10s %8d %10.0f %10d %10d\n", p, count[p], sum[p]/count[p], minv[p], maxv[p]
    }
}
'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Results saved:                                            ║${NC}"
echo -e "${BOLD}║    CSV:    ${CSV_FILE}${NC}"
echo -e "${BOLD}║    Report: ${REPORT_FILE}${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
