#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# benchmark_latency.sh — Nanosecond-Precision Packet Lifecycle Profiler
#
# Measures the exact time an eBPF/XDP program takes to recognise and act
# on attack packets, with nanosecond accuracy across every decision stage
# inside VM-B.
#
# Architecture:
#   VM-A (attacker)  ──▶  VM-B (this script + instrumented XDP)
#
# This script:
#   1. Builds and loads the instrumented XDP probe (xdp_latency_probe.bpf.c)
#   2. Optionally injects its own test packets (or you run attacks from VM-A)
#   3. Reads the latency ring buffer via a C helper program
#   4. Produces a full statistical report of packet processing time
#      broken down by pipeline stage and detection path
#
# The packet lifecycle measured inside VM-B:
#
#   ┌─────────────────────────────────────────────────────────────┐
#   │              Packet Lifecycle in XDP (VM-B)                 │
#   ├──────────┬──────────────────────────────────────────────────┤
#   │  Stage   │  Description                                    │
#   ├──────────┼──────────────────────────────────────────────────┤
#   │  T0      │  XDP hook fires (packet arrives from NIC)       │
#   │  T1      │  Ethernet header parsed                         │
#   │  T2      │  MAC flood check complete (Phase 1)             │
#   │  T3      │  Protocol identified (ARP/IPv4/other)           │
#   │  T4      │  Validation complete (binding/GARP/rate check)  │
#   │  T5      │  Final verdict (XDP_PASS or XDP_DROP)           │
#   └──────────┴──────────────────────────────────────────────────┘
#
# Run on VM-B (the Proxmox Ubuntu Server acting as the XDP switch).
#
# Usage:
#   sudo ./benchmark_latency.sh <interface> [options]
#
# Options:
#   --iface <name>           Interface to attach XDP probe (required)
#   --duration <seconds>     How long to collect data (default: 30)
#   --sample-rate <N>        Record 1-in-N packets (default: 1 = all)
#   --inject                 Also inject test packets locally
#   --static-binding <IP> <MAC>  Pre-load bindings (repeatable)
#   --output <file>          Output report file (auto-generated if omitted)
#   --help                   Show this help
#
# Example:
#   # Full capture for 30 seconds while VM-A attacks:
#   sudo ./benchmark_latency.sh --iface ens19 --duration 30 \
#       --static-binding 192.168.100.1 bc:24:11:de:d5:55 \
#       --static-binding 192.168.100.100 bc:24:11:b5:b1:9f
#
#   # With 1% sampling for high-rate attacks:
#   sudo ./benchmark_latency.sh --iface ens19 --duration 60 --sample-rate 100
#
# Prerequisites:
#   - clang, bpftool, libbpf-dev, linux-headers (same as main build)
#   - Python 3 with numpy (for statistical analysis)
# ═══════════════════════════════════════════════════════════════════════════

set -uo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────
IFACE=""
DURATION=30
SAMPLE_RATE=1
INJECT=0
OUTPUT=""
STATIC_BINDINGS=()

# ── Colors ───────────────────────────────────────────────────────────────
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
NC='\033[0m'

info()  { echo -e "${CYAN}[LATENCY]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
stage() { echo -e "${MAGENTA}[STAGE]${NC} $*"; }

# ── Parse Arguments ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)        IFACE="$2";          shift 2 ;;
        --duration)     DURATION="$2";       shift 2 ;;
        --sample-rate)  SAMPLE_RATE="$2";    shift 2 ;;
        --inject)       INJECT=1;            shift   ;;
        --output)       OUTPUT="$2";         shift 2 ;;
        --static-binding)
            STATIC_BINDINGS+=("$2" "$3"); shift 3 ;;
        --help)
            head -60 "$0" | tail -55
            exit 0
            ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$IFACE" ]]; then
    err "No interface specified. Use --iface <name>"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    err "Must run as root (sudo)"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT" ]] && OUTPUT="latency_report_${TIMESTAMP}.txt"
RAW_DATA="latency_raw_${TIMESTAMP}.csv"
BUILD_DIR="./build"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    XDP Packet Lifecycle Latency Profiler — Nanosecond Precision     ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Interface:     ${IFACE}$(printf '%*s' $((51 - ${#IFACE})) '')║${NC}"
echo -e "${BOLD}║  Duration:      ${DURATION}s$(printf '%*s' $((50 - ${#DURATION})) '')║${NC}"
echo -e "${BOLD}║  Sample Rate:   1-in-${SAMPLE_RATE}$(printf '%*s' $((47 - ${#SAMPLE_RATE})) '')║${NC}"
echo -e "${BOLD}║  Output:        ${OUTPUT}$(printf '%*s' $((51 - ${#OUTPUT})) '')║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 1: Build the Instrumented Probe
# ═══════════════════════════════════════════════════════════════════════════
stage "Phase 1: Building instrumented XDP latency probe..."

mkdir -p "$BUILD_DIR"

# Generate vmlinux.h if not present
if [[ ! -f vmlinux.h ]]; then
    info "Generating vmlinux.h from running kernel BTF..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
fi

ARCH=$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Compile the instrumented BPF program
info "Compiling xdp_latency_probe.bpf.c..."
clang -g -O2 -target bpf -D__TARGET_ARCH_${ARCH} \
    -c xdp_latency_probe.bpf.c \
    -o "${BUILD_DIR}/xdp_latency_probe.bpf.o"

if [[ $? -ne 0 ]]; then
    err "Failed to compile BPF program"
    exit 1
fi
info "BPF object compiled: ${BUILD_DIR}/xdp_latency_probe.bpf.o"

# Generate skeleton
info "Generating BPF skeleton..."
bpftool gen skeleton "${BUILD_DIR}/xdp_latency_probe.bpf.o" \
    > "${BUILD_DIR}/xdp_latency_probe.skel.h"

info "Skeleton generated: ${BUILD_DIR}/xdp_latency_probe.skel.h"

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 2: Build the User-Space Latency Collector
# ═══════════════════════════════════════════════════════════════════════════
stage "Phase 2: Building user-space latency collector..."

cat > "${BUILD_DIR}/latency_collector.c" << 'COLLECTOR_EOF'
// latency_collector.c — Reads latency events from the instrumented XDP probe
// and writes CSV output for statistical analysis.
//
// Usage: ./latency_collector <iface> <duration_s> <sample_rate> <output.csv> \
//        [--static-binding <IP> <MAC>] ...

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_l2_security.h"
#include "xdp_latency_probe.skel.h"

static volatile int running = 1;
static FILE *csv_fp = NULL;
static unsigned long long total_events = 0;
static unsigned long long dropped_events = 0;

/* Path names for human-readable output */
static const char *path_names[] = {
    [0] = "PASS_NON_ARP",
    [1] = "PASS_ARP_VALID",
    [2] = "PASS_ARP_RATELIM",
    [3] = "PASS_DHCP",
    [4] = "DROP_ARP_SPOOF",
    [5] = "DROP_GARP",
    [6] = "DROP_MAC_FLOOD",
    [7] = "DROP_RATE_LIMIT",
    [8] = "PASS_PARSE_FAIL",
};

struct latency_event {
    __u64 t_entry;
    __u64 t_eth_parsed;
    __u64 t_mac_flood_done;
    __u64 t_proto_demux;
    __u64 t_validation;
    __u64 t_verdict;
    __u32 verdict;
    __u32 path;
    __u16 eth_type;
    __u16 arp_op;
    __u32 ifindex;
} __attribute__((packed));

static void sig_handler(int sig) { (void)sig; running = 0; }

static int parse_mac(const char *str, unsigned char *mac)
{
    int vals[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2],
               &vals[3], &vals[4], &vals[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (unsigned char)vals[i];
    return 0;
}

static int handle_latency_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct latency_event))
        return 0;

    struct latency_event *evt = data;
    total_events++;

    /* Compute per-stage deltas (nanoseconds) */
    __u64 d_eth_parse   = evt->t_eth_parsed    - evt->t_entry;
    __u64 d_mac_flood   = evt->t_mac_flood_done - evt->t_eth_parsed;
    __u64 d_proto_demux = evt->t_proto_demux    - evt->t_mac_flood_done;
    __u64 d_validation  = evt->t_validation     - evt->t_proto_demux;
    __u64 d_verdict     = evt->t_verdict        - evt->t_validation;
    __u64 d_total       = evt->t_verdict        - evt->t_entry;

    const char *path = (evt->path <= 8) ? path_names[evt->path] : "UNKNOWN";
    const char *verdict_str = (evt->verdict == 1) ? "DROP" : "PASS";

    if (csv_fp) {
        fprintf(csv_fp,
            "%llu,%llu,%llu,%llu,%llu,%llu,"
            "%llu,%llu,%llu,%llu,%llu,%llu,"
            "%s,%s,0x%04x,%u,%u\n",
            /* Absolute timestamps */
            (unsigned long long)evt->t_entry,
            (unsigned long long)evt->t_eth_parsed,
            (unsigned long long)evt->t_mac_flood_done,
            (unsigned long long)evt->t_proto_demux,
            (unsigned long long)evt->t_validation,
            (unsigned long long)evt->t_verdict,
            /* Deltas */
            (unsigned long long)d_eth_parse,
            (unsigned long long)d_mac_flood,
            (unsigned long long)d_proto_demux,
            (unsigned long long)d_validation,
            (unsigned long long)d_verdict,
            (unsigned long long)d_total,
            /* Metadata */
            verdict_str, path,
            evt->eth_type, evt->arp_op, evt->ifindex
        );

        /* Flush periodically for real-time viewing */
        if (total_events % 10000 == 0)
            fflush(csv_fp);
    }

    /* Progress indicator every 100k events */
    if (total_events % 100000 == 0) {
        fprintf(stderr, "\r  [COLLECTOR] %llu events captured...",
                (unsigned long long)total_events);
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <iface> <duration_s> <sample_rate> <output.csv>"
                        " [--static-binding <IP> <MAC>] ...\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    int duration      = atoi(argv[2]);
    __u64 sample_rate = (__u64)atoll(argv[3]);
    const char *csv   = argv[4];

    /* Collect static bindings from remaining args */
    struct { struct in_addr ip; unsigned char mac[6]; } bindings[64];
    int n_bindings = 0;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--static-binding") == 0 && i + 2 < argc) {
            struct in_addr addr;
            if (inet_pton(AF_INET, argv[i+1], &addr) == 1) {
                bindings[n_bindings].ip = addr;
                if (parse_mac(argv[i+2], bindings[n_bindings].mac) == 0) {
                    n_bindings++;
                }
            }
            i += 2;
        }
    }

    /* Open BPF skeleton */
    struct xdp_latency_probe_bpf *skel = xdp_latency_probe_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton: %s\n", strerror(errno));
        return 1;
    }

    int err = xdp_latency_probe_bpf__load(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF: %s\n", strerror(-err));
        xdp_latency_probe_bpf__destroy(skel);
        return 1;
    }

    /* Get map FDs */
    int binding_fd = bpf_map__fd(skel->maps.binding_map);
    int ctrl_fd    = bpf_map__fd(skel->maps.latency_ctrl);

    /* Set sampling rate */
    __u32 key_rate = 0;
    bpf_map_update_elem(ctrl_fd, &key_rate, &sample_rate, BPF_ANY);
    fprintf(stderr, "  Sampling rate set: 1-in-%llu\n",
            (unsigned long long)sample_rate);

    /* Reset packet counter */
    __u32 key_cnt = 1;
    __u64 zero_val = 0;
    bpf_map_update_elem(ctrl_fd, &key_cnt, &zero_val, BPF_ANY);

    /* Load static bindings */
    for (int i = 0; i < n_bindings; i++) {
        struct mac_addr mac;
        memcpy(mac.addr, bindings[i].mac, 6);
        err = bpf_map_update_elem(binding_fd, &bindings[i].ip.s_addr, &mac, BPF_ANY);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &bindings[i].ip, ip_str, sizeof(ip_str));
        if (err == 0) {
            fprintf(stderr, "  ✓ Static binding: %s → %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ip_str, mac.addr[0], mac.addr[1], mac.addr[2],
                    mac.addr[3], mac.addr[4], mac.addr[5]);
        }
    }

    /* Attach XDP to interface */
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: Interface '%s' not found\n", iface);
        goto cleanup;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_latency_probe);
    LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);

    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, &attach_opts);
    if (err) {
        fprintf(stderr, "  Native XDP failed on %s, trying SKB mode...\n", iface);
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, &attach_opts);
        if (err) {
            fprintf(stderr, "ERROR: Failed to attach XDP to %s: %s\n",
                    iface, strerror(-err));
            goto cleanup;
        }
        fprintf(stderr, "  ✓ XDP attached to %s (SKB mode)\n", iface);
    } else {
        fprintf(stderr, "  ✓ XDP attached to %s (native/driver mode)\n", iface);
    }

    /* Open CSV output */
    csv_fp = fopen(csv, "w");
    if (!csv_fp) {
        fprintf(stderr, "ERROR: Cannot open %s: %s\n", csv, strerror(errno));
        goto detach;
    }
    fprintf(csv_fp,
        "t_entry_ns,t_eth_parsed_ns,t_mac_flood_done_ns,t_proto_demux_ns,"
        "t_validation_ns,t_verdict_ns,"
        "d_eth_parse_ns,d_mac_flood_ns,d_proto_demux_ns,d_validation_ns,"
        "d_verdict_ns,d_total_ns,"
        "verdict,path,eth_type,arp_op,ifindex\n");

    /* Set up latency ring buffer */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.latency_rb), handle_latency_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: Failed to create ring buffer\n");
        goto detach;
    }

    /* Also set up the DHCP events ring buffer (to avoid clogging) */
    /* We just drain it silently */
    struct ring_buffer *rb_dhcp = ring_buffer__new(
        bpf_map__fd(skel->maps.events_rb),
        NULL, /* no callback — just drain */
        NULL, NULL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    fprintf(stderr, "\n");
    fprintf(stderr, "╔══════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║  Latency Collector Active — %ds capture      ║\n", duration);
    fprintf(stderr, "║  Waiting for packets on %s...                ║\n", iface);
    fprintf(stderr, "║  Press Ctrl+C to stop early                    ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════╝\n\n");

    time_t start_time = time(NULL);

    while (running) {
        err = ring_buffer__poll(rb, 50 /* ms */);
        if (err < 0 && err != -EINTR)
            break;

        /* Also drain DHCP ring buffer */
        if (rb_dhcp)
            ring_buffer__poll(rb_dhcp, 0);

        /* Check duration */
        if (duration > 0 && (time(NULL) - start_time) >= duration) {
            fprintf(stderr, "\n  Duration reached (%ds). Stopping...\n", duration);
            break;
        }
    }

    fprintf(stderr, "\n\n  Total events captured: %llu\n",
            (unsigned long long)total_events);

    /* Print final stats */
    int stats_fd = bpf_map__fd(skel->maps.stats_map);
    int nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus > 0) {
        const char *stat_labels[] = {
            "Total Packets", "Packets Passed", "ARP Spoof Drops",
            "Gratuitous ARP Drops", "MAC Flood Drops", "Rate Limit Drops",
            "DHCP Mirrored", "ARP Passed"
        };
        fprintf(stderr, "\n  ── XDP Statistics ──\n");
        for (__u32 i = 0; i < STATS_MAX; i++) {
            __u64 values[nr_cpus];
            memset(values, 0, sizeof(values));
            if (bpf_map_lookup_elem(stats_fd, &i, values) != 0) continue;
            __u64 total = 0;
            for (int cpu = 0; cpu < nr_cpus; cpu++) total += values[cpu];
            fprintf(stderr, "  %-28s %12llu\n", stat_labels[i],
                    (unsigned long long)total);
        }
    }

    /* Cleanup */
    if (csv_fp) fclose(csv_fp);
    if (rb) ring_buffer__free(rb);
    if (rb_dhcp) ring_buffer__free(rb_dhcp);

detach:
    {
        LIBBPF_OPTS(bpf_xdp_attach_opts, detach_opts);
        bpf_xdp_detach(ifindex, 0, &detach_opts);
        fprintf(stderr, "  ✓ XDP detached from %s\n", iface);
    }

cleanup:
    xdp_latency_probe_bpf__destroy(skel);
    return 0;
}
COLLECTOR_EOF

info "Compiling latency collector..."
gcc -g -O2 -Wall -Wextra -I"${BUILD_DIR}" -I. \
    "${BUILD_DIR}/latency_collector.c" \
    -o "${BUILD_DIR}/latency_collector" \
    -lbpf -lelf -lz

if [[ $? -ne 0 ]]; then
    err "Failed to compile latency collector"
    exit 1
fi
info "Collector built: ${BUILD_DIR}/latency_collector"

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 3: Run the Collector
# ═══════════════════════════════════════════════════════════════════════════
stage "Phase 3: Running latency data collection for ${DURATION}s..."

# Build arguments for static bindings
BINDING_ARGS=""
i=0
while [[ $i -lt ${#STATIC_BINDINGS[@]} ]]; do
    BINDING_ARGS="${BINDING_ARGS} --static-binding ${STATIC_BINDINGS[$i]} ${STATIC_BINDINGS[$((i+1))]}"
    i=$((i + 2))
done

"${BUILD_DIR}/latency_collector" \
    "$IFACE" "$DURATION" "$SAMPLE_RATE" "$RAW_DATA" \
    $BINDING_ARGS

info "Raw data written to: $RAW_DATA"

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 4: Statistical Analysis (Python)
# ═══════════════════════════════════════════════════════════════════════════
stage "Phase 4: Generating statistical analysis report..."

python3 << ANALYSIS_EOF
#!/usr/bin/env python3
"""
Nanosecond-precision packet lifecycle analysis for XDP latency probe data.

Reads the CSV produced by latency_collector and generates:
  - Per-stage timing distributions (min, max, mean, median, P50/P95/P99)
  - Breakdown by detection path (spoof vs flood vs garp vs pass)
  - Attack recognition time (T0 → verdict) for malicious packets
  - Histogram data for each stage
  - Time-series analysis of processing time evolution
"""
import csv
import sys
import os
from collections import defaultdict
import math

CSV_FILE = "${RAW_DATA}"
REPORT_FILE = "${OUTPUT}"

# ── Read CSV data ────────────────────────────────────────────────────────
print(f"  Reading {CSV_FILE}...")

rows = []
try:
    with open(CSV_FILE, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
except Exception as e:
    print(f"  ERROR: Cannot read {CSV_FILE}: {e}")
    sys.exit(1)

if not rows:
    print("  WARNING: No events captured. Is the XDP probe attached and receiving traffic?")
    with open(REPORT_FILE, 'w') as f:
        f.write("No events captured. Ensure XDP probe was attached and traffic was flowing.\n")
    sys.exit(0)

print(f"  Loaded {len(rows)} events.")

# ── Parse into numeric arrays ────────────────────────────────────────────
stage_names = [
    ('d_eth_parse_ns',   'Eth Parse',        'T0→T1: Ethernet Header Parsing'),
    ('d_mac_flood_ns',   'MAC Flood Check',   'T1→T2: Phase 1 — MAC Flood Detection'),
    ('d_proto_demux_ns', 'Proto Demux',       'T2→T3: Protocol Demultiplexing'),
    ('d_validation_ns',  'Validation',        'T3→T4: Security Validation Logic'),
    ('d_verdict_ns',     'Verdict',           'T4→T5: Final Verdict Rendering'),
    ('d_total_ns',       'TOTAL',             'T0→T5: Complete XDP Processing Time'),
]

path_labels = {
    'PASS_NON_ARP':     'PASS (Non-ARP/IPv4)',
    'PASS_ARP_VALID':   'PASS (ARP Valid Binding)',
    'PASS_ARP_RATELIM': 'PASS (ARP Rate-Limited)',
    'PASS_DHCP':        'PASS (DHCP Mirrored)',
    'DROP_ARP_SPOOF':   'DROP (ARP Spoof Detected)',
    'DROP_GARP':        'DROP (Gratuitous ARP)',
    'DROP_MAC_FLOOD':   'DROP (MAC Flood)',
    'DROP_RATE_LIMIT':  'DROP (Rate Limit)',
    'PASS_PARSE_FAIL':  'PASS (Parse Failed)',
}

# Group rows by path
by_path = defaultdict(list)
all_data = defaultdict(list)

for row in rows:
    path = row.get('path', 'UNKNOWN')
    by_path[path].append(row)
    for col, _, _ in stage_names:
        try:
            val = int(row[col])
            all_data[col].append(val)
        except (ValueError, KeyError):
            pass

# ── Statistics helpers ───────────────────────────────────────────────────
def percentile(data, p):
    """Calculate the p-th percentile of a sorted list."""
    if not data:
        return 0
    k = (len(data) - 1) * (p / 100.0)
    f = int(math.floor(k))
    c = int(math.ceil(k))
    if f == c:
        return data[f]
    return data[f] * (c - k) + data[c] * (k - f)

def stats(values):
    """Compute full statistical summary."""
    if not values:
        return {'count': 0, 'min': 0, 'max': 0, 'mean': 0, 'median': 0,
                'p50': 0, 'p95': 0, 'p99': 0, 'p999': 0, 'stddev': 0}

    s = sorted(values)
    n = len(s)
    mean = sum(s) / n
    variance = sum((x - mean) ** 2 for x in s) / n if n > 1 else 0
    stddev = math.sqrt(variance)

    return {
        'count':  n,
        'min':    s[0],
        'max':    s[-1],
        'mean':   mean,
        'median': percentile(s, 50),
        'p50':    percentile(s, 50),
        'p95':    percentile(s, 95),
        'p99':    percentile(s, 99),
        'p999':   percentile(s, 99.9),
        'stddev': stddev,
    }

def fmt_ns(ns):
    """Format nanoseconds with appropriate unit."""
    if ns < 1000:
        return f"{ns:.0f} ns"
    elif ns < 1_000_000:
        return f"{ns/1000:.2f} µs"
    elif ns < 1_000_000_000:
        return f"{ns/1_000_000:.2f} ms"
    else:
        return f"{ns/1_000_000_000:.3f} s"

# ── Generate Report ──────────────────────────────────────────────────────
with open(REPORT_FILE, 'w') as f:

    f.write("═" * 80 + "\n")
    f.write("  XDP Packet Lifecycle Latency Report — Nanosecond Precision\n")
    f.write(f"  Generated: $(date)\n")
    f.write(f"  Interface: ${IFACE}\n")
    f.write(f"  Duration:  ${DURATION}s  |  Sample Rate: 1-in-${SAMPLE_RATE}\n")
    f.write(f"  Total Events Captured: {len(rows)}\n")
    f.write("═" * 80 + "\n\n")

    # ── Section 1: Overall Pipeline Timings ──────────────────────────
    f.write("┌" + "─" * 78 + "┐\n")
    f.write("│  SECTION 1: Overall XDP Pipeline Stage Timings" + " " * 31 + "│\n")
    f.write("├" + "─" * 78 + "┤\n")
    f.write("│  Stage" + " " * 8 + "│ Min" + " " * 6 + "│ Mean"
            + " " * 5 + "│ Median" + " " * 3 + "│ P95"
            + " " * 6 + "│ P99" + " " * 6 + "│ Max" + " " * 5 + "│\n")
    f.write("├" + "─" * 78 + "┤\n")

    for col, label, _ in stage_names:
        vals = all_data.get(col, [])
        s = stats(vals)
        f.write(f"│  {label:<15}│ {fmt_ns(s['min']):>9} │ {fmt_ns(s['mean']):>9} "
                f"│ {fmt_ns(s['median']):>9} │ {fmt_ns(s['p95']):>9} "
                f"│ {fmt_ns(s['p99']):>9} │ {fmt_ns(s['max']):>8} │\n")

    f.write("└" + "─" * 78 + "┘\n\n")

    # ── Section 2: Detailed per-stage breakdown ──────────────────────
    f.write("┌" + "─" * 78 + "┐\n")
    f.write("│  SECTION 2: Detailed Per-Stage Timing (nanoseconds)" + " " * 26 + "│\n")
    f.write("└" + "─" * 78 + "┘\n\n")

    for col, label, desc in stage_names:
        vals = all_data.get(col, [])
        s = stats(vals)

        f.write(f"  ── {desc} ──\n")
        f.write(f"     Samples:   {s['count']:>12}\n")
        f.write(f"     Min:       {s['min']:>12} ns   ({fmt_ns(s['min'])})\n")
        f.write(f"     Max:       {s['max']:>12} ns   ({fmt_ns(s['max'])})\n")
        f.write(f"     Mean:      {s['mean']:>12.1f} ns   ({fmt_ns(s['mean'])})\n")
        f.write(f"     Median:    {s['median']:>12.1f} ns   ({fmt_ns(s['median'])})\n")
        f.write(f"     P95:       {s['p95']:>12.1f} ns   ({fmt_ns(s['p95'])})\n")
        f.write(f"     P99:       {s['p99']:>12.1f} ns   ({fmt_ns(s['p99'])})\n")
        f.write(f"     P99.9:     {s['p999']:>12.1f} ns   ({fmt_ns(s['p999'])})\n")
        f.write(f"     Std Dev:   {s['stddev']:>12.1f} ns   ({fmt_ns(s['stddev'])})\n\n")

    # ── Section 3: Breakdown by Detection Path ───────────────────────
    f.write("┌" + "─" * 78 + "┐\n")
    f.write("│  SECTION 3: Processing Time by Detection Path" + " " * 32 + "│\n")
    f.write("│  (This shows how long the XDP program takes to RECOGNIZE each attack type) │\n")
    f.write("└" + "─" * 78 + "┘\n\n")

    for path_key in sorted(by_path.keys()):
        path_rows = by_path[path_key]
        label = path_labels.get(path_key, path_key)
        total_times = []

        for r in path_rows:
            try:
                total_times.append(int(r['d_total_ns']))
            except (ValueError, KeyError):
                pass

        s = stats(total_times)

        f.write(f"  ── {label} ({len(path_rows)} packets) ──\n")
        f.write(f"     Recognition Time (T0 → Verdict):\n")
        f.write(f"       Min:     {s['min']:>12} ns   ({fmt_ns(s['min'])})\n")
        f.write(f"       Mean:    {s['mean']:>12.1f} ns   ({fmt_ns(s['mean'])})\n")
        f.write(f"       Median:  {s['median']:>12.1f} ns   ({fmt_ns(s['median'])})\n")
        f.write(f"       P95:     {s['p95']:>12.1f} ns   ({fmt_ns(s['p95'])})\n")
        f.write(f"       P99:     {s['p99']:>12.1f} ns   ({fmt_ns(s['p99'])})\n")
        f.write(f"       Max:     {s['max']:>12} ns   ({fmt_ns(s['max'])})\n")
        f.write(f"       Std Dev: {s['stddev']:>12.1f} ns   ({fmt_ns(s['stddev'])})\n")

        # Per-stage breakdown for this path
        f.write(f"\n     Per-Stage Breakdown:\n")
        for col, stage_label, _ in stage_names[:-1]:  # skip TOTAL
            stage_vals = []
            for r in path_rows:
                try:
                    stage_vals.append(int(r[col]))
                except (ValueError, KeyError):
                    pass
            ss = stats(stage_vals)
            f.write(f"       {stage_label:<20} Mean: {fmt_ns(ss['mean']):>9}  "
                    f"P95: {fmt_ns(ss['p95']):>9}  "
                    f"P99: {fmt_ns(ss['p99']):>9}\n")
        f.write("\n")

    # ── Section 4: Attack Recognition Summary ────────────────────────
    f.write("┌" + "─" * 78 + "┐\n")
    f.write("│  SECTION 4: Attack Recognition Time Summary" + " " * 34 + "│\n")
    f.write("│  Time from packet arrival (T0) to attack verdict (T5)                      │\n")
    f.write("└" + "─" * 78 + "┘\n\n")

    attack_paths = ['DROP_ARP_SPOOF', 'DROP_GARP', 'DROP_MAC_FLOOD', 'DROP_RATE_LIMIT']
    legit_paths  = ['PASS_ARP_VALID', 'PASS_NON_ARP', 'PASS_DHCP', 'PASS_ARP_RATELIM']

    all_attack_times = []
    all_legit_times  = []

    f.write(f"  {'Attack Type':<30} {'Count':>8} {'Mean':>12} {'Median':>12} "
            f"{'P95':>12} {'P99':>12}\n")
    f.write(f"  {'─' * 30} {'─' * 8} {'─' * 12} {'─' * 12} {'─' * 12} {'─' * 12}\n")

    for path_key in attack_paths:
        if path_key not in by_path:
            continue
        times = []
        for r in by_path[path_key]:
            try: times.append(int(r['d_total_ns']))
            except: pass
        all_attack_times.extend(times)
        s = stats(times)
        label = path_labels.get(path_key, path_key)
        f.write(f"  {label:<30} {s['count']:>8} {fmt_ns(s['mean']):>12} "
                f"{fmt_ns(s['median']):>12} {fmt_ns(s['p95']):>12} "
                f"{fmt_ns(s['p99']):>12}\n")

    f.write(f"\n")

    for path_key in legit_paths:
        if path_key not in by_path:
            continue
        times = []
        for r in by_path[path_key]:
            try: times.append(int(r['d_total_ns']))
            except: pass
        all_legit_times.extend(times)
        s = stats(times)
        label = path_labels.get(path_key, path_key)
        f.write(f"  {label:<30} {s['count']:>8} {fmt_ns(s['mean']):>12} "
                f"{fmt_ns(s['median']):>12} {fmt_ns(s['p95']):>12} "
                f"{fmt_ns(s['p99']):>12}\n")

    # ── Aggregate attack vs legitimate ───────────────────────────────
    f.write(f"\n")
    if all_attack_times:
        sa = stats(all_attack_times)
        f.write(f"  ━━ ALL ATTACK PACKETS ━━\n")
        f.write(f"     Count:     {sa['count']:>12}\n")
        f.write(f"     Mean:      {sa['mean']:>12.1f} ns   ({fmt_ns(sa['mean'])})\n")
        f.write(f"     Median:    {sa['median']:>12.1f} ns   ({fmt_ns(sa['median'])})\n")
        f.write(f"     P95:       {sa['p95']:>12.1f} ns   ({fmt_ns(sa['p95'])})\n")
        f.write(f"     P99:       {sa['p99']:>12.1f} ns   ({fmt_ns(sa['p99'])})\n")
        f.write(f"     P99.9:     {sa['p999']:>12.1f} ns   ({fmt_ns(sa['p999'])})\n")
        f.write(f"     Max:       {sa['max']:>12} ns   ({fmt_ns(sa['max'])})\n\n")

    if all_legit_times:
        sl = stats(all_legit_times)
        f.write(f"  ━━ ALL LEGITIMATE PACKETS ━━\n")
        f.write(f"     Count:     {sl['count']:>12}\n")
        f.write(f"     Mean:      {sl['mean']:>12.1f} ns   ({fmt_ns(sl['mean'])})\n")
        f.write(f"     Median:    {sl['median']:>12.1f} ns   ({fmt_ns(sl['median'])})\n")
        f.write(f"     P95:       {sl['p95']:>12.1f} ns   ({fmt_ns(sl['p95'])})\n")
        f.write(f"     P99:       {sl['p99']:>12.1f} ns   ({fmt_ns(sl['p99'])})\n")
        f.write(f"     Max:       {sl['max']:>12} ns   ({fmt_ns(sl['max'])})\n\n")

    if all_attack_times and all_legit_times:
        sa = stats(all_attack_times)
        sl = stats(all_legit_times)
        overhead = sa['mean'] - sl['mean']
        f.write(f"  ━━ ATTACK DETECTION OVERHEAD ━━\n")
        f.write(f"     Mean overhead (attack - legit): {fmt_ns(overhead)}\n")
        f.write(f"     Ratio (attack / legit):         "
                f"{sa['mean']/sl['mean']:.2f}x\n\n" if sl['mean'] > 0 else "\n")

    # ── Section 5: Histogram (text-based) ────────────────────────────
    f.write("┌" + "─" * 78 + "┐\n")
    f.write("│  SECTION 5: Processing Time Distribution (Total T0→T5)" + " " * 24 + "│\n")
    f.write("└" + "─" * 78 + "┘\n\n")

    total_vals = all_data.get('d_total_ns', [])
    if total_vals:
        sorted_vals = sorted(total_vals)
        # Create histogram buckets (log-scale-ish)
        buckets = [0, 50, 100, 150, 200, 300, 500, 750, 1000,
                   1500, 2000, 3000, 5000, 10000, 50000, 100000,
                   500000, 1000000]
        counts = [0] * (len(buckets))

        for v in sorted_vals:
            placed = False
            for bi in range(len(buckets) - 1):
                if v < buckets[bi + 1]:
                    counts[bi] += 1
                    placed = True
                    break
            if not placed:
                counts[-1] += 1

        max_count = max(counts) if counts else 1
        bar_width = 40

        for bi in range(len(buckets)):
            if bi < len(buckets) - 1:
                label = f"  {fmt_ns(buckets[bi]):>9} - {fmt_ns(buckets[bi+1]):>9}"
            else:
                label = f"  {fmt_ns(buckets[bi]):>9} +          "

            bar_len = int(counts[bi] / max_count * bar_width) if max_count > 0 else 0
            bar = "█" * bar_len
            pct = 100 * counts[bi] / len(sorted_vals) if sorted_vals else 0
            f.write(f"{label} │{bar:<{bar_width}} {counts[bi]:>8} ({pct:5.1f}%)\n")
        f.write("\n")

    # ── Section 6: Time-Series (Processing Time Over Duration) ───────
    f.write("┌" + "─" * 78 + "┐\n")
    f.write("│  SECTION 6: Temporal Analysis — Processing Time Over Collection Period    │\n")
    f.write("└" + "─" * 78 + "┘\n\n")

    if rows:
        # Divide into 10 time slices
        try:
            first_t = int(rows[0]['t_entry_ns'])
            last_t  = int(rows[-1]['t_entry_ns'])
        except:
            first_t = 0
            last_t  = 1

        window = (last_t - first_t) // 10 if (last_t > first_t) else 1
        slices = [[] for _ in range(10)]

        for r in rows:
            try:
                t = int(r['t_entry_ns'])
                d = int(r['d_total_ns'])
                idx = min((t - first_t) // window, 9)
                slices[idx].append(d)
            except:
                pass

        f.write(f"  {'Time Slice':>12}  {'Packets':>8}  {'Mean':>12}  {'P95':>12}  "
                f"{'P99':>12}  {'Max':>12}\n")
        f.write(f"  {'─' * 12}  {'─' * 8}  {'─' * 12}  {'─' * 12}  {'─' * 12}  "
                f"{'─' * 12}\n")

        for i, sl in enumerate(slices):
            s = stats(sl)
            t0_s = (i * window) / 1e9
            t1_s = ((i + 1) * window) / 1e9
            f.write(f"  {t0_s:>5.1f}-{t1_s:<5.1f}s  {s['count']:>8}  "
                    f"{fmt_ns(s['mean']):>12}  {fmt_ns(s['p95']):>12}  "
                    f"{fmt_ns(s['p99']):>12}  {fmt_ns(s['max']):>12}\n")
        f.write("\n")

    # ── Section 7: Verdict Summary ───────────────────────────────────
    f.write("┌" + "─" * 78 + "┐\n")
    f.write("│  SECTION 7: Verdict Breakdown" + " " * 48 + "│\n")
    f.write("└" + "─" * 78 + "┘\n\n")

    verdict_counts = defaultdict(int)
    for r in rows:
        v = r.get('verdict', 'UNKNOWN')
        verdict_counts[v] += 1

    for v, c in sorted(verdict_counts.items()):
        pct = 100 * c / len(rows) if rows else 0
        f.write(f"  {v:<10} {c:>10} ({pct:5.1f}%)\n")
    f.write("\n")

    path_counts = defaultdict(int)
    for r in rows:
        p = r.get('path', 'UNKNOWN')
        path_counts[p] += 1

    f.write(f"  Detection Path Breakdown:\n")
    for p, c in sorted(path_counts.items(), key=lambda x: -x[1]):
        pct = 100 * c / len(rows) if rows else 0
        label = path_labels.get(p, p)
        f.write(f"    {label:<35} {c:>10} ({pct:5.1f}%)\n")

    f.write("\n" + "═" * 80 + "\n")
    f.write("  End of Report\n")
    f.write("═" * 80 + "\n")

print(f"  ✓ Report written to: {REPORT_FILE}")
print(f"  ✓ Raw CSV data at:   {CSV_FILE}")
ANALYSIS_EOF

if [[ $? -ne 0 ]]; then
    warn "Python analysis failed — raw CSV is still available: $RAW_DATA"
fi

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 5: Summary
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║               Latency Profiling Complete                            ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Report:    ${OUTPUT}${NC}"
echo -e "${BOLD}║  Raw CSV:   ${RAW_DATA}${NC}"
echo -e "${BOLD}║                                                                    ║${NC}"
echo -e "${BOLD}║  The report contains:                                              ║${NC}"
echo -e "${BOLD}║    §1  Overall pipeline stage timings (ns precision)               ║${NC}"
echo -e "${BOLD}║    §2  Detailed per-stage breakdown with percentiles               ║${NC}"
echo -e "${BOLD}║    §3  Processing time by detection path (spoof/flood/garp)        ║${NC}"
echo -e "${BOLD}║    §4  Attack recognition time summary                             ║${NC}"
echo -e "${BOLD}║    §5  Processing time distribution histogram                      ║${NC}"
echo -e "${BOLD}║    §6  Temporal analysis (time evolution)                           ║${NC}"
echo -e "${BOLD}║    §7  Verdict and path breakdown                                  ║${NC}"
echo -e "${BOLD}║                                                                    ║${NC}"
echo -e "${BOLD}║  To visualize:                                                     ║${NC}"
echo -e "${BOLD}║    Import ${RAW_DATA} into Excel/Sheets/gnuplot${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
