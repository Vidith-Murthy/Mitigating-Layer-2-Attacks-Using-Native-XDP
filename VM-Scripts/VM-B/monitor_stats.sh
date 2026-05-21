#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# monitor_stats.sh — Real-Time XDP Security Statistics Monitor
#
# Run this on the Ubuntu Server VM (switch) to view live XDP stats.
# Reads the stats_map and binding_map via bpftool.
#
# Usage: ./monitor_stats.sh [interval_seconds]
#
# Example:
#   sudo ./monitor_stats.sh        # Updates every 2 seconds
#   sudo ./monitor_stats.sh 1      # Updates every second
# ═══════════════════════════════════════════════════════════════════════

INTERVAL="${1:-2}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Must run as root" && exit 1
fi

# ── Find the map IDs ────────────────────────────────────────────────
get_map_id() {
    local name="$1"
    bpftool map list 2>/dev/null | grep "name $name" | head -1 | awk '{print $1}' | tr -d ':'
}

STATS_MAP_ID=$(get_map_id "stats_map")
BINDING_MAP_ID=$(get_map_id "binding_map")
MAC_TRACKING_ID=$(get_map_id "mac_tracking_map")

if [[ -z "$STATS_MAP_ID" ]]; then
    echo -e "${RED}[ERROR]${NC} Cannot find stats_map. Is the XDP program loaded?"
    echo ""
    echo "Check with: bpftool prog list"
    exit 1
fi

# ── Stat names ───────────────────────────────────────────────────────
STAT_NAMES=(
    "Total Packets"
    "Packets Passed"
    "ARP Spoof Drops"
    "Gratuitous ARP Drops"
    "MAC Flood Drops"
    "Rate Limit Drops"
    "DHCP Mirrored"
    "ARP Passed"
)

# ── Main loop ────────────────────────────────────────────────────────
echo -e "${CYAN}Starting XDP monitor (refresh every ${INTERVAL}s, Ctrl+C to stop)${NC}"
echo ""

while true; do
    clear

    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║      XDP Layer-2 Security — Live Monitor                   ║${NC}"
    echo -e "${BOLD}║      $TIMESTAMP                                  ║${NC}"
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"

    # ── Read stats ──────────────────────────────────────────────────
    echo -e "${BOLD}║  📊 STATISTICS                                              ║${NC}"
    echo -e "${BOLD}╠──────────────────────────────────────────────────────────────╣${NC}"

    STATS_JSON=$(bpftool map dump id "$STATS_MAP_ID" -j 2>/dev/null || echo "[]")

    for i in $(seq 0 7); do
        # Sum per-CPU values for this stat index
        VALUE=$(echo "$STATS_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
total = 0
for entry in data:
    key_val = entry.get('key', 0)
    if isinstance(key_val, list):
        # Reconstruct integer from bytes
        k = 0
        for j, b in enumerate(key_val):
            k |= (b << (8*j))
        key_val = k
    if key_val == $i:
        vals = entry.get('values', [entry])
        for v in vals:
            val = v.get('value', 0)
            if isinstance(val, list):
                n = 0
                for j, b in enumerate(val):
                    n |= (b << (8*j))
                total += n
            else:
                total += int(val)
print(total)
" 2>/dev/null || echo "0")

        NAME="${STAT_NAMES[$i]:-Unknown}"

        # Color drops red, passes green
        if [[ "$i" -ge 2 && "$i" -le 5 && "$VALUE" -gt 0 ]]; then
            printf "║  ${RED}%-30s  %12s${NC}               ║\n" "$NAME" "$VALUE"
        elif [[ "$i" -le 1 ]]; then
            printf "║  ${GREEN}%-30s  %12s${NC}               ║\n" "$NAME" "$VALUE"
        else
            printf "║  %-30s  %12s               ║\n" "$NAME" "$VALUE"
        fi
    done

    # ── Show bindings ──────────────────────────────────────────────
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║  🔗 IP → MAC BINDINGS                                      ║${NC}"
    echo -e "${BOLD}╠──────────────────────────────────────────────────────────────╣${NC}"

    if [[ -n "$BINDING_MAP_ID" ]]; then
        BINDINGS=$(bpftool map dump id "$BINDING_MAP_ID" -j 2>/dev/null || echo "[]")
        BIND_COUNT=$(echo "$BINDINGS" | python3 -c "
import json, sys, struct, socket
data = json.load(sys.stdin)
count = 0
for entry in data:
    key = entry.get('key', [])
    val = entry.get('value', [])
    if isinstance(key, list) and len(key) >= 4:
        ip_int = struct.unpack('<I', bytes(key[:4]))[0]
        ip_str = socket.inet_ntoa(struct.pack('!I', socket.ntohl(ip_int)))
    else:
        ip_str = str(key)
    if isinstance(val, list) and len(val) >= 6:
        mac_str = ':'.join(f'{b:02x}' for b in val[:6])
    else:
        mac_str = str(val)
    print(f'  {ip_str:>16} → {mac_str}')
    count += 1
if count == 0:
    print('  (no bindings)')
" 2>/dev/null || echo "  (error reading bindings)")
        echo "$BIND_COUNT" | while IFS= read -r line; do
            printf "║  %-56s  ║\n" "$line"
        done
    else
        printf "║  %-56s  ║\n" "(binding map not found)"
    fi

    # ── Show MAC tracking count ────────────────────────────────────
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
    if [[ -n "$MAC_TRACKING_ID" ]]; then
        MAC_COUNT=$(bpftool map dump id "$MAC_TRACKING_ID" -j 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(len(data))
" 2>/dev/null || echo "?")
        printf "║  🔍 Unique Unknown MACs Tracked: %-26s║\n" "$MAC_COUNT / $FLOOD_THRESHOLD"
    fi

    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Refreshing every ${INTERVAL}s... Press Ctrl+C to stop${NC}"

    sleep "$INTERVAL"
done
