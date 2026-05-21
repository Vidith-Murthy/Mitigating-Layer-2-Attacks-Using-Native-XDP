#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# benchmark_scale.sh — Scalability Test: Multiple Clients Under Attack
#
# Simulates N clients with bindings and generates both legitimate
# and attack ARP traffic to test accuracy at scale.
#
# Run on VM-A (attacker) after XDP daemon is running on VM-B.
#
# Usage:
#   sudo ./benchmark_scale.sh <num_clients> <interface> <duration>
#
# Example:
#   sudo ./benchmark_scale.sh 50 eth0 30
#   sudo ./benchmark_scale.sh 200 eth0 30
#   sudo ./benchmark_scale.sh 500 eth0 30
# ═══════════════════════════════════════════════════════════════════════

set -uo pipefail

NUM_CLIENTS="${1:?Usage: $0 <num_clients> <interface> <duration_secs>}"
IFACE="${2:-eth0}"
DURATION="${3:-30}"

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${CYAN}[SCALE]${NC} $*"; }

RESULTS_FILE="scale_benchmark_${NUM_CLIENTS}clients_$(date +%Y%m%d_%H%M%S).txt"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         Scalability Benchmark: ${NUM_CLIENTS} Simulated Clients              ║${NC}"
echo -e "${BOLD}║         Interface: ${IFACE} | Duration: ${DURATION}s                         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

{
    echo "═══════════════════════════════════════════════════════"
    echo "  Scalability Benchmark: ${NUM_CLIENTS} Clients"
    echo "  Date: $(date)"
    echo "  Duration: ${DURATION}s"
    echo "═══════════════════════════════════════════════════════"
    echo ""
} > "$RESULTS_FILE"

# ════════════════════════════════════════════════════════════════════
# Generate binding list for the daemon
# ════════════════════════════════════════════════════════════════════
info "Generating ${NUM_CLIENTS} client bindings..."

BINDING_FILE="static_bindings_${NUM_CLIENTS}.txt"
> "$BINDING_FILE"

# Generate MACs and IPs for simulated clients
# Use 192.168.100.10 - 192.168.100.10+N (skip .1 for DHCP, .100-.101 for real VMs)
for i in $(seq 1 "$NUM_CLIENTS"); do
    # Generate IP: spread across 192.168.{100-103}.{2-254}
    OCTET3=$(( 100 + (i / 253) ))
    OCTET4=$(( 2 + (i % 253) ))
    IP="192.168.${OCTET3}.${OCTET4}"

    # Generate deterministic MAC: 02:xx:xx:xx:xx:xx (locally administered)
    MAC=$(printf "02:%02x:%02x:%02x:%02x:%02x" \
        $(( (i >> 20) & 0xFF )) \
        $(( (i >> 15) & 0xFF )) \
        $(( (i >> 10) & 0xFF )) \
        $(( (i >> 5) & 0xFF )) \
        $(( i & 0x1F )) )

    echo "${IP} ${MAC}" >> "$BINDING_FILE"
done

info "Bindings written to ${BINDING_FILE}"
info ""
info "══════════════════════════════════════════════════════════════"
info "  IMPORTANT: Before running the attack phase, add these"
info "  bindings to the XDP daemon on VM-B. Run this on VM-B:"
info ""
info "  Build the --static-binding flags:"
BINDING_ARGS=""
while read -r ip mac; do
    BINDING_ARGS="${BINDING_ARGS} --static-binding ${ip} ${mac}"
done < "$BINDING_FILE"

echo "  sudo ./build/l2_security_daemon \\" 
echo "    --iface ens19 --iface ens20 --iface ens21 \\"
echo "    --static-binding 192.168.100.1 bc:24:11:de:d5:55 \\"
echo "    --static-binding 192.168.100.100 bc:24:11:b5:b1:9f \\"
echo "    --static-binding 192.168.100.101 bc:24:11:54:c1:6f \\"

# Show first few and last few
head -5 "$BINDING_FILE" | while read -r ip mac; do
    echo "    --static-binding ${ip} ${mac} \\"
done
echo "    ... (${NUM_CLIENTS} total client bindings) ..."
tail -1 "$BINDING_FILE" | while read -r ip mac; do
    echo "    --static-binding ${ip} ${mac} \\"
done
echo "    --verbose"

info ""
info "  OR use this helper to generate the full command:"
info "  Run on VM-B:"
info ""
info "══════════════════════════════════════════════════════════════"
echo ""

# Generate the full command to a file
DAEMON_CMD="sudo ./build/l2_security_daemon --iface ens19 --iface ens20 --iface ens21 --static-binding 192.168.100.1 bc:24:11:de:d5:55 --static-binding 192.168.100.100 bc:24:11:b5:b1:9f --static-binding 192.168.100.101 bc:24:11:54:c1:6f"
while read -r ip mac; do
    DAEMON_CMD="${DAEMON_CMD} --static-binding ${ip} ${mac}"
done < "$BINDING_FILE"
DAEMON_CMD="${DAEMON_CMD} --verbose"
echo "$DAEMON_CMD" > "daemon_cmd_${NUM_CLIENTS}clients.sh"
chmod +x "daemon_cmd_${NUM_CLIENTS}clients.sh"
info "Full daemon command saved to: daemon_cmd_${NUM_CLIENTS}clients.sh"
info "Copy it to VM-B and run: sudo bash daemon_cmd_${NUM_CLIENTS}clients.sh"
echo ""

read -p "Press ENTER after the daemon is running with all bindings loaded on VM-B..."

# ════════════════════════════════════════════════════════════════════
# Phase 1: Legitimate Traffic from Simulated Clients
# ════════════════════════════════════════════════════════════════════
info "Phase 1: Sending legitimate ARP from ${NUM_CLIENTS} simulated clients (${DURATION}s)..."

echo "── Phase 1: Legitimate Traffic (${NUM_CLIENTS} clients) ──" >> "$RESULTS_FILE"

python3 -c "
from scapy.all import *
import time, random

iface = '$IFACE'
duration = int('$DURATION')
binding_file = '$BINDING_FILE'

# Load bindings
clients = []
with open(binding_file) as f:
    for line in f:
        ip, mac = line.strip().split()
        clients.append((ip, mac))

print(f'Loaded {len(clients)} client bindings')

# Send legitimate ARP from each client
count = 0
legit_count = 0
end_time = time.time() + duration

while time.time() < end_time:
    # Pick a random client and send a legitimate ARP request
    src_ip, src_mac = random.choice(clients)
    dst_ip, dst_mac = random.choice(clients)

    # Legitimate ARP request/reply with correct IP-MAC binding
    pkt = Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(
        op=1,
        psrc=src_ip,
        pdst=dst_ip,
        hwsrc=src_mac,
        hwdst='00:00:00:00:00:00'
    )
    sendp(pkt, iface=iface, verbose=False)
    legit_count += 1
    count += 1

    # Every 10th packet, also send an ARP reply (legitimate)
    if count % 10 == 0:
        pkt_reply = Ether(src=src_mac, dst=dst_mac)/ARP(
            op=2,
            psrc=src_ip,
            pdst=dst_ip,
            hwsrc=src_mac,
            hwdst=dst_mac
        )
        sendp(pkt_reply, iface=iface, verbose=False)
        legit_count += 1

elapsed = duration
pps = legit_count / elapsed if elapsed > 0 else 0
print(f'Sent {legit_count} LEGITIMATE ARP packets in {elapsed}s ({pps:.0f} pps)')
print(f'  Each with CORRECT IP-MAC binding → should all PASS')
" 2>&1 | tee -a "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"

# ════════════════════════════════════════════════════════════════════
# Phase 2: Mixed Legitimate + Attack Traffic
# ════════════════════════════════════════════════════════════════════
info ""
info "Phase 2: Mixed traffic — legitimate + attacks simultaneously (${DURATION}s)..."

echo "── Phase 2: Mixed Legitimate + Attack Traffic ──" >> "$RESULTS_FILE"

python3 -c "
from scapy.all import *
import time, random, struct

iface = '$IFACE'
duration = int('$DURATION')
binding_file = '$BINDING_FILE'
target_ip = '192.168.100.100'
gateway_ip = '192.168.100.1'

# Load bindings
clients = []
with open(binding_file) as f:
    for line in f:
        ip, mac = line.strip().split()
        clients.append((ip, mac))

attacker_mac = get_if_hwaddr(iface)

legit_sent = 0
spoof_sent = 0
garp_sent = 0
flood_sent = 0
total = 0

end_time = time.time() + duration
batch = []

while time.time() < end_time:
    # 40% legitimate ARP (correct binding)
    src_ip, src_mac = random.choice(clients)
    dst_ip, _ = random.choice(clients)
    batch.append(
        Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(
            op=1, psrc=src_ip, pdst=dst_ip,
            hwsrc=src_mac, hwdst='00:00:00:00:00:00'
        )
    )
    legit_sent += 1

    # 20% ARP spoof (wrong MAC for existing binding)
    victim_ip, victim_mac = random.choice(clients)
    batch.append(
        Ether(src=attacker_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(
            op=2, psrc=victim_ip, pdst=target_ip,
            hwsrc=attacker_mac, hwdst='ff:ff:ff:ff:ff:ff'
        )
    )
    spoof_sent += 1

    # 20% GARP (sender_ip == target_ip with wrong MAC)
    victim_ip2, _ = random.choice(clients)
    batch.append(
        Ether(src=attacker_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(
            op=2, psrc=victim_ip2, pdst=victim_ip2,
            hwsrc=attacker_mac, hwdst='ff:ff:ff:ff:ff:ff'
        )
    )
    garp_sent += 1

    # 20% MAC flood (random MACs)
    rand_mac = RandMAC()
    batch.append(
        Ether(src=rand_mac, dst=RandMAC())/IP(
            src=RandIP(), dst=RandIP()
        )/TCP(sport=RandShort(), dport=RandShort())
    )
    flood_sent += 1

    # Send in batches of 40 for performance
    if len(batch) >= 40:
        sendp(batch, iface=iface, verbose=False)
        total += len(batch)
        batch = []

# Send remaining
if batch:
    sendp(batch, iface=iface, verbose=False)
    total += len(batch)

elapsed = duration
pps = total / elapsed if elapsed > 0 else 0

print(f'')
print(f'╔═══════════════════════════════════════════════╗')
print(f'║  Mixed Traffic Summary ({len(clients)} clients)         ║')
print(f'╠═══════════════════════════════════════════════╣')
print(f'║  Total packets sent:     {total:>8}             ║')
print(f'║  Rate:                   {pps:>8.0f} pps          ║')
print(f'║                                               ║')
print(f'║  Legitimate ARP (should PASS):  {legit_sent:>8}       ║')
print(f'║  ARP Spoof (should DROP):       {spoof_sent:>8}       ║')
print(f'║  GARP (should DROP as spoof):   {garp_sent:>8}       ║')
print(f'║  MAC Flood (should DROP):       {flood_sent:>8}       ║')
print(f'╚═══════════════════════════════════════════════╝')
print(f'')
print(f'EXPECTED on VM-B:')
print(f'  ARP Passed     ≈ {legit_sent}')
print(f'  ARP Spoof Drops ≈ {spoof_sent + garp_sent} (spoof + garp caught by binding check)')
print(f'  MAC Flood Drops ≈ {flood_sent} (minus ~{100} threshold window)')
print(f'  Accuracy        ≈ {100 * (spoof_sent + garp_sent + flood_sent - 100) / (spoof_sent + garp_sent + flood_sent):.3f}%')
" 2>&1 | tee -a "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Scale Benchmark Complete                                  ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Results: ${RESULTS_FILE}${NC}"
echo -e "${BOLD}║                                                            ║${NC}"
echo -e "${BOLD}║  NOW: Press Ctrl+C on the daemon (VM-B) to see stats       ║${NC}"
echo -e "${BOLD}║  Compare:                                                  ║${NC}"
echo -e "${BOLD}║    ARP Passed    → should match legitimate count           ║${NC}"
echo -e "${BOLD}║    Spoof Drops   → should match spoof + garp count         ║${NC}"
echo -e "${BOLD}║    Flood Drops   → should match flood count (- ~100)       ║${NC}"
echo -e "${BOLD}║    False positives = legitimate sent - ARP Passed           ║${NC}"
echo -e "${BOLD}║    False negatives = attack sent - total drops              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
