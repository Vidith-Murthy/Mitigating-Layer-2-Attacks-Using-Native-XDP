#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# test_legitimate.sh — Verify Legitimate Traffic Passes Through XDP
#
# Run this on the CLIENT VM to test that normal DHCP + ARP + ICMP
# traffic works correctly through the XDP-protected switch.
#
# Usage: sudo ./test_legitimate.sh <interface> <target_ip>
#
# Example:
#   sudo ./test_legitimate.sh eth0 192.168.100.1
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

IFACE="${1:-eth0}"
TARGET_IP="${2:-192.168.100.1}"

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓ PASS${NC}: $*"; }
fail() { echo -e "  ${RED}✗ FAIL${NC}: $*"; }
info() { echo -e "${CYAN}[TEST]${NC} $*"; }

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         LEGITIMATE TRAFFIC VERIFICATION                    ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Interface: $IFACE"
echo "║  Target:    $TARGET_IP"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

PASSED=0
FAILED=0

# ── Test 1: DHCP Lease Acquisition ──────────────────────────────────
info "Test 1: DHCP Lease Acquisition"
if sudo dhclient -v "$IFACE" 2>&1 | tail -5; then
    MY_IP=$(ip addr show "$IFACE" | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    if [[ -n "$MY_IP" ]]; then
        pass "Got IP address: $MY_IP via DHCP"
        ((PASSED++))
    else
        fail "DHCP completed but no IP assigned"
        ((FAILED++))
    fi
else
    fail "DHCP lease acquisition failed"
    ((FAILED++))
fi
echo ""

# ── Test 2: ARP Resolution ─────────────────────────────────────────
info "Test 2: ARP Resolution for $TARGET_IP"
if arping -c 3 -I "$IFACE" "$TARGET_IP" 2>&1; then
    pass "ARP resolution successful for $TARGET_IP"
    ((PASSED++))
else
    fail "ARP resolution failed for $TARGET_IP"
    ((FAILED++))
fi
echo ""

# ── Test 3: ICMP Ping ──────────────────────────────────────────────
info "Test 3: ICMP Ping to $TARGET_IP"
if ping -c 5 -W 2 "$TARGET_IP" 2>&1; then
    pass "Ping to $TARGET_IP successful"
    ((PASSED++))
else
    fail "Ping to $TARGET_IP failed"
    ((FAILED++))
fi
echo ""

# ── Test 4: ARP Table Verification ─────────────────────────────────
info "Test 4: ARP Table Consistency"
echo "  Current ARP table:"
arp -n | grep -v "incomplete" | head -10
ARP_ENTRIES=$(arp -n | grep -c "$TARGET_IP" || true)
if [[ "$ARP_ENTRIES" -ge 1 ]]; then
    pass "ARP entry exists for $TARGET_IP"
    ((PASSED++))
else
    fail "No ARP entry for $TARGET_IP"
    ((FAILED++))
fi
echo ""

# ── Test 5: TCP Connectivity (if anything is listening) ─────────────
info "Test 5: TCP Connectivity Check (port 22/SSH)"
if timeout 3 bash -c "echo >/dev/tcp/$TARGET_IP/22" 2>/dev/null; then
    pass "TCP connection to $TARGET_IP:22 successful"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠ SKIP${NC}: TCP port 22 not reachable (SSH may not be running)"
fi
echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    TEST SUMMARY                            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Passed: $PASSED                                                     ║"
echo "║  Failed: $FAILED                                                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed! Legitimate traffic flows through XDP correctly.${NC}"
else
    echo -e "${RED}Some tests failed. Check XDP stats on the switch.${NC}"
fi
