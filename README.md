# XDP-Based Layer-2 Security System

**Mitigating ARP Spoofing and MAC Flooding Using Native XDP**

Implementation of the paper: *"Mitigating Layer-2 Attacks Using Native XDP and its Performance Implications"*

---

## Network Architecture

```
                          PROXMOX HOST
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │   Physical NIC ──── vmbr0 (Management Network / Internet)        │
  │                       │                                          │
  │                       │  management only                         │
  │                       │                                          │
  │                  ┌────┴──────────────────────────────────┐       │
  │                  │         VM-B (Switch)                 │       │
  │                  │         Ubuntu Server VM              │       │
  │                  │                                       │       │
  │                  │    net0 (vmbr0) ─ management/SSH      │       │
  │                  │    net1 (vmbr1) ─┐                    │       │
  │                  │    net2 (vmbr2) ─┼─ Linux Bridge(br0) │       │
  │                  │    net3 (vmbr3) ─┘    + XDP attached  │       │
  │                  │                                       │       │
  │                  │    ┌────────────────────────────┐     │       │
  │                  │    │ XDP Program (Native Mode)  │     │       │
  │                  │    │ ● MAC Flood Detection      │     │       │
  │                  │    │ ● DHCP Snooping            │     │       │
  │                  │    │ ● ARP Spoofing Mitigation  │     │       │
  │                  │    │ ● Gratuitous ARP Blocking  │     │       │
  │                  │    └────────────────────────────┘     │       │
  │                  │                                       │       │
  │                  │    ┌────────────────────────────┐     │       │
  │                  │    │ User-Space Daemon          │     │       │
  │                  │    │ (Ring Buffer → Binding Map)│     │       │
  │                  │    └────────────────────────────┘     │       │
  │                  └──────┬──────────┬──────────┬─────────┘        │
  │                         │          │          │                  │
  │                    vmbr1│     vmbr2│     vmbr3│                  │
  │                (isolated)  (isolated)  (isolated)                │
  │                         │          │          │                  │
  │               ┌─────────┴┐   ┌─────┴────┐   ┌┴──────────┐        │
  │               │  VM-A    │   │  VM-C    │   │  VM-D     │        │
  │               │ Attacker │   │ Client   │   │ DHCP Srv  │        │
  │               │          │   │          │   │           │        │
  │               │ net0     │   │ net0     │   │ net0      │        │
  │               │ (vmbr1)  │   │ (vmbr2)  │   │ (vmbr3)   │        │
  │               │          │   │          │   │           │        │
  │               │ NO vmbr0 │   │ NO vmbr0 │   │ NO vmbr0  │        │
  │               │ ISOLATED │   │ ISOLATED │   │ ISOLATED  │        │
  │               └──────────┘   └──────────┘   └───────────┘        │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘

  vmbr0 ── Management bridge (physical NIC, internet access)
  vmbr1 ── Isolated bridge (NO physical ports) ── VM-A ↔ VM-B only
  vmbr2 ── Isolated bridge (NO physical ports) ── VM-C ↔ VM-B only
  vmbr3 ── Isolated bridge (NO physical ports) ── VM-D ↔ VM-B only
```

### Traffic Flow

```
  VM-A (Attacker)                                      VM-C (Client)
       │                                                    │
       │ All traffic                            All traffic │
       ▼                                                    ▼
    [vmbr1]                                             [vmbr2]
       │                                                    │
       ▼                                                    ▼
  ┌─── net1 ──────── VM-B Linux Bridge (br0) ──────── net2 ─── ┐
  │                          │                                 │
  │                    XDP inspects                            │
  │                   every packet                             │
  │                          │                                 │
  └─── net3 ─────────────────┘                                 │
       │                                                       │
       ▼                                                       │
    [vmbr3]                                                    │
       │                                                       │
       ▼                                                       │
  VM-D (DHCP Server)                                           │
       │                                                       │
       └── DHCP ACK observed by XDP ──► binding_map updated ───┘
```

**Key**: VM-A, VM-C, and VM-D have **no route to the internet** and **no management network access**. Their only connectivity is through VM-B's bridge, where XDP monitors everything.

---

## How It Works

### Data Plane (XDP — Fast Path)

The XDP program runs at the **NIC driver level** (native mode on Proxmox VirtIO NICs / virtio_net) and processes every incoming packet in three phases:

1. **Phase 1 — MAC Flooding Protection**: Tracks unique source MACs in an LRU map. If the count exceeds `FLOOD_THRESHOLD`, packets are dropped immediately.

2. **Phase 2 — Protocol Demultiplexing**:
   - **DHCP packets** → Mirrored to user-space via eBPF ring buffer, then passed normally
   - **ARP packets** → Validated against the trusted binding map (see Phase 3)
   - **All other traffic** → Passed through

3. **Phase 3 — ARP Validation**:
   - If `binding_map[sender_IP]` exists → MAC must match exactly, else DROP (ARP spoofing)
   - If no binding exists:
     - Gratuitous ARP (sender IP == target IP) → DROP (MITM vector)
     - Regular ARP → Rate-limited acceptance (allows initial DHCP window)

### Control Plane (User-Space Daemon — Slow Path)

The daemon receives mirrored DHCP packets via the ring buffer and:
- Parses DHCP ACK → extracts `yiaddr` (assigned IP) + `chaddr` (client MAC)
- Updates `binding_map[IP] = MAC` atomically
- On DHCP Release → removes the binding

---

## File Structure

```
ResearchPaper/
├── xdp_l2_security.h          # Shared header (maps, constants, structs)
├── xdp_l2_security.bpf.c      # XDP kernel program (Algorithm 6)
├── l2_security_daemon.c        # User-space daemon (Algorithm 1)
├── Makefile                    # Build system
├── install_deps.sh             # Install all dependencies
├── setup_bridge.sh             # Configure VM-B as L2 bridge
├── teardown_bridge.sh          # Remove bridge + detach XDP
├── setup_dhcp_server.sh        # Configure DHCP on VM-D
├── attack_arp_spoof.sh         # ARP spoofing simulation (VM-A)
├── attack_mac_flood.sh         # MAC flooding simulation (VM-A)
├── attack_garp.py              # Gratuitous ARP simulation (VM-A)
├── test_legitimate.sh          # Verify legitimate traffic (VM-C)
├── monitor_stats.sh            # Live stats dashboard (VM-B)
└── README.md                   # This file
```

---

## Setup Instructions

### Prerequisites

| VM | OS | Purpose | Proxmox NICs |
|----|-----|---------|-------------|
| **VM-A** | Ubuntu | Attacker | 1 × VirtIO on `vmbr1` |
| **VM-B** | Ubuntu Server | XDP Switch | 1 × VirtIO on `vmbr0` (mgmt) + 3 × VirtIO on `vmbr1`, `vmbr2`, `vmbr3` |
| **VM-C** | Ubuntu | Client | 1 × VirtIO on `vmbr2` |
| **VM-D** | Ubuntu | DHCP Server | 1 × VirtIO on `vmbr3` |

> **IMPORTANT**: VM-A, VM-C, VM-D must have **VirtIO** NIC model and must **NOT** have any NIC on `vmbr0`. This ensures they are fully isolated from the external network.

---

### Step 1: Proxmox Host — Create Isolated Bridges

SSH into your Proxmox host and add the following to `/etc/network/interfaces` (below your existing `vmbr0`):

```
# ── Isolated bridge: VM-A (Attacker) ↔ VM-B (Switch) ──
auto vmbr1
iface vmbr1 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware no

# ── Isolated bridge: VM-C (Client) ↔ VM-B (Switch) ──
auto vmbr2
iface vmbr2 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware no

# ── Isolated bridge: VM-D (DHCP Server) ↔ VM-B (Switch) ──
auto vmbr3
iface vmbr3 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware no
```

Apply:
```bash
ifreload -a
# or reboot the Proxmox host
```

---

### Step 2: Proxmox Host — Configure VM NICs

In the **Proxmox UI** (Datacenter → VM → Hardware → Add → Network Device):

#### VM-B (Switch) — 4 NICs
| NIC | Bridge | Model | Purpose |
|-----|--------|-------|---------|
| `net0` | `vmbr0` | VirtIO | Management / SSH access |
| `net1` | `vmbr1` | VirtIO | Link to VM-A (Attacker) |
| `net2` | `vmbr2` | VirtIO | Link to VM-C (Client) |
| `net3` | `vmbr3` | VirtIO | Link to VM-D (DHCP Server) |

#### VM-A (Attacker) — 1 NIC, ISOLATED
| NIC | Bridge | Model | Purpose |
|-----|--------|-------|---------|
| `net0` | `vmbr1` | VirtIO | Only link (through VM-B) |

#### VM-C (Client) — 1 NIC, ISOLATED
| NIC | Bridge | Model | Purpose |
|-----|--------|-------|---------|
| `net0` | `vmbr2` | VirtIO | Only link (through VM-B) |

#### VM-D (DHCP Server) — 1 NIC, ISOLATED
| NIC | Bridge | Model | Purpose |
|-----|--------|-------|---------|
| `net0` | `vmbr3` | VirtIO | Only link (through VM-B) |

> **Verify isolation**: After booting, VM-A/C/D should have NO internet access and NO route to `vmbr0`. Their only path is through VM-B.

Boot all VMs after configuration.

---

### Step 3: VM-B (Switch) — Install Dependencies & Build

Copy all project files to VM-B, then:

```bash
# SSH into VM-B via its vmbr0 management IP
ssh user@<VM-B-management-IP>

# Install all dependencies
sudo chmod +x *.sh
sudo ./install_deps.sh

# Check your interface names
ip link show
# Expected output (names may vary):
#   ens18  → vmbr0 (management)
#   ens19  → vmbr1 (to VM-A)
#   ens20  → vmbr2 (to VM-C)
#   ens21  → vmbr3 (to VM-D)

# Build the XDP program and daemon
make vmlinux
make
```

---

### Step 4: VM-B (Switch) — Configure the Linux Bridge

Bridge the 3 isolated interfaces (NOT the management interface):

```bash
# Replace ens19, ens20, ens21 with your actual interface names
sudo ./setup_bridge.sh ens19 ens20 ens21
```

This creates `br0` with all three ports. Traffic between VM-A, VM-C, and VM-D now flows through VM-B.

> **WARNING**: Do NOT add your management interface (ens18/vmbr0) to the bridge — you will lose SSH access.

---

### Step 5: VM-D (DHCP Server) — Set Up DHCP

Access VM-D from VM-B:
```bash
# From VM-B, once the bridge is up you can reach VM-D
# Or use Proxmox console (noVNC) since VM-D has no internet
```

On VM-D:
```bash
# Assign a static IP to VM-D's interface
sudo ip addr add 192.168.100.1/24 dev eth0
sudo ip link set eth0 up

# Run the DHCP setup script
sudo ./setup_dhcp_server.sh eth0
```

This configures `isc-dhcp-server` with:
- Subnet: `192.168.100.0/24`
- Pool: `192.168.100.100` – `192.168.100.200`
- Gateway: `192.168.100.1` (VM-D itself)

---

### Step 6: VM-B (Switch) — Start the XDP Security Daemon

```bash
# Replace with your actual interface names
sudo ./build/l2_security_daemon \
    --iface ens19 \
    --iface ens20 \
    --iface ens21 \
    --verbose
```

You should see:
```
✓ XDP attached to ens19 (native/driver mode — virtio_net)
✓ XDP attached to ens20 (native/driver mode — virtio_net)
✓ XDP attached to ens21 (native/driver mode — virtio_net)

╔══════════════════════════════════════════════════════╗
║   XDP Layer-2 Security Daemon — Active              ║
║   Monitoring DHCP traffic for binding updates...    ║
╚══════════════════════════════════════════════════════╝
```

---

### Step 7: VM-C (Client) — Get IP & Test Legitimate Traffic

Access VM-C via Proxmox console (noVNC), then:

```bash
# Request IP from DHCP (through VM-B bridge → VM-D)
sudo dhclient eth0

# Verify you got an IP
ip addr show eth0
# Should show something like: 192.168.100.100/24

# Run the legitimate traffic test
sudo ./test_legitimate.sh eth0 192.168.100.1
```

On VM-B, the daemon should log:
```
[2026-04-09 16:45:00] BINDING ADDED: 192.168.100.100 → <VM-C-MAC>
```

---

### Step 8: VM-B (Switch) — Monitor in Real-Time

Open a second SSH session to VM-B:

```bash
sudo ./monitor_stats.sh
```

This shows a live dashboard with packet counters, bindings, and drop statistics.

---

### Step 9: VM-A (Attacker) — Simulate Attacks

Access VM-A via Proxmox console (noVNC), then:

```bash
# First, get an IP via DHCP (also goes through VM-B)
sudo dhclient eth0

# ── Attack 1: ARP Spoofing ──
# Try to impersonate VM-D (192.168.100.1) to VM-C (192.168.100.100)
sudo ./attack_arp_spoof.sh 192.168.100.100 192.168.100.1 eth0
# → XDP should DROP these (ARP Spoof Drops counter increases)

# ── Attack 2: MAC Flooding ──
# Send thousands of frames with random MACs
sudo ./attack_mac_flood.sh eth0 30
# → XDP should DROP after FLOOD_THRESHOLD exceeded

# ── Attack 3: Gratuitous ARP ──
# Send GARPs pretending to own VM-C's IP
sudo python3 attack_garp.py 192.168.100.100 eth0 50
# → XDP should DROP all (Gratuitous ARP Drops counter increases)
```

Watch the `monitor_stats.sh` dashboard on VM-B — you should see the drop counters increasing in real-time while legitimate traffic from VM-C continues unaffected.

---

## Configuration

### Compile-Time Thresholds

Override thresholds when building:

```bash
make FLOOD_THRESHOLD=200 RATE_LIMIT=10
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `FLOOD_THRESHOLD` | 100 | Max unique unknown MACs before flood detection triggers |
| `RATE_LIMIT` | 5 | Max unverified ARP packets per unknown IP |

### Manual Binding Management

```bash
# Add a static binding
sudo ./build/l2_security_daemon --add-binding 192.168.100.50 aa:bb:cc:dd:ee:ff

# Remove a binding
sudo ./build/l2_security_daemon --del-binding 192.168.100.50

# List all bindings
sudo ./build/l2_security_daemon --list-bindings

# Show statistics
sudo ./build/l2_security_daemon --stats
```

---

## eBPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `binding_map` | HASH | IPv4 addr | MAC addr | Trusted IP→MAC from DHCP |
| `mac_tracking_map` | LRU_HASH | MAC addr | Timestamp | Unknown MAC tracking |
| `mac_count_map` | ARRAY | 0 | Counter | Unique unknown MAC count |
| `rate_limit_map` | LRU_HASH | IPv4 addr | Counter | Per-IP ARP rate limiting |
| `stats_map` | PERCPU_ARRAY | Stat index | Counter | Performance counters |
| `events_rb` | RINGBUF | — | Packet data | DHCP packet mirroring |

## Algorithm Reference

| Algorithm | Paper Section | File | Function |
|-----------|--------------|------|----------|
| Algorithm 1 — DHCP Binding Update | §3.2 | `l2_security_daemon.c` | `handle_dhcp_event()` |
| Algorithm 2 — ARP Validation | §3.3 | `xdp_l2_security.bpf.c` | Phase 3 |
| Algorithm 3 — Gratuitous ARP Handling | §3.3 | `xdp_l2_security.bpf.c` | Phase 3 (GARP check) |
| Algorithm 4 — Rate Limiting | §3.4 | `xdp_l2_security.bpf.c` | Phase 3 (rate limit) |
| Algorithm 5 — MAC Tracking | §3.5 | `xdp_l2_security.bpf.c` | Phase 1 |
| Algorithm 6 — Unified Enforcement | §3.6 | `xdp_l2_security.bpf.c` | `xdp_l2_security()` |

---

## Troubleshooting

### XDP attach fails
```bash
# Check if interface supports XDP
ethtool -i eth0 | grep driver
# virtio_net = native XDP support (Proxmox VirtIO)
# e1000 / rtl8139 = NO XDP support (change NIC model in Proxmox to VirtIO)

# Check for existing XDP programs
ip link show eth0 | grep xdp

# Force detach
ip link set dev eth0 xdp off
```

### No bindings appearing
```bash
# Verify DHCP traffic reaches VM-B
tcpdump -i ens19 port 67 or port 68 -vv

# Check ring buffer
bpftool map dump name events_rb

# Verify daemon is running
ps aux | grep l2_security_daemon
```

### VM-A/C/D can't communicate
```bash
# On VM-B, verify the bridge is up
brctl show br0

# Verify all interfaces are in the bridge
bridge link

# Check that XDP is attached
ip link show ens19 | grep xdp
ip link show ens20 | grep xdp
ip link show ens21 | grep xdp
```

### Accessing isolated VMs (VM-A, VM-C, VM-D)
Since these VMs have no internet and no management network:
- Use **Proxmox noVNC console** (Datacenter → VM → Console)
- Or copy files via VM-B after the bridge is up:
  ```bash
  # From VM-B, once bridge is up and VMs have IPs:
  scp *.sh user@192.168.100.100:~/   # to VM-C
  scp *.sh user@192.168.100.101:~/   # to VM-A
  ```

### Program verification fails
```bash
# Check BPF verifier log
bpftool prog load xdp_l2_security.bpf.o /sys/fs/bpf/test type xdp

# The default 1M instruction limit should be sufficient
```

---

## Teardown

```bash
# On VM-B: stop the daemon (Ctrl+C), then:
sudo ./teardown_bridge.sh ens19 ens20 ens21
```

---

## License

GPL-2.0 (required for eBPF/XDP programs)
