// SPDX-License-Identifier: GPL-2.0
/*
 * arp_guard.bpf.c — Unified XDP-Based Layer-2 Security Enforcement
 *
 * Implements Algorithm 6 from the paper:
 *   "Mitigating Layer-2 Attacks Using Native XDP and its Performance Implications"
 *
 * This program runs in native XDP mode on Proxmox VirtIO NICs (virtio_net driver)
 * and performs:
 *   Phase 1 — MAC Flooding Protection          (Algorithm 5)
 *   Phase 2 — Protocol Demultiplexing
 *             • DHCP → mirror to user-space     (Algorithm 1)
 *             • ARP  → strict validation         (Algorithms 2, 3, 4)
 *             • Other → XDP_PASS
 */

#include "vmlinux.h"
#define HAVE_VMLINUX_H 1
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "arp_guard.h"

#define ETH_P_ARP  0x0806
#define ETH_P_IP   0x0800
#define ETH_ALEN   6

#define IPPROTO_UDP 17

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2


struct arp_hdr {
    __be16 ar_hrd;        /* Hardware type */
    __be16 ar_pro;        /* Protocol type */
    __u8   ar_hln;        /* Hardware address length */
    __u8   ar_pln;        /* Protocol address length */
    __be16 ar_op;         /* ARP operation */
    __u8   ar_sha[6];     /* Sender hardware address (MAC) */
    __be32 ar_sip;        /* Sender IP address */
    __u8   ar_tha[6];     /* Target hardware address */
    __be32 ar_tip;        /* Target IP address */
} __attribute__((packed));

/* ── eBPF Map Definitions ────────────────────────────────────────────── */

/*
 * binding_map — Trusted IP → MAC associations learned from DHCP snooping.
 * Key:   __be32  (IPv4 address)
 * Value: struct mac_addr (6-byte MAC)
 * Populated by the user-space daemon upon observing DHCP ACK.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BINDINGS);
    __type(key, __be32);
    __type(value, struct mac_addr);
} binding_map SEC(".maps");

/*
 * mac_tracking_map — LRU map tracking unique unverified source MACs.
 * Used for MAC flooding detection.  LRU eviction prevents memory
 * exhaustion during volumetric attacks.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAC_ENTRIES);
    __type(key, struct mac_addr);
    __type(value, __u64);
} mac_tracking_map SEC(".maps");

/*
 * mac_count_map — Single-entry array storing the current count of
 * unique unverified MACs.  Index 0 holds the count.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} mac_count_map SEC(".maps");

/*
 * rate_limit_map — Per-IP packet counter for rate-limiting unknown
 * ARP sources.  LRU eviction keeps memory bounded.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __be32);
    __type(value, __u64);
} rate_limit_map SEC(".maps");

/*
 * stats_map — Per-CPU array of counters for observability.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/*
 * events_rb — Ring buffer for zero-copy mirroring of DHCP packets
 * to user-space control plane.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events_rb SEC(".maps");

// Increment a stats counter 
static __always_inline void stats_inc(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// Compare two MAC addresses
static __always_inline int mac_equal(const unsigned char *a,
                                     const unsigned char *b)
{
    return (a[0] == b[0]) && (a[1] == b[1]) && (a[2] == b[2]) &&
           (a[3] == b[3]) && (a[4] == b[4]) && (a[5] == b[5]);
}

// Check if MAC is broadcast (ff:ff:ff:ff:ff:ff)
static __always_inline int is_broadcast_mac(const unsigned char *mac)
{
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xff;
}

// Check if MAC is zero (00:00:00:00:00:00)
static __always_inline int is_zero_mac(const unsigned char *mac)
{
    return (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0;
}


// Main XDP Entry Point — Unified Layer-2 Security Enforcement
SEC("xdp")
int arp_guard(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    stats_inc(STATS_TOTAL_PACKETS);

    // Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_type = bpf_ntohs(eth->h_proto);

    /* ════════════════════════════════════════════════════════════════
     *  PHASE 1 — MAC Flooding Protection (Algorithm 5)
     *
     *  Extract source MAC.  If not in binding_map (unverified),
     *  insert into mac_tracking_map (LRU).  If total unique
     *  unverified MACs exceed FLOOD_THRESHOLD → DROP.
     * ════════════════════════════════════════════════════════════════ */

    struct mac_addr src_mac;
    __builtin_memcpy(src_mac.addr, eth->h_source, ETH_ALEN);

    /* Skip broadcast and zero MACs from flood tracking */
    if (!is_broadcast_mac(src_mac.addr) && !is_zero_mac(src_mac.addr)) {

        /* Check if this source MAC has a trusted binding.
         * We need to search binding_map by value (MAC), but maps are
         * keyed by IP.  Instead, we check the mac_tracking_map:
         * if the MAC is NOT in mac_tracking_map and NOT verifiable via
         * any binding, we track it.
         *
         * Simplified: track all source MACs in LRU.  If the LRU
         * utilization exceeds threshold, trigger flood detection.
         */
        __u64 *existing = bpf_map_lookup_elem(&mac_tracking_map, &src_mac);
        if (!existing) {
            /* New unverified MAC — insert into tracking map */
            __u64 ts = bpf_ktime_get_ns();
            bpf_map_update_elem(&mac_tracking_map, &src_mac, &ts, BPF_ANY);

            /* Increment unique MAC counter */
            __u32 zero = 0;
            __u64 *cnt = bpf_map_lookup_elem(&mac_count_map, &zero);
            if (cnt) {
                __u64 new_count = __sync_add_and_fetch(cnt, 1);
                if (new_count > FLOOD_THRESHOLD) {
                    stats_inc(STATS_DROPPED_MAC_FLOOD);
                    return XDP_DROP;
                }
            }
        }
        /* If MAC is already tracked, nothing to do for flood detection */
    }

    // PHASE 2 — Protocol Demultiplexing & Enforcement
    

    
     /* If the packet is an IPv4/UDP packet on ports 67 or 68,
     * mirror it to user-space via the ring buffer and PASS.
     */
    if (eth_type == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (void *)iph + (iph->ihl * 4);
            if ((void *)(udph + 1) > data_end)
                return XDP_PASS;

            __u16 src_port = bpf_ntohs(udph->source);
            __u16 dst_port = bpf_ntohs(udph->dest);

            if (src_port == DHCP_SERVER_PORT || src_port == DHCP_CLIENT_PORT ||
                dst_port == DHCP_SERVER_PORT || dst_port == DHCP_CLIENT_PORT) {

                /* Mirror the full packet to user-space via ring buffer */
                __u32 pkt_len = data_end - data;
                if (pkt_len > MAX_DHCP_PACKET_SIZE)
                    pkt_len = MAX_DHCP_PACKET_SIZE;

                struct dhcp_event *evt;
                evt = bpf_ringbuf_reserve(&events_rb,
                                          sizeof(struct dhcp_event), 0);
                if (evt) {
                    evt->pkt_len = pkt_len;

                    /* Use bounded read — verifier requires bounds check */
                    if (pkt_len <= MAX_DHCP_PACKET_SIZE) {
                        bpf_probe_read_kernel(evt->pkt_data, pkt_len, data);
                    }

                    bpf_ringbuf_submit(evt, 0);
                    stats_inc(STATS_DHCP_MIRRORED);
                }

                /* DHCP traffic is always passed for normal forwarding */
                stats_inc(STATS_PASSED);
                return XDP_PASS;
            }
        }

        /* Non-DHCP IPv4 traffic: pass */
        stats_inc(STATS_PASSED);
        return XDP_PASS;
    }

    // ARP Handling 
    if (eth_type == ETH_P_ARP) {
        struct arp_hdr *arph = (void *)(eth + 1);
        if ((void *)(arph + 1) > data_end)
            return XDP_PASS;

        /* Only handle IPv4-over-Ethernet ARP */
        if (bpf_ntohs(arph->ar_hrd) != 1 ||    /* Ethernet */
            bpf_ntohs(arph->ar_pro) != ETH_P_IP ||
            arph->ar_hln != ETH_ALEN ||
            arph->ar_pln != 4)
        {
            stats_inc(STATS_PASSED);
            return XDP_PASS;
        }

        /* Extract sender IP, target IP, and sender MAC from ARP payload */
        __be32 ip_src    = arph->ar_sip;
        __be32 ip_target = arph->ar_tip;

        // Check binding_map for sender IP 
        struct mac_addr *binding = bpf_map_lookup_elem(&binding_map, &ip_src);

        if (binding) {
            /* Binding exists: strict MAC validation  */
            if (mac_equal(arph->ar_sha, binding->addr)) {
                /* MAC matches trusted binding → PASS */
                stats_inc(STATS_ARP_PASSED);
                stats_inc(STATS_PASSED);
                return XDP_PASS;
            } else {
                /* MAC mismatch → ARP SPOOFING detected → DROP */
                stats_inc(STATS_DROPPED_ARP_SPOOF);
                return XDP_DROP;
            }
        }

        /* ── No binding exists — handle initial state / race condition ─ */

        /*Gratuitous ARP (sender IP == target IP)
         * Without a trusted binding, GARP is strictly dropped
         * as it is the primary vector for MITM cache poisoning.
         */
        if (ip_src == ip_target) {
            stats_inc(STATS_DROPPED_GARP);
            return XDP_DROP;
        }

        /* Rate-limited acceptance for unknown ARP
         * Allow a small threshold of packets for initial network
         * discovery (DHCP hasn't completed yet).
         */
        __u64 *counter = bpf_map_lookup_elem(&rate_limit_map, &ip_src);
        if (counter) {
            __u64 cnt = __sync_add_and_fetch(counter, 1);
            if (cnt > RATE_LIMIT) {
                stats_inc(STATS_DROPPED_RATE_LIMIT);
                return XDP_DROP;
            }
        } else {
            __u64 init_val = 1;
            bpf_map_update_elem(&rate_limit_map, &ip_src, &init_val, BPF_ANY);
        }

        stats_inc(STATS_ARP_PASSED);
        stats_inc(STATS_PASSED);
        return XDP_PASS;
    }

    // All other EtherTypes (IPv6, etc.) — PASS 
    stats_inc(STATS_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
