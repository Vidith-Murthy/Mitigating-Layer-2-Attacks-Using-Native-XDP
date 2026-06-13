/* SPDX-License-Identifier: GPL-2.0
 *
 * arp_guard.h — Shared definitions for XDP Layer-2 Security System
 *
 * Implements the data structures and constants described in:
 *   "Mitigating Layer-2 Attacks Using Native XDP and its Performance Implications"
 *
 * This header is shared between the XDP/BPF kernel program and the
 * user-space control plane daemon.
 */

#ifndef ARP_GUARD_H
#define ARP_GUARD_H

/* ── Tuneable Thresholds ─────────────────────────────────────────────────
 *
 * FLOOD_THRESHOLD  – Maximum number of unique, unverified MAC addresses
 *                    allowed in the mac_tracking_map before the system
 *                    assumes a MAC flooding attack and begins dropping
 *                    packets.  (Algorithm 5/6 Phase 1)
 *
 * RATE_LIMIT       – Maximum number of unverified ARP requests from a
 *                    single unknown IP before packets are dropped.
 *                    Bridges the DHCP binding-update gap.  (Algorithm 4)
 *
 * These can be overridden at compile time:
 *   clang -DFLOOD_THRESHOLD=200 ...
 */
#ifndef FLOOD_THRESHOLD
#define FLOOD_THRESHOLD 100
#endif

#ifndef RATE_LIMIT
#define RATE_LIMIT 5
#endif

/* Ring buffer size for mirroring DHCP packets to user-space (256 KB) */
#define RINGBUF_SIZE (256 * 1024)

/* Maximum entries in the binding map (IP → MAC) */
#define MAX_BINDINGS 1024

/* Maximum entries in the LRU MAC tracking map */
#define MAX_MAC_ENTRIES 4096

/* Maximum entries in the rate-limit tracking map */
#define MAX_RATE_ENTRIES 1024

// Statistics Counters (indices into stats_map) 
enum stats_index {
    STATS_TOTAL_PACKETS = 0,    
    STATS_PASSED,               
    STATS_DROPPED_ARP_SPOOF,     
    STATS_DROPPED_GARP,          
    STATS_DROPPED_MAC_FLOOD,     
    STATS_DROPPED_RATE_LIMIT,   
    STATS_DHCP_MIRRORED,         
    STATS_ARP_PASSED,            
    STATS_MAX                    
};

// MAC Address Container 
/*
 * vmlinux.h (included by BPF programs) already defines struct mac_addr.
 * Only define it here for user-space builds.
 */
#ifndef HAVE_VMLINUX_H
struct mac_addr {
    unsigned char addr[6];
} __attribute__((packed));
#endif

// Ring Buffer Event Structure (DHCP packet mirror)
#define MAX_DHCP_PACKET_SIZE 1500

struct dhcp_event {
    unsigned int  pkt_len;                      /* Actual packet length */
    unsigned char pkt_data[MAX_DHCP_PACKET_SIZE]; /* Full packet copy */
};

// DHCP Protocol Constants 
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

/* DHCP message types (option 53) */
#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER    2
#define DHCP_MSG_REQUEST  3
#define DHCP_MSG_DECLINE  4
#define DHCP_MSG_ACK      5
#define DHCP_MSG_NAK      6
#define DHCP_MSG_RELEASE  7
#define DHCP_MSG_INFORM   8

/* DHCP option codes */
#define DHCP_OPT_MSG_TYPE    53
#define DHCP_OPT_END        255
#define DHCP_OPT_PAD          0


#define DHCP_MAGIC_COOKIE 0x63825363

// DHCP Packet Layout
struct dhcp_packet {
    unsigned char  op;         
    unsigned char  htype;      
    unsigned char  hlen;       
    unsigned char  hops;       
    unsigned int   xid;        
    unsigned short secs;       
    unsigned short flags;      
    unsigned int   ciaddr;     
    unsigned int   yiaddr;     
    unsigned int   siaddr;     
    unsigned int   giaddr;     
    unsigned char  chaddr[16]; 
    unsigned char  sname[64];  
    unsigned char  file[128];  
    unsigned int   magic;      
} __attribute__((packed));

#endif /* ARP_GUARD_H */
