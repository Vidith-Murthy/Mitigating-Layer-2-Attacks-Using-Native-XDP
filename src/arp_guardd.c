// SPDX-License-Identifier: GPL-2.0
/*
 * arp_guardd.c — User-Space Control Plane for XDP Layer-2 Security
 *
 * This daemon:
 *   1. Loads and attaches the XDP program to specified network interfaces
 *   2. Polls the ring buffer for mirrored DHCP packets
 *   3. Parses DHCP ACK → extracts yiaddr (IP) + chaddr (MAC)
 *   4. Updates the eBPF binding_map atomically
 *   5. Provides CLI for listing bindings, stats, and manual management
 *
 * Usage:
 *   ./arp_guardd --iface <if1> [--iface <if2> ...] [options]
 *
 * Options:
 *   --iface <name>          Network interface to attach XDP (repeatable)
 *   --list-bindings         List current IP→MAC bindings
 *   --stats                 Show current statistics
 *   --add-binding <IP> <MAC> Manually add a binding
 *   --del-binding <IP>      Remove a binding
 *   --flood-threshold <N>   Override MAC flood threshold
 *   --rate-limit <N>        Override ARP rate limit
 *   --verbose               Enable verbose logging
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "arp_guard.h"
#include "arp_guard.skel.h"   

static volatile int running = 1;
static int verbose = 0;

#define MAX_IFACES 8
#define MAX_STATIC_BINDINGS 16

static const char *stat_names[] = {
    [STATS_TOTAL_PACKETS]      = "Total Packets",
    [STATS_PASSED]             = "Packets Passed",
    [STATS_DROPPED_ARP_SPOOF]  = "ARP Spoof Drops",
    [STATS_DROPPED_GARP]       = "Gratuitous ARP Drops",
    [STATS_DROPPED_MAC_FLOOD]  = "MAC Flood Drops",
    [STATS_DROPPED_RATE_LIMIT] = "Rate Limit Drops",
    [STATS_DHCP_MIRRORED]      = "DHCP Packets Mirrored",
    [STATS_ARP_PASSED]         = "ARP Packets Passed",
};

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}


static void mac_to_str(const unsigned char *mac, char *buf, size_t buf_sz)
{
    snprintf(buf, buf_sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


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


static void time_str(char *buf, size_t sz)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", tm);
}

/* ══════════════════════════════════════════════════════════════════════
 *  DHCP Packet Parser — Algorithm 1
 *
 *  The ring buffer callback receives mirrored DHCP packets from XDP.
 *  We parse DHCP ACK messages, extract yiaddr and chaddr, and update
 *  the binding_map.
 * ══════════════════════════════════════════════════════════════════════ */

static int binding_map_fd = -1;


 /* parse_dhcp_options() — Walk DHCP options to find message type.
  Returns the DHCP message type, or -1 on failure.*/
 
static int parse_dhcp_msg_type(const unsigned char *options, int options_len)
{
    int i = 0;
    while (i < options_len) {
        unsigned char opt_code = options[i];

        if (opt_code == DHCP_OPT_PAD) {
            i++;
            continue;
        }
        if (opt_code == DHCP_OPT_END)
            break;

        if (i + 1 >= options_len)
            break;

        unsigned char opt_len = options[i + 1];

        if (opt_code == DHCP_OPT_MSG_TYPE) {
            if (opt_len >= 1 && i + 2 < options_len)
                return options[i + 2];
        }

        i += 2 + opt_len;
    }
    return -1;
}


 // Ring buffer callback — called for each DHCP packet mirrored from XDP.
static int handle_dhcp_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    struct dhcp_event *evt = data;

    if (data_sz < sizeof(struct dhcp_event))
        return 0;

    unsigned int pkt_len = evt->pkt_len;
    unsigned char *pkt = evt->pkt_data;

    /* Minimum: Ethernet(14) + IP(20) + UDP(8) + DHCP header(236) + magic(4) */
    if (pkt_len < 14 + 20 + 8 + 236 + 4)
        return 0;

    /* Skip Ethernet header */
    unsigned char *ip_hdr = pkt + 14;
    int ip_hdr_len = (ip_hdr[0] & 0x0f) * 4;

    /* Skip IP + UDP headers */
    unsigned char *dhcp_start = ip_hdr + ip_hdr_len + 8;
    int dhcp_offset = (dhcp_start - pkt);
    int dhcp_len = pkt_len - dhcp_offset;

    if (dhcp_len < 240)  /* minimum DHCP packet with magic cookie */
        return 0;

    /* Cast to DHCP packet structure */
    struct dhcp_packet *dhcp = (struct dhcp_packet *)dhcp_start;

    /* Verify magic cookie */
    if (ntohl(dhcp->magic) != DHCP_MAGIC_COOKIE)
        return 0;

    /* Parse options to find message type */
    unsigned char *options = dhcp_start + 240;  /* After fixed header + magic */
    int options_len = dhcp_len - 240;

    int msg_type = parse_dhcp_msg_type(options, options_len);

    char ts[32];
    time_str(ts, sizeof(ts));

    if (msg_type == DHCP_MSG_ACK) {
        /*
         * DHCP ACK received — Algorithm 1 binding update:
         *   Extract IP ← yiaddr
         *   Extract MAC ← chaddr
         *   binding_map[IP] ← MAC
         */
        __be32 assigned_ip = dhcp->yiaddr;
        struct mac_addr client_mac;
        memcpy(client_mac.addr, dhcp->chaddr, 6);

        /* Update binding map atomically */
        int err = bpf_map_update_elem(binding_map_fd, &assigned_ip,
                                       &client_mac, BPF_ANY);

        char ip_str[INET_ADDRSTRLEN];
        char mac_str[18];
        inet_ntop(AF_INET, &assigned_ip, ip_str, sizeof(ip_str));
        mac_to_str(client_mac.addr, mac_str, sizeof(mac_str));

        if (err == 0) {
            printf("[%s] BINDING ADDED: %s → %s\n", ts, ip_str, mac_str);
        } else {
            fprintf(stderr, "[%s] ERROR: Failed to add binding %s → %s: %s\n",
                    ts, ip_str, mac_str, strerror(errno));
        }
    } else if (msg_type == DHCP_MSG_RELEASE) {
        /* On DHCP Release, remove the binding */
        __be32 client_ip = dhcp->ciaddr;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_ip, ip_str, sizeof(ip_str));

        bpf_map_delete_elem(binding_map_fd, &client_ip);
        printf("[%s] BINDING REMOVED: %s (DHCP Release)\n", ts, ip_str);

    } else if (verbose && msg_type >= 0) {
        const char *type_names[] = {
            [1] = "DISCOVER", [2] = "OFFER", [3] = "REQUEST",
            [4] = "DECLINE",  [5] = "ACK",   [6] = "NAK",
            [7] = "RELEASE",  [8] = "INFORM",
        };
        const char *name = (msg_type >= 1 && msg_type <= 8)
                               ? type_names[msg_type] : "UNKNOWN";
        printf("[%s] DHCP %s observed (no action)\n", ts, name);
    }

    return 0;
}


 // CLI: List Bindings

static void list_bindings(int map_fd)
{
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf(  "║          Current IP → MAC Bindings               ║\n");
    printf(  "╠══════════════════════════════════════════════════╣\n");

    __be32 key = 0, next_key;
    struct mac_addr value;
    int count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            char ip_str[INET_ADDRSTRLEN];
            char mac_str[18];
            inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str));
            mac_to_str(value.addr, mac_str, sizeof(mac_str));
            printf("║  %-16s  →  %-18s      ║\n", ip_str, mac_str);
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("║          (no bindings currently)                ║\n");
    }
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("Total bindings: %d\n\n", count);
}


static void show_stats(int map_fd)
{
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf(  "║           XDP Layer-2 Security Statistics        ║\n");
    printf(  "╠══════════════════════════════════════════════════╣\n");

    /* stats_map is PERCPU, so we sum across CPUs */
    int nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get CPU count\n");
        return;
    }

    __u64 values[nr_cpus];

    for (__u32 i = 0; i < STATS_MAX; i++) {
        if (bpf_map_lookup_elem(map_fd, &i, values) != 0)
            continue;

        __u64 total = 0;
        for (int cpu = 0; cpu < nr_cpus; cpu++)
            total += values[cpu];

        printf("║  %-28s  %12llu     ║\n", stat_names[i], total);
    }

    printf("╚══════════════════════════════════════════════════╝\n\n");
}

static void usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("XDP-based Layer-2 Security Daemon\n");
    printf("Implements DHCP snooping and binding map management.\n\n");
    printf("Options:\n");
    printf("  --iface <name>            Interface to attach XDP (repeatable)\n");
    printf("  --static-binding <IP> <MAC> Pre-load a binding at startup (repeatable)\n");
    printf("  --list-bindings           List current IP→MAC bindings and exit\n");
    printf("  --stats                   Show statistics and exit\n");
    printf("  --add-binding <IP> <MAC>  Manually add a binding and exit\n");
    printf("  --del-binding <IP>        Remove a binding and exit\n");
    printf("  --flood-threshold <N>     Set flood threshold (default: %d)\n", FLOOD_THRESHOLD);
    printf("  --rate-limit <N>          Set ARP rate limit (default: %d)\n", RATE_LIMIT);
    printf("  --verbose                 Verbose logging\n");
    printf("  --help                    Show this help\n");
}


int main(int argc, char **argv)
{
    const char *ifaces[MAX_IFACES];
    int n_ifaces = 0;
    int mode_list = 0, mode_stats = 0;
    const char *add_ip = NULL, *add_mac = NULL, *del_ip = NULL;
    const char *static_ips[MAX_STATIC_BINDINGS];
    const char *static_macs[MAX_STATIC_BINDINGS];
    int n_static = 0;
    int i;
    struct ring_buffer *rb = NULL;

    
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            if (n_ifaces < MAX_IFACES)
                ifaces[n_ifaces++] = argv[++i];
        } else if (strcmp(argv[i], "--list-bindings") == 0) {
            mode_list = 1;
        } else if (strcmp(argv[i], "--stats") == 0) {
            mode_stats = 1;
        } else if (strcmp(argv[i], "--add-binding") == 0 && i + 2 < argc) {
            add_ip = argv[++i];
            add_mac = argv[++i];
        } else if (strcmp(argv[i], "--del-binding") == 0 && i + 1 < argc) {
            del_ip = argv[++i];
        } else if (strcmp(argv[i], "--static-binding") == 0 && i + 2 < argc) {
            if (n_static < MAX_STATIC_BINDINGS) {
                static_ips[n_static] = argv[++i];
                static_macs[n_static] = argv[++i];
                n_static++;
            }
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

   
    struct arp_guard_bpf *skel = arp_guard_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton: %s\n",
                strerror(errno));
        return 1;
    }

    /* Load BPF programs and maps */
    int err = arp_guard_bpf__load(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF program: %s\n",
                strerror(-err));
        arp_guard_bpf__destroy(skel);
        return 1;
    }

    /* Get map file descriptors */
    binding_map_fd = bpf_map__fd(skel->maps.binding_map);
    int stats_map_fd = bpf_map__fd(skel->maps.stats_map);

    //  Handle one-shot CLI commands 
    if (mode_list) {
        list_bindings(binding_map_fd);
        arp_guard_bpf__destroy(skel);
        return 0;
    }

    if (mode_stats) {
        show_stats(stats_map_fd);
        arp_guard_bpf__destroy(skel);
        return 0;
    }

    if (add_ip && add_mac) {
        struct in_addr addr;
        if (inet_pton(AF_INET, add_ip, &addr) != 1) {
            fprintf(stderr, "Invalid IP address: %s\n", add_ip);
            arp_guard_bpf__destroy(skel);
            return 1;
        }
        struct mac_addr mac;
        if (parse_mac(add_mac, mac.addr) != 0) {
            fprintf(stderr, "Invalid MAC address: %s\n", add_mac);
            arp_guard_bpf__destroy(skel);
            return 1;
        }
        err = bpf_map_update_elem(binding_map_fd, &addr.s_addr, &mac, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to add binding: %s\n", strerror(errno));
        } else {
            printf("Binding added: %s → %s\n", add_ip, add_mac);
        }
        arp_guard_bpf__destroy(skel);
        return err ? 1 : 0;
    }

    if (del_ip) {
        struct in_addr addr;
        if (inet_pton(AF_INET, del_ip, &addr) != 1) {
            fprintf(stderr, "Invalid IP address: %s\n", del_ip);
            arp_guard_bpf__destroy(skel);
            return 1;
        }
        err = bpf_map_delete_elem(binding_map_fd, &addr.s_addr);
        if (err) {
            fprintf(stderr, "Failed to delete binding: %s\n", strerror(errno));
        } else {
            printf("Binding removed: %s\n", del_ip);
        }
        arp_guard_bpf__destroy(skel);
        return err ? 1 : 0;
    }

    /* ── Pre-load static bindings (for devices with static IPs like DHCP server) ─ */
    for (i = 0; i < n_static; i++) {
        struct in_addr addr;
        if (inet_pton(AF_INET, static_ips[i], &addr) != 1) {
            fprintf(stderr, "WARNING: Invalid static binding IP: %s\n", static_ips[i]);
            continue;
        }
        struct mac_addr mac;
        if (parse_mac(static_macs[i], mac.addr) != 0) {
            fprintf(stderr, "WARNING: Invalid static binding MAC: %s\n", static_macs[i]);
            continue;
        }
        err = bpf_map_update_elem(binding_map_fd, &addr.s_addr, &mac, BPF_ANY);
        if (err == 0) {
            printf("✓ Static binding: %s → %s\n", static_ips[i], static_macs[i]);
        } else {
            fprintf(stderr, "WARNING: Failed to add static binding %s: %s\n",
                    static_ips[i], strerror(errno));
        }
    }

    // Daemon mode: attach to interfaces and run
    if (n_ifaces == 0) {
        fprintf(stderr, "ERROR: No interfaces specified. Use --iface <name>\n");
        usage(argv[0]);
        arp_guard_bpf__destroy(skel);
        return 1;
    }

    /* Attach XDP program to each interface */
    int prog_fd = bpf_program__fd(skel->progs.arp_guard);

    for (i = 0; i < n_ifaces; i++) {
        unsigned int ifindex = if_nametoindex(ifaces[i]);
        if (ifindex == 0) {
            fprintf(stderr, "ERROR: Interface '%s' not found\n", ifaces[i]);
            goto cleanup;
        }

        /* Use XDP_FLAGS_DRV_MODE for native XDP on VirtIO (virtio_net) */
        LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, &attach_opts);
        if (err) {
            fprintf(stderr, "WARNING: Native XDP attach failed on %s (%s), "
                    "falling back to SKB mode\n", ifaces[i], strerror(-err));

            err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, &attach_opts);
            if (err) {
                fprintf(stderr, "ERROR: Failed to attach XDP to %s: %s\n",
                        ifaces[i], strerror(-err));
                goto cleanup;
            }
            printf("✓ XDP attached to %s (SKB/generic mode)\n", ifaces[i]);
        } else {
            printf("✓ XDP attached to %s (native/driver mode — virtio_net)\n", ifaces[i]);
        }
    }

    // Set up ring buffer polling
    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events_rb), handle_dhcp_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: Failed to create ring buffer: %s\n",
                strerror(errno));
        goto cleanup;
    }

    // Install signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Main event loop
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║   XDP Layer-2 Security Daemon — Active               ║\n");
    printf("║   Monitoring DHCP traffic for binding updates...     ║\n");
    printf("║   Press Ctrl+C to stop                               ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║   Interfaces: ");
    for (i = 0; i < n_ifaces; i++)
        printf("%s%s", ifaces[i], i < n_ifaces - 1 ? ", " : "");
    printf("%*s║\n", (int)(39 - (n_ifaces > 1 ? 16 : strlen(ifaces[0]))), "");
    printf("║   Flood Threshold: %-33d║\n", FLOOD_THRESHOLD);
    printf("║   ARP Rate Limit:  %-33d║\n", RATE_LIMIT);
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    while (running) {
        err = ring_buffer__poll(rb, 100 /* timeout_ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Ring buffer poll error: %d\n", err);
            break;
        }
    }

    printf("\nShutting down...\n");

    show_stats(stats_map_fd);
    list_bindings(binding_map_fd);

cleanup:

    for (i = 0; i < n_ifaces; i++) {
        unsigned int ifindex = if_nametoindex(ifaces[i]);
        if (ifindex > 0) {
            LIBBPF_OPTS(bpf_xdp_attach_opts, detach_opts);
            bpf_xdp_detach(ifindex, 0, &detach_opts);
            printf("✓ XDP detached from %s\n", ifaces[i]);
        }
    }

    if (rb)
        ring_buffer__free(rb);
    arp_guard_bpf__destroy(skel);

    printf("Done.\n");
    return 0;
}
