// SPDX-License-Identifier: GPL-2.0
// Ritma firewall BPF program
// Enforces deny/allow/throttle/isolate decisions based on DID pairs

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define XDP_PASS 2
#define XDP_DROP 1

#define ETH_P_IP 0x0800

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 h_proto;
};

struct iphdr {
    __u8 ihl_version;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

// Map key: (src_id, dst_id) where IDs are u32 hashes of DIDs
struct fw_key {
    __u32 src_id;
    __u32 dst_id;
};

// Map value: decision (0=allow, 1=deny, 2=throttle, 3=isolate)
// For deny-list model: presence of entry with value=1 or 3 means drop.
// Absence of entry or value=0 means allow.
struct {
    __u32 _unused;
} _ritma_fw_pairs_unused;

struct bpf_map_def SEC("maps") ritma_fw_pairs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct fw_key),
    .value_size = sizeof(__u8),
    .max_entries = 10000,
    .map_flags = 0,
};

// IP to DID ID mapping: maps IPv4 address to DID numeric ID
struct {
    __u32 _unused;
} _ip_to_did_unused;

struct bpf_map_def SEC("maps") ip_to_did = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10000,
    .map_flags = 0,
};

// Statistics counters
struct {
    __u32 _unused;
} _stats_unused;

struct bpf_map_def SEC("maps") stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
    .map_flags = 0,
};

#define STAT_TOTAL_PKTS    0
#define STAT_DROPPED_PKTS  1
#define STAT_ALLOWED_PKTS  2
#define STAT_UNKNOWN_IPS   3

static __always_inline void update_stat(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

// XDP program that enforces firewall decisions based on DID pairs
SEC("xdp")
int ritma_fw_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    update_stat(STAT_TOTAL_PKTS);

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Extract source and destination IPs
    __u32 src_ip = iph->saddr;  // Already in network byte order
    __u32 dst_ip = iph->daddr;

    // Lookup source IP → DID ID
    __u32 *src_did_id = bpf_map_lookup_elem(&ip_to_did, &src_ip);
    if (!src_did_id) {
        // Unknown source IP - allow by default (fail-open for now)
        update_stat(STAT_UNKNOWN_IPS);
        update_stat(STAT_ALLOWED_PKTS);
        return XDP_PASS;
    }

    // Lookup destination IP → DID ID
    __u32 *dst_did_id = bpf_map_lookup_elem(&ip_to_did, &dst_ip);
    if (!dst_did_id) {
        // Unknown destination IP - allow by default
        update_stat(STAT_UNKNOWN_IPS);
        update_stat(STAT_ALLOWED_PKTS);
        return XDP_PASS;
    }

    // Build firewall key from DID IDs
    struct fw_key key = {
        .src_id = *src_did_id,
        .dst_id = *dst_did_id,
    };

    // Lookup firewall decision
    __u8 *decision = bpf_map_lookup_elem(&ritma_fw_pairs, &key);
    
    if (decision) {
        // Check decision value
        if (*decision == 1 || *decision == 3) {
            // 1 = deny, 3 = isolate → DROP
            update_stat(STAT_DROPPED_PKTS);
            return XDP_DROP;
        }
        // 0 = allow, 2 = throttle → PASS (throttle not implemented yet)
    }

    // No entry or allow decision → PASS
    update_stat(STAT_ALLOWED_PKTS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
