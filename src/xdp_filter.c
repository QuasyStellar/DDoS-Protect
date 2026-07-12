#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#endif


#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

// Statistics Map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// Stat IDs
#define STAT_GEO_DROP 0
#define STAT_RATE_LIMIT_DROP 1
#define STAT_TCP_INVALID 2
#define STAT_UDP_INVALID 3
#define STAT_GLOBAL_UDP_DROP 4

static __always_inline void record_stat(__u32 stat_id) {
    __u64 *value = bpf_map_lookup_elem(&stats_map, &stat_id);
    if (value) {
        *value += 1;
    }
}

#ifndef RATE_LIMIT_PPS
#define RATE_LIMIT_PPS 100000
#endif
#ifndef GLOBAL_UDP_PPS
#define GLOBAL_UDP_PPS 100000
#endif
#define RATE_LIMIT_WINDOW_NS 1000000000ULL

struct rate_value {
    __u64 last_time;
    __u64 count;
};

// Rate Limit Map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct rate_value);
} rate_limit_map SEC(".maps");

// IP Spoofing Bloom Filter Map
struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, 1000000);
    __type(value, __u32);
} ip_bloom_map SEC(".maps");

// Global UDP Rate Limit Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_value);
} global_udp_rate_map SEC(".maps");

// Port-Specific UDP Rate Limit Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_value);
} port_udp_rate_map SEC(".maps");

// Geo-Blocking LPM Trie Map
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 ipv4;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 500000);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} geo_map SEC(".maps");


SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    int ip_hlen = iph->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr)) return XDP_PASS;

    void *l4_hdr = (void *)iph + ip_hlen;
    if (l4_hdr > data_end) return XDP_PASS;

    __u32 src_ip = iph->saddr;

    // 1. Geo-Blocking (LPM Trie lookup)
    struct ipv4_lpm_key geo_key = { .prefixlen = 32, .ipv4 = src_ip };
    __u8 *blocked = bpf_map_lookup_elem(&geo_map, &geo_key);
    if (blocked && *blocked == 1) {
        record_stat(STAT_GEO_DROP);
        return XDP_DROP;
    }

    // 2. Dynamic Rate Limiting (SYN and UDP)
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        
        // Only inspect L4 headers if this is the first fragment
        if (!(__builtin_bswap16(iph->frag_off) & IP_OFFSET)) {
            // Protocol specific basic drops
            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = (struct tcphdr *)l4_hdr;
                if ((void *)(tcph + 1) > data_end) return XDP_PASS;
                if (tcph->urg && tcph->psh && tcph->fin) {
                    record_stat(STAT_TCP_INVALID);
                    return XDP_DROP;
                }
                if (!tcph->syn && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->ack && !tcph->urg) {
                    record_stat(STAT_TCP_INVALID);
                    return XDP_DROP;
                }
                if (tcph->syn && tcph->fin) {
                    record_stat(STAT_TCP_INVALID);
                    return XDP_DROP;
                }
                
                // Only rate limit SYN packets for TCP
                if (!tcph->syn) return XDP_PASS;
            }
            if (iph->protocol == IPPROTO_UDP) {
                __u64 now = bpf_ktime_get_ns();
                // Apply Global UDP Limit
                __u32 global_key = 0;
                struct rate_value *g_val = bpf_map_lookup_elem(&global_udp_rate_map, &global_key);
                if (g_val) {
                    if (now - g_val->last_time > RATE_LIMIT_WINDOW_NS) {
                        g_val->count = 1;
                        g_val->last_time = now;
                    } else {
                        __sync_fetch_and_add(&g_val->count, 1);
                        if (g_val->count > GLOBAL_UDP_PPS) {
                            record_stat(STAT_GLOBAL_UDP_DROP);
                            return XDP_DROP;
                        }
                    }
                }

                struct udphdr *udph = (struct udphdr *)l4_hdr;
                if ((void *)(udph + 1) > data_end) return XDP_PASS;
                if (udph->source == 0 || udph->dest == 0) {
                    record_stat(STAT_UDP_INVALID);
                    return XDP_DROP;
                }

                // Apply Port-Specific UDP Limit
                __u32 dest_port = bpf_htons(udph->dest);
                struct rate_value *p_val = bpf_map_lookup_elem(&port_udp_rate_map, &dest_port);
                if (p_val) {
                    if (now - p_val->last_time > RATE_LIMIT_WINDOW_NS) {
                        p_val->count = 1;
                        p_val->last_time = now;
                    } else {
                        __sync_fetch_and_add(&p_val->count, 1);
                        // Default port limit: 100k for 443 (VPN), 1000 for others
                        __u32 limit = (dest_port == 443 || dest_port == 8443) ? GLOBAL_UDP_PPS : 1000;
                        if (p_val->count > limit) {
                            record_stat(STAT_GLOBAL_UDP_DROP); // Reuse stat for simplicity
                            return XDP_DROP;
                        }
                    }
                }
            }
        } // End of L4 inspection

        // Apply Rate Limit with Bloom Filter
        __u64 now = bpf_ktime_get_ns();
        long err = bpf_map_peek_elem(&ip_bloom_map, &src_ip);
        if (err == 0) {
            // IP is in Bloom Filter (has sent at least 1 packet before)
            struct rate_value *val = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
            if (val) {
                if (now - val->last_time > RATE_LIMIT_WINDOW_NS) {
                    val->count = 1;
                    val->last_time = now;
                } else {
                    __sync_fetch_and_add(&val->count, 1);
                    if (val->count > RATE_LIMIT_PPS) {
                        record_stat(STAT_RATE_LIMIT_DROP);
                        return XDP_DROP;
                    }
                }
            } else {
                struct rate_value new_val = { .last_time = now, .count = 1 };
                bpf_map_update_elem(&rate_limit_map, &src_ip, &new_val, BPF_ANY);
            }
        } else {
            // First time seeing this IP: Push to bloom filter but DO NOT add to LRU map yet.
            // This absorbs massive random IP spoofing without thrashing the LRU map.
            bpf_map_push_elem(&ip_bloom_map, &src_ip, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
