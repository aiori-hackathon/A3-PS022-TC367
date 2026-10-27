// SPDX-License-Identifier: GPL-2.0
/* Bounded IPv4/UDP/DNS parser, per-source GCRA then shared global GCRA. */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "gcra.h"
#define CFG_SRC_ON 1
#define CFG_GLOBAL_ON 2

enum counter_id {
    C_SEEN,
    C_PASS_NON_IPV4,
    C_PASS_NON_UDP,
    C_PASS_NON53,
    C_PASS_FRAGMENT,
    C_PASS_TRUNCATED,
    C_PASS_INVALID_IPV4,
    C_DNS_PASS,
    C_DROP_BAD_UDP,
    C_DROP_SHORT_DNS,
    C_DROP_SRC,
    C_DROP_GLOBAL,
    C_DROP_BUSY,
    C_DROP_STATE,
    C_COUNT
};

struct kavach_config {
    __u64 src_interval_ns;
    __u64 src_tolerance_ns;
    __u64 glob_interval_ns;
    __u64 glob_tolerance_ns;
    __u32 flags;
    __u32 pad;
};

_Static_assert(sizeof(struct kavach_config) == 40, "config must be 40 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, C_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kavach_config);
} kavach_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u64);
} src_tat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_tat SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&counters, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int finish(__u32 reason, int action)
{
    count(reason);
    return action;
}

SEC("xdp")
int kavach_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    count(C_SEEN);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return finish(C_PASS_TRUNCATED, XDP_PASS);
    /* VLAN-tagged frames, IPv6 and ARP pass unchanged. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return finish(C_PASS_NON_IPV4, XDP_PASS);

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return finish(C_PASS_TRUNCATED, XDP_PASS);

    __u32 ihl = (__u32)ip->ihl * 4;
    __u32 ip_len = bpf_ntohs(ip->tot_len);
    if (ip->version != 4 || ihl < sizeof(*ip) || ip_len < ihl)
        return finish(C_PASS_INVALID_IPV4, XDP_PASS);
    if ((void *)ip + ihl > data_end)
        return finish(C_PASS_TRUNCATED, XDP_PASS);
    if (ip->protocol != 17)
        return finish(C_PASS_NON_UDP, XDP_PASS);

    __u16 frag = bpf_ntohs(ip->frag_off);
    if (frag & 0x1fff)
        return finish(C_PASS_FRAGMENT, XDP_PASS);

    __u32 ip_payload = ip_len - ihl;
    struct udphdr *udp = (void *)ip + ihl;
    if (ip_payload < sizeof(*udp) || (void *)(udp + 1) > data_end)
        return finish(C_PASS_TRUNCATED, XDP_PASS);
    if (udp->dest != bpf_htons(53))
        return finish(C_PASS_NON53, XDP_PASS);

    __u32 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(*udp))
        return finish(C_DROP_BAD_UDP, XDP_DROP);
    if (udp_len < sizeof(*udp) + 12)
        return finish(C_DROP_SHORT_DNS, XDP_DROP);

    /* A first fragment may advertise a longer complete UDP datagram. */
    if (!(frag & 0x2000) && udp_len > ip_payload)
        return finish(C_DROP_BAD_UDP, XDP_DROP);

    /* Ethernet padding cannot supply bytes beyond the IP payload. */
    if (ip_payload < sizeof(*udp) + 12 ||
        (void *)(udp + 1) + 12 > data_end)
        return finish(C_DROP_SHORT_DNS, XDP_DROP);

    if (!(frag & 0x2000) && (void *)udp + udp_len > data_end)
        return finish(C_DROP_BAD_UDP, XDP_DROP);

    __u32 zero = 0;
    struct kavach_config *cfg = bpf_map_lookup_elem(&kavach_cfg, &zero);
    if (!cfg)
        return finish(C_DROP_STATE, XDP_DROP);
    __u32 flags = cfg->flags;
    __u64 now = bpf_ktime_get_ns();
    if (flags & CFG_SRC_ON) {
        __u32 source = ip->saddr;
        __u64 *slot = bpf_map_lookup_elem(&src_tat, &source);
        if (!slot) {
            __u64 initial = 0;
            bpf_map_update_elem(&src_tat, &source, &initial, BPF_NOEXIST);
            slot = bpf_map_lookup_elem(&src_tat, &source);
        }
        if (!slot)
            return finish(C_DROP_STATE, XDP_DROP);
        int result = gcra(slot, now, cfg->src_interval_ns, cfg->src_tolerance_ns);
        if (result == GCRA_BUSY)
            return finish(C_DROP_BUSY, XDP_DROP);
        if (result == GCRA_DROP)
            return finish(C_DROP_SRC, XDP_DROP);
    }
    if (flags & CFG_GLOBAL_ON) {
        __u64 *slot = bpf_map_lookup_elem(&global_tat, &zero);
        if (!slot)
            return finish(C_DROP_STATE, XDP_DROP);
        int result = gcra(slot, now, cfg->glob_interval_ns, cfg->glob_tolerance_ns);
        if (result == GCRA_BUSY)
            return finish(C_DROP_BUSY, XDP_DROP);
        if (result == GCRA_DROP)
            return finish(C_DROP_GLOBAL, XDP_DROP);
    }
    return finish(C_DNS_PASS, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
