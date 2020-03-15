#include "platform.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <inttypes.h>

#include "lib/libbpf/src/bpf_helpers.h"
#include "mac_helpers.c"


#define trace_printk(fmt, ...) do { \
    char _fmt[] = fmt; \
    bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
    } while (0)


#define _htonl __builtin_bswap32
#define bpf_memcpy __builtin_memcpy


struct bpf_map_def SEC("maps") v4_mac_table = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(uint32_t),   /* ipv4 address */
    .value_size = sizeof(uint64_t), /* mac address */
    .max_entries = 256,
};


SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
    return -1;
}

SEC("action")
int learn_mac(struct __sk_buff *skb)
{
    /* We will access all data through pointers to structs */
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* first we check that the packet has enough data,
     * so we can access the three different headers of ethernet and ip
     */
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return TC_ACT_UNSPEC;

    /* for easy access we re-use the kernel's struct definitions */
    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));

    /* Only actual IP packets are allowed */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    /* Let's grab the MAC address.
     * We need to copy them out, as they are 48 bits long */
    uint8_t src_mac_arr[ETH_ALEN];
    bpf_memcpy(src_mac_arr, eth->h_source, ETH_ALEN);
    uint64_t src_mac = mac2int(src_mac_arr);

    /* Let's grab the IP addresses.
     * They are 32-bit, so it is easy to access */
    uint32_t src_ip = ip->saddr;

    uintptr_t *value;
    value = bpf_map_lookup_elem(&v4_mac_table, &src_ip);

    if (value) {
        if(src_mac != *value) {
            /* Update learned IP/MAC */
            bpf_map_update_elem(&v4_mac_table, &src_ip, &src_mac, BPF_ANY);

#ifdef DEBUG
            trace_printk("[ebpf:learn_mac] new mac %d old mac %d, for IP:\n", *value, src_mac);
            trace_printk("  %d.%d\n", (src_ip & 0xFF), (src_ip >> 8) & 0xFF);
            trace_printk("      %d.%d\n", (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF);
#endif
        }

        return TC_ACT_OK;
    }

#ifdef DEBUG
    trace_printk("[ebpf:learn_mac] IP Packet, proto=%d mac=%d for IP:\n", ip->protocol, src_mac);
    trace_printk("  %d.%d\n", (src_ip & 0xFF), (src_ip >> 8) & 0xFF);
    trace_printk("      %d.%d\n", (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF);
#endif

    /* Add passively learned IP/MAC combo to the LRU map */
    bpf_map_update_elem(&v4_mac_table, &src_ip, &src_mac, BPF_ANY);

    /* Allow packet to continue */
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
