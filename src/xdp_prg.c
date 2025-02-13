#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

#define SYN_THRESHOLD 1000 // pac/sec limit

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__be32));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1000);
} blocked_ips SEC("maps"); // map for blocked ips

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__be32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 10000);
} pacs_count SEC("maps"); // map for pacs count by ip

SEC("xdp")
int syn_flood_detector(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *) (eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *) (ip + 1);

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __be32 src_ip = ip->saddr;

    __u32 *is_blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip); // check if ip is in hash map

    // block ips & check count
    if(tcp->syn && !tcp->ack){
        __u32 *count_of_pacs = bpf_map_lookup_elem(&pacs_count, &src_ip); // get actual count of pacs
        __u32 new_count_of_pacs = 1;

        if(count_of_pacs){
            new_count_of_pacs = *count_of_pacs + 1;
        }

        if(new_count_of_pacs > SYN_THRESHOLD){ // is max?
            __u32 block = 1;
            bpf_map_update_elem(&blocked_ips, &src_ip, &block, BPF_ANY); // block ip

            return XDP_DROP;
        }

        bpf_map_update_elem(&pacs_count, &src_ip, &new_count_of_pacs, BPF_ANY); // update count
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";