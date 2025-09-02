//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "../lib/parsing_helpers.h"
#include "../lib/packet_event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB buffer
} egress_packet_events SEC(".maps");


// xdp/tc.c - new file for TC program
SEC("tc")
int tc_egress_observer(struct __sk_buff *skb) {
    // Similar parsing logic to your XDP program
    // but using skb instead of xdp_md
    
    struct packet_event event = {};

    if (skb->family == AF_INET) {
        event.src_ip.family = AF_INET;
        event.src_ip.addr.v4_addr = bpf_htonl(skb->local_ip4);
        event.dst_ip.family = AF_INET;
        event.dst_ip.addr.v4_addr = bpf_htonl(skb->remote_ip4);
    } else if (skb->family == AF_INET6) {
        // event.src_ip.family = AF_INET6;
        // event.src_ip.addr.v6_addr[0] = bpf_htonl(skb->local_ip6[0]);
        // event.src_ip.addr.v6_addr[1] = bpf_htonl(skb->local_ip6[1]);
        // event.src_ip.addr.v6_addr[2] = bpf_htonl(skb->local_ip6[2]);
        // event.src_ip.addr.v6_addr[3] = bpf_htonl(skb->local_ip6[3]);
        
        // event.dst_ip.family = AF_INET6;
        // event.dst_ip.addr.v6_addr[0] = bpf_htonl(skb->remote_ip6[0]);
        // event.dst_ip.addr.v6_addr[1] = bpf_htonl(skb->remote_ip6[1]);
        // event.dst_ip.addr.v6_addr[2] = bpf_htonl(skb->remote_ip6[2]);
        // event.dst_ip.addr.v6_addr[3] = bpf_htonl(skb->remote_ip6[3]);
    }

    event.direction = PACKET_DIRECTION_OUT;

    bpf_ringbuf_output(&egress_packet_events, &event, sizeof(event), 0);
        
    return 0;
}