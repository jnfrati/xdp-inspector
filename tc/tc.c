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

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB buffer
} egress_packet_events SEC(".maps");


// xdp/tc.c - new file for TC program
SEC("tc")
int tc_egress_observer(struct __sk_buff *skb) {
	struct hdr_cursor nh;
	
	nh.pos = (void *)(long)skb->data;

	struct ethhdr *ethh;
	int eth_proto = parse_ethhdr(&nh, (void *)(long)skb->data_end, &ethh);
	if (eth_proto < 0) {
		const char fmt_str2[] = "Failed to parse Ethernet header %d\n";
		bpf_trace_printk(fmt_str2, sizeof(fmt_str2), skb->data_end);
		goto skip;
	}

	struct packet_event event = {
		.direction = PACKET_DIRECTION_OUT,
	};

	int ip_proto = -1;
	switch (eth_proto)
	{
	case bpf_htons(ETH_P_IP):

		if (parse_event_from_ipv4(&nh, (void *)(long)skb->data_end, &event) < 0) {
			goto skip;
		}
		break;
	case bpf_htons(ETH_P_IPV6):
		if (parse_event_from_ipv6(&nh, (void *)(long)skb->data_end, &event) < 0) {
			goto skip;
		}
		break;
	default:
		const char fmt_str2[] = "Unknown Ethernet type %d\n";
		bpf_trace_printk(fmt_str2, sizeof(fmt_str2), eth_proto);
		goto skip;
	}

    bpf_ringbuf_output(&egress_packet_events, &event, sizeof(event), 0);
        
skip:
    return 0;
}