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

#define MAX_MAP_ENTRIES 16


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB buffer
} xdp_packet_events SEC(".maps");


/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32); // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

static __always_inline int parse_packet_event_from_tcp(struct packet_event *event, struct tcphdr *tcph, unsigned short packet_len) {
	event->src_port = tcph->source;
	event->dst_port = tcph->dest;
	event->protocol = IPPROTO_TCP;
	event->packet_len = packet_len;

	return 0;
} 

static __always_inline int parse_packet_event_from_udp(struct packet_event *event, struct udphdr *udph, unsigned short packet_len) {
	event->src_port = udph->source;
	event->dst_port = udph->dest;
	event->protocol = IPPROTO_UDP;
	event->packet_len = packet_len;

	return 0;
}

static __always_inline int parse_packet_event_from_icmp(struct packet_event *event, struct icmphdr *icmph, unsigned short packet_len) {
	event->src_port = 0;
	event->dst_port = 0;
	event->protocol = IPPROTO_ICMP;
	event->packet_len = packet_len;

	return 0;
}


static __always_inline int parse_event_from_ipv4(struct hdr_cursor *nh, void *data_end, struct packet_event *event) {

	struct iphdr *iph;

	int ip_proto = parse_iphdr(nh, data_end, &iph);	
	if (ip_proto < 0) {
		return -1;
	}

	// Set IP addresses
	event->src_ip.family = AF_INET;
	event->src_ip.addr.v4_addr = iph->saddr;
	event->dst_ip.family = AF_INET;
	event->dst_ip.addr.v4_addr = iph->daddr;

	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	switch (ip_proto)
	{
	case IPPROTO_TCP:
		if (parse_tcphdr(nh, data_end, &tcph) < 0) {
			return -1;
		}
		parse_packet_event_from_tcp(event, tcph, iph->tot_len);
		break;
	case IPPROTO_UDP:
		if (parse_udphdr(nh, data_end, &udph) < 0) {
			return -1;
		}
		parse_packet_event_from_udp(event, udph, iph->tot_len);
		break;
	case IPPROTO_ICMP:
		if (parse_icmphdr(nh, data_end, &icmph) < 0) {
			return -1;
		}
		parse_packet_event_from_icmp(event, icmph, iph->tot_len);
		break;
	default:
		event->protocol = ip_proto;
	}


	return 0;
}


static __always_inline int parse_event_from_ipv6(struct hdr_cursor *nh, void *data_end, struct packet_event *event) {

	struct ipv6hdr *ip6h;

	int ip_proto = parse_ip6hdr(nh, data_end, &ip6h);
	if (ip_proto < 0) {
		return -1;
	}

	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;

	event->src_ip.family = AF_INET6;
	__builtin_memcpy(event->src_ip.addr.v6_addr, ip6h->saddr.in6_u.u6_addr32, 16);
    
	event->dst_ip.family = AF_INET6;
	__builtin_memcpy(event->dst_ip.addr.v6_addr, ip6h->daddr.in6_u.u6_addr32, 16);


	switch (ip_proto)
	{
	case IPPROTO_TCP:
		if (parse_tcphdr(nh, data_end, &tcph) < 0) {
			return -1;
		}
		parse_packet_event_from_tcp(event, tcph, ip6h->payload_len);
		break;
	case IPPROTO_UDP:
		if (parse_udphdr(nh, data_end, &udph) < 0) {
			return -1;
		}
		parse_packet_event_from_udp(event, udph, ip6h->payload_len);
		break;
	// case IPPROTO_ICMP:
	// 	parse_icmphdr(nh, data_end, &icmph);
	// 	parse_packet_event_from_icmp(event, icmph, ip6h->payload_len);
	// 	break;
	default:
		event->protocol = ip_proto;
	}


	return 0;
}


SEC("xdp")
int xdp_packet_observer(struct xdp_md *ctx) {

	
	const char fmt_str[] = "Log lvl %d\n";

	bpf_trace_printk(fmt_str, sizeof(fmt_str), 1);
	struct hdr_cursor nh;
	
	nh.pos = (void *)(long)ctx->data;

	struct ethhdr *ethh;
	int eth_proto = parse_ethhdr(&nh, (void *)(long)ctx->data_end, &ethh);
	if (eth_proto < 0) {
		const char fmt_str2[] = "Failed to parse Ethernet header %d\n";
		bpf_trace_printk(fmt_str2, sizeof(fmt_str2), ctx->data_end);
		goto skip;
	}

	struct packet_event event = {
		.direction = PACKET_DIRECTION_IN,
	};

	int ip_proto = -1;
	switch (eth_proto)
	{
	case bpf_htons(ETH_P_IP):

		if (parse_event_from_ipv4(&nh, (void *)(long)ctx->data_end, &event) < 0) {
			goto skip;
		}
		break;
	case bpf_htons(ETH_P_IPV6):
		if (parse_event_from_ipv6(&nh, (void *)(long)ctx->data_end, &event) < 0) {
			goto skip;
		}
		break;
	default:
		const char fmt_str2[] = "Unknown Ethernet type %d\n";
		bpf_trace_printk(fmt_str2, sizeof(fmt_str2), eth_proto);
		goto skip;
	}
	
	if (event.src_ip.family != AF_INET) {
		// Only IPv4 is supported for stats map
		goto emit;
	}

	__u32 src_ip = bpf_ntohl(event.src_ip.addr.v4_addr);

	__u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &src_ip);
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u32 init_pkt_count = 1;
		bpf_map_update_elem(&xdp_stats_map, &src_ip, &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}

emit:
	bpf_trace_printk(fmt_str, sizeof(fmt_str), 5);
	bpf_ringbuf_output(&xdp_packet_events, &event, sizeof(event), 0);
	return XDP_PASS;

skip:
	bpf_trace_printk(fmt_str, sizeof(fmt_str), 6);
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}

