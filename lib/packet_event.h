#ifndef __PACKET_EVENT_H
#define __PACKET_EVENT_H

#include <linux/bpf.h>

const int PACKET_DIRECTION_IN = 0, PACKET_DIRECTION_OUT = 1;


struct ip_addr {
    __u8 family;  // AF_INET or AF_INET6
    union {
        __be32 v4_addr;           // IPv4 address (4 bytes)
        __be32 v6_addr[4];        // IPv6 address (16 bytes as 4 x 32-bit)
        // Alternative: __u8 v6_addr[16];
    } addr;
} __attribute__((packed));

struct packet_event {
	struct ip_addr src_ip;
	struct ip_addr dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8  protocol;
	__be32 packet_len;
    __u8 direction;
} __attribute__((packed));


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



#endif // __PACKET_EVENT_H