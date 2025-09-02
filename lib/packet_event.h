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


#endif // __PACKET_EVENT_H