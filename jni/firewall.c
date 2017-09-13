#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>

#ifdef __linux__
#define __BSD_VISIBLE 1
#define __packed    __attribute__((__packed__))
#define __aligned(x)    __attribute__((__aligned__(x)))
#include <bsd/queue.h>
#include <bsdinet/ip.h>
#include <bsdinet/ip6.h>
#include <bsdinet/udp.h>
#include <bsdinet/tcp.h>
#endif

#ifndef __BSD_VISIBLE
#include <sys/queue.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#endif

#include <base_link.h>
#include <bsdinet/tcpup.h>

typedef unsigned char uint8_t;

typedef struct ip nat_iphdr_t;
typedef struct tcphdr nat_tcphdr_t;
typedef struct udphdr nat_udphdr_t;
typedef struct ip6_hdr nat_ip6hdr_t;

#define VERSION_IPV4 4
#define VERSION_IPV6 6

ssize_t tcp_frag_rst(nat_tcphdr_t *th, uint8_t *packet);

int check_blocked(int tunfd, unsigned char *packet, size_t len)
{
    nat_iphdr_t *ip;

    nat_ip6hdr_t *ip6;
    nat_tcphdr_t *th, h1;
    nat_udphdr_t *uh, u1;

    ip = (nat_iphdr_t *)packet;

    if (ip->ip_v != VERSION_IPV4) {
		return 0;
	}

	if (ip->ip_p == IPPROTO_UDP) {
		uh = (nat_udphdr_t *)(ip + 1);
		switch(htons(uh->uh_dport)) {
			case 443:
				LOG_VERBOSE("block udp/443 to: %s\n", inet_ntoa(ip->ip_dst));
				return 1;

			default:
				break;
		}
	}

	if (ip->ip_p == IPPROTO_TCP) {
		th = (nat_tcphdr_t *)(ip + 1);
		switch(htons(th->th_dport)) {
			case 80:
			case 443:
				if ((th->th_flags & (TH_SYN|TH_ACK)) == TH_SYN) {
					ssize_t count = tcp_frag_rst(th, packet);
					if (count > 0) write(tunfd, packet, count);
					LOG_VERBOSE("block tcp/%d to: %s\n", htons(th->th_dport), inet_ntoa(ip->ip_dst));
					return 1;
				}

			default:
				break;
		}
	}

	return 0;
}

int check_blocked_normal(int tunfd, unsigned char *packet, size_t len)
{
    nat_iphdr_t *ip;

    nat_ip6hdr_t *ip6;
    nat_tcphdr_t *th, h1;
    nat_udphdr_t *uh, u1;

    ip = (nat_iphdr_t *)packet;

    if (ip->ip_v != VERSION_IPV4) {
		return 0;
	}

	if (ip->ip_p == IPPROTO_UDP) {
		uh = (nat_udphdr_t *)(ip + 1);
		switch(htons(uh->uh_dport)) {
			default:
				break;
		}
	}

	return 0;
}
