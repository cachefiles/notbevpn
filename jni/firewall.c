#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <assert.h>

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
#include <router.h>

typedef unsigned char uint8_t;

typedef struct ip nat_iphdr_t;
typedef struct tcphdr nat_tcphdr_t;
typedef struct udphdr nat_udphdr_t;
typedef struct ip6_hdr nat_ip6hdr_t;

#define VERSION_IPV4 4
#define VERSION_IPV6 6

ssize_t tcp_frag_rst(nat_tcphdr_t *th, uint8_t *packet);

static const char _inet_prefix[] = "104.16.0.0/12 184.84.0.0/14 23.64.0.0/14 23.32.0.0/11 96.6.0.0/15 162.125.0.0/16 203.0.0.0/8 66.6.32.0/20 199.59.148.0/22 31.13.70.0/23 108.160.160.0/20 8.8.0.0/16 64.18.0.0/20 64.233.160.0/19 66.102.0.0/20 66.249.80.0/20 72.14.192.0/18 74.125.0.0/16 108.177.8.0/21 173.194.0.0/16 207.126.144.0/20 209.85.128.0/17 216.58.192.0/19 216.239.32.0/19 172.217.0.0/19";

int is_google_net(struct in_addr net)
{
	int index;
	unsigned network = 0;
	static int _is_initilize = 0;

	if (_is_initilize == 0) {
		route_restore(_inet_prefix);
		_is_initilize = 1;
	}

	return route_get(net) != NULL;
}

int check_blocked(int tunfd, unsigned char *packet, size_t len, time_t *limited)
{
	ssize_t count; 
	time_t current;
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
				LOG_DEBUG("block!%d udp/443 to: :%d -> %s\n", tunfd, htons(uh->uh_sport), inet_ntoa(ip->ip_dst));
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
					if (is_google_net(ip->ip_dst)) {
						LOG_DEBUG("active!%d tcp/%d to: :%d -> %s\n",
								tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
						time(limited);
						break;
					}

					time(&current);
					if (*limited + 18 < current) {
						LOG_DEBUG("ignore!%d tcp/%d to: :%d -> %s\n",
								tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
						break;
					} else if (*limited + 180 > current) {
						LOG_DEBUG("reject!%d tcp/%d to: :%d -> %s\n",
								tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
						count = tcp_frag_rst(th, packet);
						if (count > 0) write(tunfd, packet, count);
					} else {
						LOG_DEBUG("drop!%d tcp/%d to: :%d -> %s\n",
								tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
					}

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
