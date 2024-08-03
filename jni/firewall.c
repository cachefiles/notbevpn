#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <config.h>
#include <base_link.h>
#include <bsdinet/tcpup.h>
#include <router.h>

#ifndef ENOBUFS
#define ENOBUFS -111
#endif

typedef unsigned char uint8_t;

typedef struct ip nat_iphdr_t;
typedef struct tcphdr nat_tcphdr_t;
typedef struct udphdr nat_udphdr_t;
typedef struct ip6_hdr nat_ip6hdr_t;

#define VERSION_IPV4 4
#define VERSION_IPV6 6

ssize_t tcp_frag_rst(nat_tcphdr_t *th, uint8_t *packet);
int check_blocked_silent(int tunfd, int dnsfd, char *packet, size_t len, time_t *limited);
int check_blocked_normal(int tunfd, int dnsfd, char *packet, size_t len, int *failure_try);

#define CPTR(ptr) ((char *)(ptr))
static const char *_ntop_v6(void *ptr)
{
	static char buf[64];
    return inet_ntop(AF_INET6, ptr, buf, sizeof(buf));
}

#define ntop_v6(a) _ntop_v6(&a)

int set_linkfailure();
int is_tethering_dns(struct in_addr);
int resolv_invoke(int dnsfd, char *packet, size_t len, struct sockaddr_in6 *dest, struct sockaddr_in6 *from, int nswrap);
static char _tailing[3200];
const char *hexdump(void *buf, size_t len)
{
    int i, ch = 0;
    uint8_t *p = (uint8_t *)buf;
    char *tailing = _tailing;
    const char *limit = _tailing + sizeof(_tailing);
    char map[] = "0123456789abcdef";

    for (i = 0; i < len; i++) {
        if (tailing < limit) {
            ch = *p++;
            *tailing++ = map[(ch >> 4) & 0xf];
        }

        if (tailing < limit) {
            *tailing++ = map[ch & 0xf];
        }
    }

    if (tailing < limit) {
        *tailing++ = 0;
    }

    return _tailing;
}


static const int _firewall_always_off = 1;

static uint16_t update_cksum(uint16_t old, int delta)
{
    int acc;

    acc = delta;
    acc += old;

    if (acc < 0) {
        acc  = -acc;
        acc  = (acc >> 16) + (acc & 0xffff);
        acc += (acc >> 16);
        return ~acc;
    } else {
        acc  = (acc >> 16) + (acc & 0xffff);
        acc += (acc >> 16);
        return acc;
    }
}

static void dump_packet(char *packet, size_t len)
{
    nat_ip6hdr_t *ip6 = (nat_ip6hdr_t *)packet;
    if ((ip6->ip6_vfc & 0xf0) != (VERSION_IPV6 << 4)) {
        return ;
    }

    if (ip6->ip6_nxt == IPPROTO_TCP) {
        return ;
    }

    if (ip6->ip6_nxt == IPPROTO_UDP) {
        return ;
    }

    LOG_DEBUG("dump_packet: %s\n", hexdump(packet, len));
}

int check_blocked_silent(int tunfd, int dnsfd, char *packet, size_t len, time_t *limited)
{
	int ignore = 0;
	ssize_t count; 
	time_t current;
	nat_ip6hdr_t *ip6;

	nat_tcphdr_t *th;
	nat_udphdr_t *uh;

	ip6 = (nat_ip6hdr_t *)packet;

    if ((ip6->ip6_vfc & 0xf0) != (VERSION_IPV6 << 4)) {
		dump_packet(packet, len);
		return 0;
	}

	if (ip6->ip6_nxt == IPPROTO_UDP) {
		uh = (nat_udphdr_t *)(ip6 + 1);
		switch(htons(uh->uh_dport)) {
			case 443:
				LOG_DEBUG("block!%d udp/443 to: :%d -> %s\n", tunfd, htons(uh->uh_sport), ntop_v6(ip6->ip6_dst));
				return _firewall_always_off == 0;

			case 53:
				LOG_DEBUG("convert!%d udp/53 to: :%d -> %s\n", tunfd, htons(uh->uh_sport), ntop_v6(ip6->ip6_dst));
				return check_blocked_normal(tunfd, dnsfd, packet, len, &ignore);

			default:
				break;
		}
	}

	return 0;
}

#define tun_write write

int check_blocked_normal(int tunfd, int dnsfd, char *packet, size_t len, int *failure_try)
{
	nat_ip6hdr_t *ip6;
	nat_udphdr_t *uh;

	int nswrap, istether = 0;
	struct sockaddr_in6 dest;
	struct sockaddr_in6 from;

	ip6 = (nat_ip6hdr_t *)packet;

    if ((ip6->ip6_vfc & 0xf0) != (VERSION_IPV6 << 4)) {
		dump_packet(packet, len);
		return 0;
	}

	const uint8_t nat64_prefix[16] = {
		0, 0x64, 0xff, 0x9b, 0
	};

	if (ip6->ip6_nxt == IPPROTO_UDP) {
		uh = (nat_udphdr_t *)(ip6 + 1);

		switch(htons(uh->uh_dport)) {
			case 53:
				
				nswrap = !memcmp(&ip6->ip6_dst, nat64_prefix, 8);
#ifdef __ANDROID__
				istether = 0; // is_tethering_dns(ip6->ip6_dst);
#endif
				set_ack_type(ACK_TYPE_NEED);
				if ((nswrap || istether) &&
						CPTR(uh + 1) < (packet + len)) {
					dest.sin6_family = AF_INET6;
					dest.sin6_port   = uh->uh_dport;
					dest.sin6_addr   = ip6->ip6_dst;

					from.sin6_family = AF_INET6;
					from.sin6_port   = uh->uh_sport;
					from.sin6_addr   = ip6->ip6_src;

					int code = resolv_invoke(dnsfd, CPTR(uh + 1), packet + len - CPTR(uh + 1), &dest, &from, istether);
					if (-100 == code) {
						return 0;
					} else if (-1 == code) {
						if (errno != ENOBUFS && errno != EAGAIN) {
							set_linkfailure();
						}
					}
					(*failure_try)++;
					return 1;
				}

			default:
				break;
		}
	}

	return 0;
}
