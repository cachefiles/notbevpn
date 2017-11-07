#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <config.h>
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

#define xschg(t, a, b) do { t _t = a; a = b; b = _t; } while ( 0 )

static uint32_t _track_bits_1[65536 / 32] = {};
static uint32_t _track_bits_0[65536 / 32] = {};
static uint32_t _track_bits_2[65536 / 32] = {};

static int conntrack_tcp_nat(nat_tcphdr_t *th, char *packet, size_t len)
{
	nat_iphdr_t * ip = (nat_iphdr_t *)packet;

#if 0
	if (ip->ip_src != inet_addr("10.24.0.1")) {
		return 0;
	}

	if (ip->ip_dst == inet_addr("10.24.0.1")) {
		return 0;
	}
#endif

	uint16_t sport = htons(th->th_sport);
	uint16_t dport = htons(th->th_dport);

	if (dport > 1024) {
		/* relay -> client */
		assert (sport == 3080 || sport == 3443);
		xschg(struct in_addr, ip->ip_dst, ip->ip_src);
		th->th_sum = update_cksum(th->th_sum, th->th_sport - htons(sport - 3000));
		th->th_sport = htons(sport - 3000);

		ip->ip_sum = update_cksum(ip->ip_sum, th->th_sport - htons(sport - 3000));

		uint16_t mark = th->th_dport;
		if (th->th_flags & TH_RST) {
			int byte_index = (mark / 32);
			int bit_offset = (mark % 32);
			_track_bits_0[byte_index] &= ~(1 << bit_offset);
			_track_bits_1[byte_index] &= ~(1 << bit_offset);
		} else if (th->th_flags & TH_FIN) {
			int byte_index = (mark / 32);
			int bit_offset = (mark % 32);
			_track_bits_0[byte_index] &= ~(1 << bit_offset);
			_track_bits_2[byte_index] |= (1 << bit_offset);
		}

		return len;
	} else {
		/* client -> server */
		assert (dport == 80 || dport == 443);
		xschg(struct in_addr, ip->ip_dst, ip->ip_src);
		th->th_sum = update_cksum(th->th_sum, th->th_dport - htons(dport + 3000));
		th->th_dport = htons(dport + 3000);

		ip->ip_sum = update_cksum(ip->ip_sum, th->th_dport - htons(dport + 3000));

		uint16_t mark = th->th_sport;
		if (th->th_flags & TH_RST) {
			int byte_index = (mark / 32);
			int bit_offset = (mark % 32);
			_track_bits_0[byte_index] &= ~(1 << bit_offset);
			_track_bits_1[byte_index] &= ~(1 << bit_offset);
		} else if (th->th_flags & TH_FIN) {
			int byte_index = (mark / 32);
			int bit_offset = (mark % 32);
			_track_bits_1[byte_index] &= ~(1 << bit_offset);
			_track_bits_2[byte_index] |= (1 << bit_offset);
		}

		return len;
	}

	return 0;
}

static int conntrack_tcp_marked(uint16_t mark)
{
	int byte_index = (mark / 32);
	int bit_offset = (mark % 32);

	if (_track_bits_0[byte_index] & (1 << bit_offset)) {
		LOG_DEBUG("mark bits_0 failure: %d %d\n", mark, htons(mark));
		return 0;
	}

	if (_track_bits_1[byte_index] & (1 << bit_offset)) {
		LOG_DEBUG("mark bits_1 failure: %d %d\n", mark, htons(mark));
		return 0;
	}

	_track_bits_0[byte_index] |= (1 << bit_offset);
	_track_bits_1[byte_index] |= (1 << bit_offset);
	return 1;
}

static int conntrack_tcp_lookup(nat_iphdr_t *ip, nat_tcphdr_t *th)
{
	uint16_t mark = th->th_sport;

	int byte_index = (mark / 32);
	int bit_offset = (mark % 32);

	switch (htons(mark)) {
		case (3000 + 80):
			assert (htons(th->th_dport) > 1024);
			return 1;

		case (3000 + 443):
			assert (htons(th->th_dport) > 1024);
			return 1;
	}

	if (_track_bits_0[byte_index] & (1 << bit_offset)) {
		return 1;
	}

	if (_track_bits_1[byte_index] & (1 << bit_offset)) {
		return 1;
	}

	if (_track_bits_2[byte_index] & (1 << bit_offset)) {
		_track_bits_2[byte_index] &= ~(1 << bit_offset);
		return 1;
	}

	return 0;
}

static int conntrack_tcp_new(nat_tcphdr_t *th, char *packet, size_t len)
{
	int count;
	nat_iphdr_t * ip = (nat_iphdr_t *)packet;
	assert (htons(th->th_sport) > 1024);
	assert (htons(th->th_dport) < 1024);

	count = conntrack_tcp_nat(th, packet, len);

	if (count > 0 &&
			!conntrack_tcp_marked(th->th_sport)) {
	}

	return count;
}

int check_blocked(int tunfd, char *packet, size_t len, time_t *limited)
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
						/* time(limited); */
						break;
					}

					time(&current);
					if (*limited + 36 > current) {
						LOG_DEBUG("ignore!%d tcp/%d to: :%d -> %s\n",
								tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
						break;
					} else {
						LOG_DEBUG("reject!%d tcp/%d to: :%d -> %s\n",
								tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
						count = conntrack_tcp_new(th, packet, len);
						LOG_DEBUG("tcpnat!%d tcp/%d to: :%d -> %s, count=%d\n",
								tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst), count);
						if (count > 0) write(tunfd, packet, count);
					}

					return 1;
				} else if (conntrack_tcp_lookup(ip, th)) {
					LOG_DEBUG("continue!%d tcp/%d to: :%d -> %s\n",
							tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
					count = conntrack_tcp_nat(th, packet, len);
					if (count > 0) write(tunfd, packet, count);
					return 1;
				}

			default:
				if ((th->th_flags & (TH_SYN|TH_ACK)) == TH_SYN) {
					LOG_DEBUG("keepalive!%d tcp/%d to: :%d -> %s\n",
							tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
				} else if (conntrack_tcp_lookup(ip, th)) {
					LOG_DEBUG("continue!%d tcp/%d to: :%d -> %s\n",
							tunfd, htons(th->th_dport), htons(th->th_sport), inet_ntoa(ip->ip_dst));
					count = conntrack_tcp_nat(th, packet, len);
					if (count > 0) write(tunfd, packet, count);
					return 1;
				}
				break;
		}
	}

	return 0;
}

int check_blocked_normal(int tunfd, char *packet, size_t len)
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
