#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>

#ifdef __linux__
#define __BSD_VISIBLE 1
#define	__packed	__attribute__((__packed__))
#define	__aligned(x)	__attribute__((__aligned__(x)))
#include <bsd/queue.h>
#include <bsdinet/ip.h>
#include <bsdinet/ip6.h>
#include <bsdinet/tcp.h>
#endif

#ifndef __BSD_VISIBLE
#include <sys/queue.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#endif

#include <bsdinet/tcpup.h>

#include "portpool.h"

typedef unsigned char uint8_t;

typedef struct ip nat_iphdr_t;
typedef struct tcphdr nat_tcphdr_t;
typedef struct ip6_hdr nat_ip6hdr_t;

#define VERSION_IPV4 4
#define VERSION_IPV6 6

#define d_off(ptr, base) ((uint8_t *)(ptr) - (uint8_t *)(base))

#define CHECK_NAT_PROTOCOL(proto, expect) \
	do { if ((proto) != (expect)) return 0; } while (0)

#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))

#define CHECK_NAT_FAIL_RETURN(expr) do { if (expr); else return 0; } while (0)

#define CHECK_FLAGS(flags, want) ((flags) & (want))
#define xchg(s, d, t) { t _t = d; d = s; s = _t; } 

#define log_verbose printf
#define log_error printf

typedef struct _tcp_state_t {
	int flags;
	int pkt_sent;
	int byte_sent;

	int th_sum;
	int ip_sum;

	uint16_t th_sport;
	uint16_t th_dport;

	struct in_addr ip_dst;
	struct in_addr ip_src;

	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;

} tcp_state_t;

static port_pool_t _tcp_pool = {};

static void alloc_nat_slot(tcp_state_t *s, tcp_state_t *c, int is_ipv6, uint16_t port)
{
	int i;
	uint16_t *src, *dst;
	uint16_t *nats, *natd;

	s->ip_dst.s_addr = 0x5a5afeed;
	s->ip_src.s_addr = 0x5a5afeed;
	s->th_dport = use_nat_port(&_tcp_pool, port);
	s->th_sport = 0xfeed;

	s->th_sum = 0;
	s->ip_sum = 0;

	if (is_ipv6) {
		src = (uint16_t *)&c->ip6_src;
		dst = (uint16_t *)&c->ip6_dst;

		for (i = 0; i < 8; i++) {
			s->ip_sum += (src[i]);
			s->ip_sum += (dst[i]);
		}

		s->th_sum = s->ip_sum;
	} else {
		src = (uint16_t *)&c->ip_src;
		dst = (uint16_t *)&c->ip_dst;

		for (i = 0; i < 2; i++) {
			s->ip_sum += (src[i]);
			s->ip_sum += (dst[i]);
		}

		s->th_sum = s->ip_sum;
	}

	s->th_sum += (c->th_sport - s->th_dport);
	s->th_sum += (c->th_dport - s->th_sport);

	c->ip_sum = -s->ip_sum;
	c->th_sum = -s->th_sum;
	return;
}

#define DIRECT_CLIENT_TO_SERVER 0x01
#define DIRECT_SERVER_TO_CLIENT 0x02

typedef struct _nat_conntrack_t {
	int is_ipv6;
	int last_dir;
	int tcp_wscale;
	time_t last_alive;

	int track_len;
	int track_round;
	char track_buf[80];

	tcp_state_t c; /* client side tcp state */
	tcp_state_t s; /* server side tcp state */
	LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

typedef struct _nat_conntrack_ops {
	nat_conntrack_t * (*lookup)(uint8_t *packet, uint16_t sport, uint16_t dport);
	nat_conntrack_t * (*newconn)(uint8_t *packet, uint16_t sport, uint16_t dport);
} nat_conntrack_ops;

static time_t _ipv4_gc_time = 0;
LIST_HEAD(nat_conntrack_q, _nat_conntrack_t) _ipv4_header = LIST_HEAD_INITIALIZER(_ipv4_header);

static nat_conntrack_t * lookup_ipv4(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	nat_iphdr_t *ip;
	nat_conntrack_t *item;

	ip = (nat_iphdr_t *)packet;
	LIST_FOREACH(item, &_ipv4_header, entry) {
		if (item->c.th_sport != sport ||
				item->c.th_dport != dport) {
			continue;
		}

		if (item->c.ip_src.s_addr == ip->ip_src.s_addr &&
				item->c.ip_dst.s_addr == ip->ip_dst.s_addr) {
			item->last_alive = time(NULL);
			return item;
		}
	}

	return NULL;
}

static int establish_timeout(int live_count)
{
	if (live_count < 16) {
		return 72000;
	}

	if (live_count < 128) {
		return 3600;
	}

	if (live_count < 1024) {
		return 1800;
	}

	if (live_count < 10240) {
		return 600;
	}

	return 120;
}

static nat_conntrack_t * newconn_ipv4(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	time_t now;
	nat_iphdr_t *ip;
	nat_conntrack_t *conn;
	unsigned short nat_port = alloc_nat_port(&_tcp_pool);

	now = time(NULL);
	if (nat_port == 0) {
		conn = NULL;
		goto free_conn;
	}

	conn = ALLOC_NEW(nat_conntrack_t);

	if (conn != NULL) {
		ip = (nat_iphdr_t *)packet;

		conn->last_alive = now;
		conn->c.th_sport = sport;
		conn->c.th_dport = dport;

		conn->c.ip_src = ip->ip_src;
		conn->c.ip_dst = ip->ip_dst;

		alloc_nat_slot(&conn->s, &conn->c, 0, nat_port);
		LIST_INSERT_HEAD(&_ipv4_header, conn, entry);
	}

free_conn:
	if (now < _ipv4_gc_time || now > _ipv4_gc_time + 120) {
		nat_conntrack_t *item, *next;

		_ipv4_gc_time = now;
		LIST_FOREACH_SAFE(item, &_ipv4_header, entry, next) {
			if (item == conn) {
				continue;
			}

			int cflags = item->c.flags;
			int sflags = item->s.flags;
			int mflags = (TH_SYN| TH_FIN);
			int s_established = (sflags & mflags) == TH_SYN;
			int c_established = (cflags & mflags) == TH_SYN;
			int timeout = (s_established && c_established)? establish_timeout(_tcp_pool._nat_count): 60;

			if ((item->last_alive > now) ||
					((cflags| sflags) & TH_RST) ||
					(item->last_alive + timeout < now)) {
				log_verbose("free dead connection: %p %d F: %ld T: %ld\n", item, _tcp_pool._nat_count, now, item->last_alive);
				log_verbose("connection: cflags %x sflags %x fin %x rst %x\n", item->c.flags, item->s.flags, TH_FIN, TH_RST);
				free_nat_port(&_tcp_pool, item->s.th_dport);
				LIST_REMOVE(item, entry);
				free(item);
			}
		}
	}

	log_verbose("new connection: %p, %d\n", conn, _tcp_pool._nat_count);
	return conn;
}

static nat_conntrack_ops ip_conntrack_ops = {
	.lookup = lookup_ipv4,
	.newconn = newconn_ipv4
};

static time_t _ipv6_gc_time = 0;
struct nat_conntrack_q _ipv6_header = LIST_HEAD_INITIALIZER(_ipv6_header);

static nat_conntrack_t * lookup_ipv6(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	nat_ip6hdr_t *ip;
	nat_conntrack_t *item;

	ip = (nat_ip6hdr_t *)packet;
	LIST_FOREACH(item, &_ipv4_header, entry) {
		if (item->c.th_sport != sport ||
				item->c.th_dport != dport) {
			continue;
		}

		if (0 == memcmp(&item->c.ip_src, &ip->ip6_src, sizeof(ip->ip6_src)) &&
				0 == memcmp(&item->c.ip_dst, &ip->ip6_dst, sizeof(ip->ip6_dst))) {
			item->last_alive = time(NULL);
			return item;
		}
	}

	return NULL;
}

static nat_conntrack_t * newconn_ipv6(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	time_t now;
	nat_ip6hdr_t *ip;
	nat_conntrack_t *conn;
	unsigned short nat_port = alloc_nat_port(&_tcp_pool);

	now = time(NULL);
	if (nat_port == 0) {
		conn = NULL;
		goto free_conn;
	}

	conn = ALLOC_NEW(nat_conntrack_t);
	if (conn != NULL) {
		ip = (nat_ip6hdr_t *)packet;

		conn->last_alive = now;
		conn->c.th_sport = sport;
		conn->c.th_dport = dport;

		conn->c.ip6_src = ip->ip6_src;
		conn->c.ip6_dst = ip->ip6_dst;

		alloc_nat_slot(&conn->s, &conn->c, 1, nat_port);
		LIST_INSERT_HEAD(&_ipv6_header, conn, entry);
	}

free_conn:
	if (now < _ipv6_gc_time || now > _ipv6_gc_time + 120) {
		_ipv6_gc_time = now;
	}

	return conn;
}

static nat_conntrack_ops ip6_conntrack_ops = {
	.lookup = lookup_ipv6,
	.newconn = newconn_ipv6
};

ssize_t tcp_frag_rst(nat_tcphdr_t *th, uint8_t *packet)
{
	int acc = 0;
	int flags = th->th_flags;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	if (flags & TH_RST) {
		log_error("drop RST packet\n");
		return 0;
	}

	if (flags & TH_ACK) {
		th->th_flags = TH_RST;
		th->th_seq = th->th_ack;
		th->th_ack = 0;
	} else {
		th->th_flags = (TH_RST| TH_ACK);
		th->th_ack = htonl(ntohl(th->th_seq) + 1);
		th->th_seq = 0;
	}

	th->th_off = (sizeof(*th) >> 2);
	th->th_urp = 0;
	th->th_win = 0;
	th->th_sum = 0;

	xchg(th->th_sport, th->th_dport, u_int16_t);

	unsigned cksum = 0;
	cksum = tcpip_checksum(cksum, &ip->ip_dst, 4, 0);
	cksum = tcpip_checksum(cksum, &ip->ip_src, 4, 0);
	th->th_sum = tcp_checksum(cksum, th, sizeof(*th));

	/* TODO: update tcp/ip checksum */

	ip->ip_sum = 0;
	ip->ip_len = ntohs(d_off(th +1, packet));
	xchg(ip->ip_src, ip->ip_dst, struct in_addr);
	ip->ip_sum = ip_checksum(ip, sizeof(*ip));

	return d_off(th +1, packet);
}

ssize_t tcpup_frag_rst(struct tcpuphdr *th, uint8_t *packet)
{
	int flags = th->th_flags;

	if (flags & TH_RST) {
		log_error("drop RST packet\n");
		return 0;
	}

	if (flags & TH_ACK) {
		th->th_flags = TH_RST;
		th->th_seq = th->th_ack;
		th->th_ack = 0;
	} else {
		th->th_flags = (TH_RST| TH_ACK);
		th->th_ack = htonl(ntohl(th->th_seq) + 1);
		th->th_seq = 0;
	}

	th->th_opten = 0;
	th->th_win = 0;

	return sizeof(*th);
}

static char _pkt_buf[1500];
static size_t _tcpup_len = 0;

static char _tcp_buf[1500];
static size_t _tcpip_len = 0;

void * get_tcpup_data(int *len)
{
	if (_tcpup_len == 0) return NULL;
	if (len) *len = _tcpup_len;
	_tcpup_len = 0;
	return _pkt_buf;
}

void * get_tcpip_data(int *len)
{
	if (_tcpip_len == 0) return NULL;
	if (len) *len = _tcpip_len;
	_tcpip_len = 0;
	return _tcp_buf;
}

static u_char _null_[28] = {0};
static u_char type_len_map[8] = {0x0, 0x04, 0x0, 0x0, 0x10};
#define RELAY_IPV4 0x01
#define RELAY_IPV6 0x04

static int set_relay_info(u_char *target, int type, void *host, u_short port)
{      
	int len;
	char *p, buf[60];

	p = (char *)target;
	*p++ = (type & 0xff);
	*p++ = 0;

	memcpy(p, &port, 2);
	p += 2;

	len = type_len_map[type & 0x7];
	memcpy(p, host, len);
	p += len;

	return p - (char *)target;
}

static int _tcp_mss = 1440;

int set_tcp_mss_by_mtu(int mtu)
{
	if (mtu < 512 || mtu < sizeof(struct tcpuphdr)) {
		return 0;
	}

	if (mtu < sizeof(struct tcpuphdr) + _tcp_mss) {
		_tcp_mss = mtu - sizeof(struct tcpuphdr);
	}

	return 0;
}

static int handle_client_to_server(nat_conntrack_t *conn, nat_conntrack_ops *ops, nat_tcphdr_t *th, uint8_t *packet, size_t len)
{
	const uint8_t *data_start = NULL;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	int count, offset;
	struct tcpupopt to = {0};
	struct tcpuphdr *up = (struct tcpuphdr *)_pkt_buf;

	up->th_seq = th->th_seq;
	up->th_ack = th->th_ack;
	up->th_magic = MAGIC_UDP_TCP;

	up->th_win   = th->th_win;
	up->th_flags = th->th_flags;

	count = (th->th_off << 2);
	offset = tcpip_dooptions(&to, (u_char *)(th + 1), count - sizeof(*th));

	if (th->th_flags & TH_SYN) {
		to.to_flags |= TOF_DESTINATION;
		to.to_dslen  = set_relay_info(_null_, RELAY_IPV4, &conn->c.ip_dst, th->th_dport);
		to.to_dsaddr = _null_;

		if (to.to_flags & TOF_SCALE) {
			/* TODO: wscale will be not 7 */
			conn->tcp_wscale = to.to_wscale;
		}

		if ((to.to_flags & TOF_MSS)
				&& (_tcp_mss < to.to_mss)) {
			to.to_mss = _tcp_mss;
		}
	}

	if (conn->tcp_wscale != 7) {
		/* convert windows scale from old to new */
		unsigned int win = htons(th->th_win) << conn->tcp_wscale;
		up->th_win = htons(win >> 7);
	}

	offset = tcpup_addoptions(&to, (u_char *)(up + 1));
	up->th_opten = (offset >> 2);

	data_start = ((uint8_t *)th) + (th->th_off << 2);
	count = ((packet + len) - data_start);

	memcpy(((u_char *)(up + 1)) + offset, data_start, count);
	_tcpup_len = sizeof(*up) + offset + count;

	up->th_conv = conn->s.th_dport;
	conn->track_len = 0;
	if (count > 0 || CHECK_FLAGS(up->th_flags, TH_SYN| TH_FIN| TH_RST)) {
		conn->last_dir = DIRECT_CLIENT_TO_SERVER;
		conn->c.byte_sent += count;
		conn->c.pkt_sent ++;
	} else {
		struct tcpuphdr *tuh = (struct tcpuphdr *)conn->track_buf;
		assert(sizeof(conn->track_buf) >= sizeof(*up) + offset);
		memcpy(conn->track_buf, up, sizeof(*up) + offset);
		tuh->th_seq = htonl(ntohl(tuh->th_seq) -1);
		conn->track_len = sizeof(*tuh) + offset;

		tuh->th_opten = 0;
		conn->track_len = sizeof(*tuh);
	}

	return 0;
}

static int init_ipv4_tpl(nat_iphdr_t *ip, size_t len)
{
	ip->ip_hl = 5;
	ip->ip_v  = 4;
	ip->ip_tos = 0;
	ip->ip_id  = 0;
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = 64;
	ip->ip_p   = IPPROTO_TCP;

	ip->ip_dst.s_addr = 0;
	ip->ip_src.s_addr = 0;

	ip->ip_sum = 0;
	ip->ip_len = htons(len + sizeof(*ip));

	return 0;
}

static int handle_server_to_client(nat_conntrack_t *conn,
		nat_conntrack_ops *ops, struct tcpuphdr *up, uint8_t *packet, size_t len)
{
	const uint8_t *data_start = NULL;
	nat_iphdr_t *ip = (nat_iphdr_t *)_tcp_buf;

	int count, offset;
	struct tcpupopt to = {0};
	nat_tcphdr_t *th = (nat_tcphdr_t *)(ip + 1);
	memset(th, 0, sizeof(*th));

	th->th_seq = up->th_seq;
	th->th_ack = up->th_ack;

	th->th_win   = up->th_win;
	th->th_flags = up->th_flags;

	th->th_sport = conn->c.th_dport;
	th->th_dport = conn->c.th_sport;
	th->th_urp   = 0;
	th->th_sum   = 0;

	count = (up->th_opten << 2);
	offset = tcpup_dooptions(&to, (u_char *)(up + 1), count);

	if (th->th_flags & TH_SYN) {
		to.to_flags |= TOF_SACKPERM;
		to.to_flags |= TOF_SCALE;
		to.to_wscale = 7;

		if ((to.to_flags & TOF_MSS)
				&& (_tcp_mss < to.to_mss)) {
			to.to_mss = _tcp_mss;
		}
	}

	offset = tcpip_addoptions(&to, (u_char *)(th + 1));
	th->th_off = ((offset + sizeof(*th)) >> 2);

	data_start = ((uint8_t *)(up + 1)) + (up->th_opten << 2);
	count = ((packet + len) - data_start);
	memcpy(((u_char *)(th + 1)) + offset, data_start, count);

	init_ipv4_tpl(ip, count + sizeof(*th) + offset);
	ip->ip_dst = conn->c.ip_src;
	ip->ip_src = conn->c.ip_dst;
	ip->ip_sum = ip_checksum(ip, sizeof(*ip));

	unsigned cksum = 0;
	cksum = tcpip_checksum(cksum, &ip->ip_dst, 4, 0);
	cksum = tcpip_checksum(cksum, &ip->ip_src, 4, 0);
	th->th_sum = tcp_checksum(cksum, th, sizeof(*th) + offset + count);

	if (count > 0 || CHECK_FLAGS(th->th_flags, TH_FIN)) {
		conn->last_dir = DIRECT_SERVER_TO_CLIENT;
		conn->s.byte_sent += count;
		conn->s.pkt_sent ++;
	} else if (CHECK_FLAGS(th->th_flags, TH_RST) || 
			conn->last_dir == DIRECT_SERVER_TO_CLIENT) {
		/* conn->s.pkt_sent ++; */
		conn->last_dir = 0;
	}

	_tcpip_len = sizeof(*th) + sizeof(*ip) + offset + count;
	return 0;
}

ssize_t tcpup_frag_input(void *packet, size_t len, size_t limit)
{
	struct tcpuphdr *up;
	nat_conntrack_ops *ops;
	nat_conntrack_t *item, *conn = NULL;

	up = (struct tcpuphdr *)packet;
	if (up->th_conv == htonl(TCPUP_PROTO_UDP)) {
		_tcpip_len = udpup_frag_input(packet, len, (uint8_t *)_tcp_buf, sizeof(_tcp_buf));
		return 0;
	}

	LIST_FOREACH(item, &_ipv4_header, entry) {
		if (item->s.th_dport != up->th_conv) {
			continue;
		}

		item->last_alive = time(NULL);
		conn = item;
	}

	if (conn == NULL) {
		return tcpup_frag_rst(up, packet);
	}

	ops = (nat_conntrack_ops *)&ip_conntrack_ops;
	handle_server_to_client(conn, ops, up, packet, len);
	conn->s.flags |= up->th_flags;

	return 0;
}

ssize_t tcpip_frag_input(void *packet, size_t len, size_t limit)
{
	nat_iphdr_t *ip;
	tcp_state_t *tcpcb;

	nat_ip6hdr_t *ip6;
	nat_tcphdr_t *th, h1;

	nat_conntrack_t *conn;
	nat_conntrack_ops *ops;

	ip = (nat_iphdr_t *)packet; 

	if (ip->ip_v == VERSION_IPV4) {
		ip6 = NULL;
		if (ip->ip_p == IPPROTO_UDP) goto process_udp;
		CHECK_NAT_PROTOCOL(ip->ip_p, IPPROTO_TCP);
		th  = (nat_tcphdr_t *)(ip + 1);
		ops = (nat_conntrack_ops *)&ip_conntrack_ops;
	} else if (ip->ip_v == VERSION_IPV6) {
		ip6 = (nat_ip6hdr_t *)packet;
		if (ip6->ip6_nxt == IPPROTO_UDP) goto process_udp;
		CHECK_NAT_PROTOCOL(ip6->ip6_nxt, IPPROTO_TCP);
		th  = (nat_tcphdr_t *)(ip6 + 1);
		ops = (nat_conntrack_ops *)&ip6_conntrack_ops;
	} else {
		log_error("invlid ip protocol version: %d\n", ip->ip_v);
		return 0;
	}

	conn = (*ops->lookup)(packet, th->th_sport, th->th_dport);

	if (conn == NULL) {
		if (th->th_flags & TH_RST) {
			log_verbose("receive RST packet without connection\n");
			return 0;
		}

		if (th->th_flags & TH_ACK) {
			log_error("receive ACK packet without connection\n");
			return tcp_frag_rst(th, packet);
		}

		if (!CHECK_FLAGS(th->th_flags, TH_SYN)) {
			log_verbose("receive ACK packet without connection\n");
			return 0;
		}

		conn = (*ops->newconn)(packet, th->th_sport, th->th_dport);
		if (conn == NULL) {
			log_verbose("receive SYN packet without connection, no availiable port\n");
			return tcp_frag_rst(th, packet);
		}
	}

	handle_client_to_server(conn, ops, th, packet, len);
	conn->c.flags |= th->th_flags;
	return 0;

process_udp:
	_tcpup_len = udpip_frag_input(packet, len, (uint8_t *)_pkt_buf, sizeof(_pkt_buf));
	return 0;
}

static int _need_track = 0;
static int _last_track_round = 0;

static int is_stale(nat_conntrack_t *item, time_t now)
{
	if (item->last_alive + 5 < now &&
			item->last_alive + 500 > now &&
			item->last_dir == DIRECT_SERVER_TO_CLIENT &&
			item->c.pkt_sent + 10 < item->s.pkt_sent
			&& item->c.byte_sent + 65536 < item->s.byte_sent) {
		return 1;
	}

	return 0;
}

int tcpup_track_stage1()
{
	time_t now = time(NULL);
	nat_conntrack_t *item = NULL;

	_need_track = 0;
	LIST_FOREACH(item, &_ipv4_header, entry) {
		if (is_stale(item, now)) {
			log_verbose("tcpup_track_stage1: %d/%d %d/%d\n",
					item->c.byte_sent, item->c.pkt_sent,
					item->s.byte_sent, item->s.pkt_sent);
			_need_track = 1;
			break;
		}
	}

	return 0;
}

int tcpup_track_stage2()
{
	if (_need_track) {
		time_t now = time(NULL);
		nat_conntrack_t *item = NULL;
		nat_conntrack_t *weak_item = NULL;
		nat_conntrack_t *full_item = NULL;

		LIST_FOREACH(item, &_ipv4_header, entry) {
			if (is_stale(item, now)) {
				if (item->track_round != _last_track_round) {
					full_item = item;
					break;
				} else {
					weak_item = item;
				}
			}
		}

		if (full_item == NULL) {
			full_item = weak_item;
			_last_track_round++;
		}

		if (full_item != NULL) {
			_tcpup_len = full_item->track_len;
			memcpy(_pkt_buf, full_item->track_buf, _tcpup_len);
			full_item->track_round = _last_track_round;
			log_verbose("tcpup_track_stage2: %ld, %s\n", _tcpup_len, inet_ntoa(full_item->c.ip_dst));
			return 1;
		}

		log_verbose("not tcpup_track_stage2: %ld\n", _tcpup_len);
		_need_track = 0;
	}

	return 0;
}

