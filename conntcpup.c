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

	int th_sum;
	int ip_sum;

	uint16_t th_sport;
	uint16_t th_dport;

	struct in_addr ip_dst;
	struct in_addr ip_src;

	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;

} tcp_state_t;

static int init_ip6_tpl(nat_ip6hdr_t *tpl)
{
	return 0;
}

static int cksum_long_delta(u_long src, u_long dst)
{
	int acc = (src & 0xffff) - (dst & 0xffff);
	return acc + (src >> 16) - (dst >> 16);
}

static int cksum_delta(void *ptr, size_t len)
{
	int acc = 0, i;
	uint8_t padding[2];
	uint16_t *d = (uint16_t *)ptr;

	for (i = 0; i < len/2; i++) {
		acc -= d[i];
	}

	if (len & 1) {
		padding[0] = *((uint8_t *)ptr + len - 1);
		padding[1] = 0;
		acc -= *(uint16_t *)padding;
	}

	return acc;
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

static int _nat_count = 0;
static unsigned short _nat_port = 1024;
static uint32_t _nat_port_bitmap[65536 / 32] = {0};

static uint16_t use_nat_port(uint16_t port)
{
	int index = (port / 32);
	int offset = (port % 32);

	uint32_t old = _nat_port_bitmap[index];
	_nat_port_bitmap[index] |= (1 << offset);
	assert(old != _nat_port_bitmap[index]);
	_nat_count++;

	return htons(port + 1024);
}

#define USER_PORT_COUNT (65536 - 1024)

static uint16_t alloc_nat_port()
{
	uint32_t bitmap;
	int index, offset, bound;

	if (_nat_count >= USER_PORT_COUNT) {
		return 0;
	}

	_nat_port += (rand() % 17);
	_nat_port %= USER_PORT_COUNT;

	bound = (_nat_port >> 5);
	bitmap = _nat_port_bitmap[bound];

	for (offset = (_nat_port % 32); offset < 32; offset++) {
		if (bitmap & (1 << offset)) {
			_nat_port++;
		} else {
			return _nat_port;
		}
	}

	for (index = bound + 1; index < (USER_PORT_COUNT / 32); index++) {
		if (_nat_port_bitmap[index] != 0xffffffff) {
			bitmap = _nat_port_bitmap[index];
			offset = 0;
			goto found;
		}
	}

	for (index = 0; index < bound; index++) {
		if (_nat_port_bitmap[index] != 0xffffffff) {
			bitmap = _nat_port_bitmap[index];
			offset = 0;
			goto found;
		}
	}

	_nat_port = bound * 32;
	for (offset = 0; offset < (_nat_port % 32); offset++) {
		if (bitmap & (1 << offset)) {
			_nat_port++;
		} else {
			return _nat_port;
		}
	}

	return 0;

found:
	_nat_port = index * 32;
	for (offset = 0; offset < 32; offset++) {
		if (bitmap & (1 << offset)) {
			_nat_port++;
		} else {
			return _nat_port;
		}
	}

	return _nat_port;
}

static uint16_t free_nat_port(uint16_t port)
{
	int index, offset;

	port = htons(port) - 1024;
	index = (port / 32);
	offset = (port % 32);

	_nat_port_bitmap[index] &= ~(1 << offset);
	_nat_count--;

	return 0;
}

static void alloc_nat_slot(tcp_state_t *s, tcp_state_t *c, int is_ipv6, uint16_t port)
{
	int i;
	uint16_t *src, *dst;
	uint16_t *nats, *natd;

	s->ip_dst.s_addr = 0x5a5afeed;
	s->ip_src.s_addr = 0x5a5afeed;
	s->th_dport = use_nat_port(port);
	s->th_sport = 0xfeed;

	s->th_sum = 0;
	s->ip_sum = 0;

	if (is_ipv6) {
		src = (uint16_t *)&c->ip6_src;
		nats = (uint16_t *)&s->ip6_dst;

		dst = (uint16_t *)&c->ip6_dst;
		natd = (uint16_t *)&s->ip6_src;

		for (i = 0; i < 8; i++) {
			s->ip_sum += (src[i] - nats[i]);
			s->ip_sum += (dst[i] - natd[i]);
		}

		s->th_sum = s->ip_sum;
		assert(0);
	} else {
		src = (uint16_t *)&c->ip_src;
		nats = (uint16_t *)&s->ip_dst;

		dst = (uint16_t *)&c->ip_dst;
		natd = (uint16_t *)&s->ip_src;

		for (i = 0; i < 2; i++) {
			s->ip_sum += (src[i] - nats[i]);
			s->ip_sum += (dst[i] - natd[i]);
		}

		s->th_sum = s->ip_sum;
	}

	s->th_sum += (c->th_sport - s->th_dport);
	s->th_sum += (c->th_dport - s->th_sport);

	c->ip_sum = -s->ip_sum;
	c->th_sum = -s->th_sum;
	return;
}

typedef struct _nat_conntrack_t {
	int is_ipv6;
	int last_meta;
	int tcp_wscale;
	time_t last_alive;
	tcp_state_t c; /* client side tcp state */
	tcp_state_t s; /* server side tcp state */
	LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

typedef struct _nat_conntrack_ops {
	int (*adjust)(uint8_t *packet, int adjust);
	int (*ip_nat)(tcp_state_t *tcpcb, uint8_t *packet);
	nat_conntrack_t * (*lookup)(uint8_t *packet, uint16_t sport, uint16_t dport);
	nat_conntrack_t * (*newconn)(uint8_t *packet, uint16_t sport, uint16_t dport);
} nat_conntrack_ops;

static int adjust_ipv4(uint8_t *packet, int adjust)
{
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;
	uint16_t tlen   = htons(ip->ip_len) + adjust;
	ip->ip_sum = update_cksum(ip->ip_sum, ip->ip_len - ntohs(tlen));
	ip->ip_len = ntohs(tlen);

	return 0;
}

static int ip_nat_ipv4(tcp_state_t *tcpcb, uint8_t *packet)
{
	uint16_t d0, d1;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	ip->ip_src = tcpcb->ip_dst;
	ip->ip_dst = tcpcb->ip_src;
	ip->ip_sum = update_cksum(ip->ip_sum, tcpcb->ip_sum);

	d0 = *(uint16_t *)&ip->ip_ttl;
	ip->ip_ttl--;
	d1 = *(uint16_t *)&ip->ip_ttl;
	ip->ip_sum = update_cksum(ip->ip_sum, d0 - d1);

	return tcpcb->ip_sum;
}

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

static nat_conntrack_t * newconn_ipv4(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	time_t now;
	nat_iphdr_t *ip;
	nat_conntrack_t *conn;
	unsigned short nat_port = alloc_nat_port();

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
			int timeout = (s_established && c_established)? 60: 1800;

			if ((item->last_alive > now) ||
					((cflags| sflags) & TH_RST) ||
					(item->last_alive + timeout < now)) {
				log_verbose("free dead connection: %p %d F: %ld T: %ld\n", item, _nat_count, now, item->last_alive);
				log_verbose("connection: cflags %x sflags %x fin %x rst %x\n", item->c.flags, item->s.flags, TH_FIN, TH_RST);
				free_nat_port(item->s.th_dport);
				LIST_REMOVE(item, entry);
				free(item);
			}
		}
	}

	log_verbose("new connection: %p, %d\n", conn, _nat_count);
	return conn;
}

static nat_conntrack_ops ip_conntrack_ops = {
	.ip_nat = ip_nat_ipv4,
	.adjust = adjust_ipv4,
	.lookup = lookup_ipv4,
	.newconn = newconn_ipv4
};

static int ip_nat_ipv6(tcp_state_t *tcpcb, uint8_t *packet)
{
	nat_ip6hdr_t *ip6 = (nat_ip6hdr_t *)packet;

	ip6->ip6_src = tcpcb->ip6_dst;
	ip6->ip6_dst = tcpcb->ip6_src;
	ip6->ip6_hlim --;

	return tcpcb->ip_sum;
}

static int adjust_ipv6(uint8_t *packet, int adjust)
{
	nat_ip6hdr_t *ip = (nat_ip6hdr_t *)packet;
	ip->ip6_plen += adjust;
	return 0;
}

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
	unsigned short nat_port = alloc_nat_port();

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
	.ip_nat = ip_nat_ipv6,
	.lookup = lookup_ipv6,
	.newconn = newconn_ipv6
};

void *m_off(void *ptr, int off) 
{
	uint8_t *m = (uint8_t *)ptr;
	return (m + off);
}

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
	th->th_sum = update_cksum(0xffff, cksum_delta(th, sizeof(*th)));
	th->th_sum = update_cksum(th->th_sum, cksum_long_delta(0xffffffff, ip->ip_src.s_addr));
	th->th_sum = update_cksum(th->th_sum, cksum_long_delta(0xffffffff, ip->ip_dst.s_addr));
	th->th_sum = update_cksum(th->th_sum, -htons(6 + sizeof(*th)));

	/* TODO: update tcp/ip checksum */

	ip->ip_sum = 0;
	ip->ip_len = ntohs(d_off(th +1, packet));
	xchg(ip->ip_src, ip->ip_dst, struct in_addr);
	ip->ip_sum = update_cksum(0xffff, cksum_delta(packet, sizeof(*ip)));

	return d_off(th +1, packet);
}

static char _pkt_buf[1500];
static size_t _pkt_len = 0;

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

	memcpy(((u_char *)(th + 1)) + offset, data_start, count);
	_pkt_len = sizeof(*up) + offset + count;

	up->th_conv = conn->s.th_dport;

	return 0;
}

ssize_t tcp_frag_nat(void *packet, size_t len, size_t limit)
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
		CHECK_NAT_PROTOCOL(ip->ip_p, IPPROTO_TCP);
		th  = (nat_tcphdr_t *)(ip + 1);
		ops = (nat_conntrack_ops *)&ip_conntrack_ops;
	} else if (ip->ip_v == VERSION_IPV6) {
		ip6 = (nat_ip6hdr_t *)packet;
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

	log_verbose("_pkt_len: %ld\n", _pkt_len);
	return 0;
}

void module_init(int port)
{
#if 0
	init_ip6_tpl(&ip6_tpl);
#endif

	return;
}
