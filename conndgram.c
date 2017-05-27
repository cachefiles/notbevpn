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
#include <bsdinet/udp.h>
#endif

#ifndef __BSD_VISIBLE
#include <sys/queue.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

#include <bsdinet/tcpup.h>

typedef unsigned char uint8_t;

typedef struct ip nat_iphdr_t;
typedef struct udphdr nat_udphdr_t;
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

struct udpuphdr {
    int u_conv;

    u_char  u_flag;
    u_char  u_magic;

    u_char  u_frag;
    u_char  u_doff;
};

struct udpuphdr4 {
    struct udpuphdr uh;
    u_char uh_tag;
    u_char uh_len;
    u_short uh_dport;
    u_int uh_daddr[1];
};

struct udpuphdr6 {
    struct udpuphdr uh;
    u_char uh_tag;
    u_char uh_len;
    u_short uh_dport;
    u_int uh_daddr[4];
};

typedef struct _udp_state_t {
	int ttl;

	int th_sum;
	int ip_sum;

	uint16_t th_sport;
	uint16_t th_dport;

	struct in_addr ip_dst;
	struct in_addr ip_src;

	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;

} udp_state_t;

static int init_ip6_tpl(nat_ip6hdr_t *tpl)
{
	return 0;
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

static void alloc_nat_slot(udp_state_t *s, udp_state_t *c, int is_ipv6, uint16_t port)
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
	time_t last_alive;
	udp_state_t c; /* client side tcp state */
	udp_state_t s; /* server side tcp state */
	LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

typedef struct _nat_conntrack_ops {
	nat_conntrack_t * (*lookup)(uint8_t *packet, uint16_t sport, uint16_t dport);
	nat_conntrack_t * (*newconn)(uint8_t *packet, uint16_t sport, uint16_t dport);
} nat_conntrack_ops;

static time_t _ipv4_gc_time = 0;
static LIST_HEAD(nat_conntrack_q, _nat_conntrack_t) _ipv4_header = LIST_HEAD_INITIALIZER(_ipv4_header);

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

			int timeout = 60;
			if (item->c.ttl > 10) timeout += 60;
			if (item->s.ttl > 10) timeout += 60;

			if ((item->last_alive > now) ||
					(item->last_alive + timeout < now)) {
				free_nat_port(item->s.th_dport);
				LIST_REMOVE(item, entry);
				free(item);
			}
		}
	}

	log_verbose("new datagram connection: %p, %d\n", conn, _nat_count);
	return conn;
}

static nat_conntrack_ops ip_conntrack_ops = {
	.lookup = lookup_ipv4,
	.newconn = newconn_ipv4
};

static time_t _ipv6_gc_time = 0;
static struct nat_conntrack_q _ipv6_header = LIST_HEAD_INITIALIZER(_ipv6_header);

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
	.lookup = lookup_ipv6,
	.newconn = newconn_ipv6
};

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

static uint32_t _proto_tag[2] = {};

static int handle_client_to_server(nat_conntrack_t *conn, nat_conntrack_ops *ops, nat_udphdr_t *uh, uint8_t *packet, size_t len, uint8_t *buf, size_t limit)
{
	const uint8_t *data_start = NULL;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	int count, offset;
	struct udpuphdr4 *up = (struct udpuphdr4 *)(buf + sizeof(_proto_tag));

	_proto_tag[0] = htonl(TCPUP_PROTO_UDP);
	memcpy(buf, _proto_tag, sizeof(_proto_tag));

	up->uh.u_conv = 0xf6e7d8c9;
	up->uh.u_flag = 0;
	up->uh.u_magic = 0xCC;
	up->uh.u_frag = 0;
	up->uh.u_doff = (sizeof(*up) >> 2);

	up->uh_len  = 8;
	up->uh_tag  = 0x84;
	up->uh_dport = uh->uh_dport;
	memcpy(up->uh_daddr, &ip->ip_dst, 4);
	
#if 0
    u_short uh_sport;       /* source port */
    u_short uh_dport;       /* destination port */
    u_short uh_ulen;        /* udp length */
    u_short uh_sum;         /* udp checksum */
#endif

	data_start = (uint8_t *)(uh + 1);
	count = (packet + len - data_start);
	memcpy(up + 1, data_start, count);

	up->uh.u_conv = conn->s.th_dport;
	conn->s.ttl ++;

	return sizeof(*up) + count + sizeof(_proto_tag);
}

int ip_checksum(void *buf, size_t len);
unsigned tcpip_checksum(unsigned cksum,  const void *buf, size_t len, int finish);

int udp_checksum(unsigned cksum, void *buf, size_t len)
{
    unsigned short cksum1 = 0;
    cksum += htons(IPPROTO_UDP + len);
    cksum = tcpip_checksum(cksum, buf, len, 1);

    cksum1 = (cksum >> 16);
    while (cksum1 > 0) {
        cksum  = cksum1 + (cksum & 0xffff);
        cksum1 = (cksum >> 16);
    }

    return (~cksum);
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
		nat_conntrack_ops *ops, struct udpuphdr4 *up, uint8_t *packet, size_t len, uint8_t *buf, size_t limit)
{
	size_t payload = 0;
	const uint8_t *data_start = NULL;
	nat_iphdr_t *ip = (nat_iphdr_t *)buf;

	nat_udphdr_t *uh = (nat_udphdr_t *)(ip + 1);
	payload = packet + len - (uint8_t *)(up + 1);

	uh->uh_dport = conn->c.th_dport;
	uh->uh_sport = conn->c.th_sport;
	uh->uh_ulen  = htons(payload + sizeof(*uh));
	uh->uh_sum   = 0;
	xchg(uh->uh_sport, uh->uh_dport, u_int16_t);

	init_ipv4_tpl(ip, payload + sizeof(*uh));
	ip->ip_p   = IPPROTO_UDP;
    ip->ip_dst = conn->c.ip_src;
    ip->ip_src = conn->c.ip_dst;
    ip->ip_sum = ip_checksum(ip, sizeof(*ip));

    unsigned cksum = 0;
    cksum = tcpip_checksum(cksum, &ip->ip_dst, 4, 0);
    cksum = tcpip_checksum(cksum, &ip->ip_src, 4, 0);
	memcpy(uh + 1, up + 1, payload);
    uh->uh_sum = udp_checksum(cksum, uh, sizeof(*uh) + payload);
	conn->c.ttl ++;

	return payload + sizeof(*uh) + sizeof(*ip);
}

ssize_t udpup_frag_input(void *packet, size_t len, uint8_t *buf, size_t limit)
{
	struct udpuphdr4 *up;
	nat_conntrack_ops *ops;
	nat_conntrack_t *item, *conn = NULL;

	up = (struct udpuphdr4 *)(((uint8_t *)packet) + sizeof(_proto_tag));
	LIST_FOREACH(item, &_ipv4_header, entry) {
		if (item->s.th_dport != up->uh.u_conv) {
			continue;
		}

		item->last_alive = time(NULL);
		conn = item;
	}

	if (conn == NULL) {
		return 0;
	}

	ops = (nat_conntrack_ops *)&ip_conntrack_ops;
	return handle_server_to_client(conn, ops, up, packet, len, buf, limit);
}

ssize_t udpip_frag_input(void *packet, size_t len, uint8_t *buf, size_t limit)
{
	nat_iphdr_t *ip;
	udp_state_t *udpcb;

	nat_ip6hdr_t *ip6;
	nat_udphdr_t *uh, h1;

	nat_conntrack_t *conn;
	nat_conntrack_ops *ops;

	ip = (nat_iphdr_t *)packet; 

	if (ip->ip_v == VERSION_IPV4) {
		ip6 = NULL;
		CHECK_NAT_PROTOCOL(ip->ip_p, IPPROTO_UDP);
		uh  = (nat_udphdr_t *)(ip + 1);
		ops = (nat_conntrack_ops *)&ip_conntrack_ops;
	} else if (ip->ip_v == VERSION_IPV6) {
		ip6 = (nat_ip6hdr_t *)packet;
		CHECK_NAT_PROTOCOL(ip6->ip6_nxt, IPPROTO_UDP);
		uh  = (nat_udphdr_t *)(ip6 + 1);
		ops = (nat_conntrack_ops *)&ip6_conntrack_ops;
	} else {
		log_error("invlid ip protocol version: %d\n", ip->ip_v);
		return 0;
	}

	conn = (*ops->lookup)(packet, uh->uh_sport, uh->uh_dport);
	if (conn == NULL) {
		conn = (*ops->newconn)(packet, uh->uh_sport, uh->uh_dport);
		assert(conn != NULL);
	}

	return handle_client_to_server(conn, ops, uh, packet, len, buf, limit);
}

