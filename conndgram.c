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
#include "portpool.h"

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

static port_pool_t _udp_pool = {};

static void alloc_nat_slot(udp_state_t *s, udp_state_t *c, uint16_t port)
{
	s->ip_dst.s_addr = 0x5a5afeed;
	s->ip_src.s_addr = 0x5a5afeed;
	s->th_dport = use_nat_port(&_udp_pool, port);
	s->th_sport = 0xfeed;
	s->ip_sum = 0;
	return;
}

typedef struct _nat_conntrack_t {
	int is_ipv6;
	int last_meta;
	time_t last_alive;

	void *ops;
	udp_state_t c; /* client side tcp state */
	udp_state_t s; /* server side tcp state */
	LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

typedef struct _nat_conntrack_ops {
	size_t  (*get_hdr_len)(void);
	size_t (*set_hdr_buf)(void *buf, int proto, size_t total, udp_state_t *st);
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
		if (item->c.th_sport != sport) {
			continue;
		}

		if (item->c.ip_src.s_addr == ip->ip_src.s_addr) {
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
	unsigned short nat_port = alloc_nat_port(&_udp_pool);

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

		unsigned cksum = tcpip_checksum(0, &ip->ip_src, 4, 0);
		conn->c.ip_sum = tcpip_checksum(cksum, &ip->ip_dst, 4, 0);

		alloc_nat_slot(&conn->s, &conn->c, nat_port);
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
				log_verbose("free datagram connection: %p, %d\n", conn, _udp_pool._nat_count);
				free_nat_port(&_udp_pool, item->s.th_dport);
				LIST_REMOVE(item, entry);
				free(item);
			}
		}
	}

	log_verbose("new datagram connection: %p, %d\n", conn, _udp_pool._nat_count);
	return conn;
}

static size_t ipv4_hdr_len(void)
{
	return sizeof(nat_iphdr_t);
}

static size_t ipv4_hdr_setbuf(void *buf, int proto, size_t total, udp_state_t *st)
{
	nat_iphdr_t *ip = (nat_iphdr_t *)buf;

	ip->ip_hl = 5;
	ip->ip_v  = 4;
	ip->ip_tos = 0;
	ip->ip_id  = 0;
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = 64;
	ip->ip_p   = proto;

	ip->ip_dst.s_addr = st->ip_dst.s_addr;
	ip->ip_src.s_addr = st->ip_src.s_addr;
	xchg(ip->ip_src, ip->ip_dst, struct in_addr);

	ip->ip_sum = 0;
	ip->ip_len = htons(total + sizeof(*ip));
	ip->ip_sum = ip_checksum(ip, sizeof(*ip));

	return 0;
}

static nat_conntrack_ops ip_conntrack_ops = {
	.get_hdr_len = ipv4_hdr_len,
	.set_hdr_buf = ipv4_hdr_setbuf,
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
		if (item->c.th_sport != sport) {
			continue;
		}

		if (0 == memcmp(&item->c.ip_src, &ip->ip6_src, sizeof(ip->ip6_src))) {
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
	unsigned short nat_port = alloc_nat_port(&_udp_pool);

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

		unsigned cksum = tcpip_checksum(0, &ip->ip6_src, 16, 0);
		conn->c.ip_sum = tcpip_checksum(cksum, &ip->ip6_dst, 16, 0);

		alloc_nat_slot(&conn->s, &conn->c, nat_port);
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
	nat_udphdr_t *uh = (nat_udphdr_t *)(buf + (*ops->get_hdr_len)());
	payload = packet + len - (uint8_t *)(up + 1);

	uh->uh_dport = conn->c.th_dport;
	uh->uh_sport = conn->c.th_sport;
	uh->uh_ulen  = htons(payload + sizeof(*uh));
	uh->uh_sum   = 0;

	xchg(uh->uh_sport, uh->uh_dport, u_int16_t);
	memcpy(uh + 1, up + 1, payload);
    uh->uh_sum = udp_checksum(conn->c.ip_sum, uh, sizeof(*uh) + payload);
	ops->set_hdr_buf(buf, IPPROTO_UDP, payload + sizeof(*uh), &conn->c);
	conn->c.ttl ++;

	return payload + sizeof(*uh) + ops->get_hdr_len();
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

	ops = (nat_conntrack_ops *)conn->ops;
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
		conn->ops = ops;
	}

	return handle_client_to_server(conn, ops, uh, packet, len, buf, limit);
}
