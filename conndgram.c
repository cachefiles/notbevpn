#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>

#include <config.h>
#include <bsdinet/tcpup.h>

#include "tx_debug.h"
#include "portpool.h"
#include "conversation.h"

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

uint16_t get_client_id();
static port_pool_t _udp_pool = {};

static void alloc_nat_slot(udp_state_t *s, udp_state_t *c, uint16_t port)
{
	uint16_t convs[2] = {};
	s->th_dport = convs[0] = use_nat_port(&_udp_pool, port);
	s->th_sport = convs[1] = get_client_id();
	memcpy(&s->ip_src, convs, sizeof(s->ip_src));
	memcpy(&s->ip_dst, convs, sizeof(s->ip_dst));
	s->ip_sum = 0;
	return;
}

typedef struct _nat_conntrack_t {
	int use_port;
	int last_meta;
	time_t last_alive;

	void *ops;
	void *udata;
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
		if (item->use_port) {
			if ((item->c.th_sport == sport) &&
					(item->c.ip_src.s_addr == ip->ip_src.s_addr)) {
				item->last_alive = time(NULL);
				return item;
			}
		} else {
			if ((item->c.th_dport == dport) &&
					(item->c.ip_dst.s_addr == ip->ip_dst.s_addr)) {
				item->last_alive = time(NULL);
				return item;
			}
		}
	}

	return NULL;
}

#define P(x) ip2text(x)
const char *ip2text(struct in_addr *ip);

static int conngc_ipv4(int type, time_t now, nat_conntrack_t *skip)
{
	if (now < _ipv4_gc_time || now > _ipv4_gc_time + 30) {
		nat_conntrack_t *item, *next;

		_ipv4_gc_time = now;
		LIST_FOREACH_SAFE(item, &_ipv4_header, entry, next) {
			if (item == skip) {
				continue;
			}

			int timeout = 30;
			if (item->c.ttl > 3) timeout += 150;
			if (item->s.ttl > 3) timeout += 150;

			if ((item->last_alive > now) ||
					(item->last_alive + timeout < now)) {
				log_verbose("free datagram connection: %p, %d\n", skip, _udp_pool._nat_count);
				if (item->use_port) free_nat_port(&_udp_pool, item->s.th_dport);
				LIST_REMOVE(item, entry);
				free(item);
			}
		}
	}

	return 0;
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

	ip = (nat_iphdr_t *)packet;
	uint32_t ip_src_xor = htonl(ip->ip_src.s_addr)^0x64400001;

	if (ip_src_xor != 0 && (ip_src_xor & ~0xffff) == 0) {
		log_verbose("loop detected: %s:%d -> %s:%d", P(&ip->ip_src), htons(sport), P(&ip->ip_dst), htons(dport));
		conn = NULL;
		goto free_conn;
	}

	conn = ALLOC_NEW(nat_conntrack_t);

	if (conn != NULL) {

		conn->use_port = 1;
		conn->last_alive = now;
		conn->c.th_sport = sport;
		conn->c.th_dport = dport;

		conn->c.ip_src = ip->ip_src;
		conn->c.ip_dst = ip->ip_dst;

		unsigned cksum = tcpip_checksum(0, &ip->ip_src, 4, 0);
		conn->c.ip_sum = tcpip_checksum(cksum, &ip->ip_dst, 4, 0);

		alloc_nat_slot(&conn->s, &conn->c, nat_port);
		LIST_INSERT_HEAD(&_ipv4_header, conn, entry);

		log_verbose("new datagram connection: %p, %d %s:%d -> %s:%d\n",
				conn, _udp_pool._nat_count, P(&ip->ip_src), htons(sport), P(&ip->ip_dst), htons(dport));
	}

free_conn:
	conngc_ipv4(0, now, conn);

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
	LIST_FOREACH(item, &_ipv6_header, entry) {
		if (item->use_port) {
			if ((item->c.th_sport == sport) &&
					0 == memcmp(&item->c.ip6_src, &ip->ip6_src, sizeof(ip->ip6_src))) {
				item->last_alive = time(NULL);
				return item;
			}
		} else {
			if ((item->c.th_dport == dport) &&
					0 == memcmp(&item->c.ip6_dst, &ip->ip6_dst, sizeof(ip->ip6_dst))) {
				item->last_alive = time(NULL);
				return item;
			}
		}
	}

	return NULL;
}

static int conngc_ipv6(int type, time_t now, nat_conntrack_t *skip)
{
	if (now < _ipv6_gc_time || now > _ipv6_gc_time + 30) {
		nat_conntrack_t *item, *next;

		_ipv6_gc_time = now;
		LIST_FOREACH_SAFE(item, &_ipv6_header, entry, next) {
			if (item == skip) {
				continue;
			}

			int timeout = 30;
			if (item->c.ttl > 10) timeout += 60;
			if (item->s.ttl > 10) timeout += 60;

			if ((item->last_alive > now) ||
					(item->last_alive + timeout < now)) {
				log_verbose("free datagram connection: %p, %d\n", skip, _udp_pool._nat_count);
				if (item->use_port) free_nat_port(&_udp_pool, item->s.th_dport);
				LIST_REMOVE(item, entry);
				free(item);
			}
		}
	}

	return 0;
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
	conngc_ipv6(0, now, conn);
	return conn;
}

static size_t ipv6_hdr_len(void)
{
	return sizeof(nat_ip6hdr_t);
}

static size_t ipv6_hdr_setbuf(void *buf, int proto, size_t total, udp_state_t *st)
{
	nat_ip6hdr_t *ip = (nat_ip6hdr_t *)buf;

	ip->ip6_flow = htonl(0x60000000);
	ip->ip6_nxt  = proto;
	ip->ip6_plen = htons(total);
	ip->ip6_hlim = 64;

	ip->ip6_src = st->ip6_src;
	ip->ip6_dst = st->ip6_dst;
	xchg(ip->ip6_src, ip->ip6_dst, struct in6_addr);

	return 0;
}

static nat_conntrack_ops ip6_conntrack_ops = {
	.get_hdr_len = ipv6_hdr_len,
	.set_hdr_buf = ipv6_hdr_setbuf,
	.lookup = lookup_ipv6,
	.newconn = newconn_ipv6
};

#define TAG_SRC_IPV4 0x14
#define TAG_SRC_IPV6 0x16

#define TAG_DST_IPV4 0x84
#define TAG_DST_IPV6 0x86

static nat_conntrack_t * newconn_tcpup(struct udpuphdr4 *hdr)
{
	time_t now;
	uint16_t parts[2];
	nat_conntrack_t *conn;

	now = time(NULL);
	if (hdr->uh_tag != TAG_DST_IPV4
			&& hdr->uh_tag != TAG_DST_IPV6) {
		return NULL;
	}

	conn = ALLOC_NEW(nat_conntrack_t);

	if (conn != NULL) {
		conn->last_alive = now;

		memcpy(parts, &hdr->uh.u_conv, 4);
		conn->s.th_dport = parts[0];
		conn->s.th_sport = parts[1];
		conn->s.ip_src.s_addr = hdr->uh.u_conv;
		conn->s.ip_dst.s_addr = hdr->uh.u_conv;

		if (hdr->uh_tag == TAG_DST_IPV4) {
			conn->c.th_dport = parts[0];
			conn->c.ip_dst.s_addr = htonl(parts[1]| 0x64400000);

			conngc_ipv4(0, now, conn);
			conn->ops = (nat_conntrack_ops *)&ip_conntrack_ops;
			LIST_INSERT_HEAD(&_ipv4_header, conn, entry);
		} else if (hdr->uh_tag == TAG_DST_IPV6) {
#if 0
			conn->c.th_sport = parts[0];
			/* conn->c.ip6_src  = htonl(parts[1]); */
#endif

			conngc_ipv6(0, now, conn);
			conn->ops = (nat_conntrack_ops *)&ip6_conntrack_ops;
			LIST_INSERT_HEAD(&_ipv6_header, conn, entry);
		} else {
			assert(0);
		}
	}

free_conn:
	log_verbose("newconn: %p\n", conn);
	return conn;
}

static nat_conntrack_t * (*__so_newconn)(struct udpuphdr4 *hdr) = newconn_tcpup;

static uint32_t _proto_tag[2] = {};
static int handle_client_to_server_v4(nat_conntrack_t *conn, nat_conntrack_ops *ops, nat_udphdr_t *uh, uint8_t *packet, size_t len, uint8_t *buf, size_t limit)
{
	const uint8_t *data_start = NULL;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	int count, offset;
	struct udpuphdr4 *up = (struct udpuphdr4 *)(buf + sizeof(_proto_tag));

	_proto_tag[0] = htonl(TCPUP_PROTO_UDP);
	assert(limit > sizeof(*up) + sizeof(_proto_tag));
	memcpy(buf, _proto_tag, sizeof(_proto_tag));

	up->uh.u_conv = 0xf6e7d8c9;
	up->uh.u_flag = 0;
	up->uh.u_magic = 0xCC;
	up->uh.u_frag = 0;
	up->uh.u_doff = (sizeof(*up) >> 2);

	up->uh_len  = (sizeof(*up) - sizeof(up->uh));
	if (conn->use_port) {
		up->uh_tag  = TAG_DST_IPV4;
		up->uh_dport = uh->uh_dport;
		memcpy(up->uh_daddr, &ip->ip_dst, 4);
	} else {
		up->uh_tag  = TAG_SRC_IPV4;
		up->uh_dport = uh->uh_sport;
		memcpy(up->uh_daddr, &ip->ip_src, 4);
	}
	
	data_start = (uint8_t *)(uh + 1);
	count = (packet + len - data_start);
	assert(limit > sizeof(*uh) + sizeof(_proto_tag) + count);
	memcpy(up + 1, data_start, count);

	up->uh.u_conv = conn->s.ip_src.s_addr;
	conn->s.ttl ++;

	return sizeof(*up) + count + sizeof(_proto_tag);
}

static int handle_client_to_server_v6(nat_conntrack_t *conn, nat_conntrack_ops *ops, nat_udphdr_t *uh, uint8_t *packet, size_t len, uint8_t *buf, size_t limit)
{
	const uint8_t *data_start = NULL;
	nat_ip6hdr_t *ip = (nat_ip6hdr_t *)packet;

	int count, offset;
	struct udpuphdr6 *up = (struct udpuphdr6 *)(buf + sizeof(_proto_tag));

	assert(limit > sizeof(*up) + sizeof(_proto_tag));
	_proto_tag[0] = htonl(TCPUP_PROTO_UDP);
	memcpy(buf, _proto_tag, sizeof(_proto_tag));

	up->uh.u_conv = 0xf6e7d8c9;
	up->uh.u_flag = 0;
	up->uh.u_magic = 0xCC;
	up->uh.u_frag = 0;
	up->uh.u_doff = (sizeof(*up) >> 2);

	up->uh_len  = (sizeof(*up) - sizeof(up->uh));
	if (conn->use_port) {
		up->uh_tag  = TAG_DST_IPV6;
		up->uh_dport = uh->uh_dport;
		memcpy(up->uh_daddr, &ip->ip6_dst, 16);
	} else {
		up->uh_tag  = TAG_SRC_IPV6;
		up->uh_dport = uh->uh_sport;
		memcpy(up->uh_daddr, &ip->ip6_src, 16);
	}
	
	data_start = (uint8_t *)(uh + 1);
	count = (packet + len - data_start);
	assert(limit > sizeof(*up) + sizeof(_proto_tag) + count);
	memcpy(up + 1, data_start, count);

	up->uh.u_conv = conn->s.ip_src.s_addr;
	conn->s.ttl ++;

	return sizeof(*up) + count + sizeof(_proto_tag);
}

static int update_conntrack(nat_conntrack_t *conn, void *buf, size_t len)
{
	int is_ipv4 = 0;
	int is_ipv6 = 0;
	unsigned cksum = 0;

	size_t  optlen = len;
	u_char *optp = (u_char *) buf;

	while (optlen > 1) {
		switch (*optp) {
			case TAG_DST_IPV4:
				if (conn->use_port) break;
				assert(optlen >= 8 && optp[1] == 8);
				memcpy(&conn->c.th_sport, optp + 2, sizeof(conn->c.th_sport));
				memcpy(&conn->c.ip_src, optp + 4, sizeof(conn->c.ip_src));
				is_ipv4 = 1;
				break;

			case TAG_DST_IPV6:
				if (conn->use_port) break;
				assert(optlen >= 20 && optp[1] == 20);
				memcpy(&conn->c.th_sport, optp + 2, sizeof(conn->c.th_sport));
				memcpy(&conn->c.ip6_src, optp + 4, sizeof(conn->c.ip6_src));
				is_ipv6 = 1;
				break;

			case TAG_SRC_IPV4:
				if (!conn->use_port) break;
				assert(optlen >= 8 && optp[1] == 8);
				memcpy(&conn->c.th_dport, optp + 2, sizeof(conn->c.th_dport));
				memcpy(&conn->c.ip_dst, optp + 4, sizeof(conn->c.ip_dst));
				is_ipv4 = 1;
				break;

			case TAG_SRC_IPV6:
				if (!conn->use_port) break;
				assert(optlen >= 20 && optp[1] == 20);
				memcpy(&conn->c.th_dport, optp + 2, sizeof(conn->c.th_dport));
				memcpy(&conn->c.ip6_dst, optp + 4, sizeof(conn->c.ip6_dst));
				is_ipv6 = 1;
				break;

			default:
				log_verbose("tag: %x %ld %ld\n", *optp, optlen, len);
				return -1;
		}

		optlen -= optp[1];
		optp += optp[1];
	}

	if (is_ipv4) {
		cksum = tcpip_checksum(0, &conn->c.ip_src, 4, 0);
		conn->c.ip_sum = tcpip_checksum(cksum, &conn->c.ip_dst, 4, 0);
	} else if (is_ipv6) {
		cksum = tcpip_checksum(0, &conn->c.ip6_src, 16, 0);
		conn->c.ip_sum = tcpip_checksum(cksum, &conn->c.ip6_dst, 16, 0);
	}

	return 0;
}

static int handle_server_to_client(nat_conntrack_t *conn,
		nat_conntrack_ops *ops, struct udpuphdr4 *up, uint8_t *packet, size_t len, uint8_t *buf, size_t limit)
{
	size_t payload = 0;
	uint8_t *base = (uint8_t *)up;
	nat_udphdr_t *uh = (nat_udphdr_t *)(buf + (*ops->get_hdr_len)());
	assert (len >= sizeof(*up));

	unsigned doff = (up->uh.u_doff << 2);
	payload = packet + len - (base + doff);
	assert (len >= doff);

	assert (doff >= sizeof(*up));
	int check = update_conntrack(conn, base + sizeof(up->uh), doff - sizeof(up->uh));
	if (check != 0) {
		/* ignore bad packet */
		return 0;
	}

	uh->uh_dport = conn->c.th_dport;
	uh->uh_sport = conn->c.th_sport;
	uh->uh_ulen  = htons(payload + sizeof(*uh));
	uh->uh_sum   = 0;

	xchg(uh->uh_sport, uh->uh_dport, u_int16_t);
	memcpy(uh + 1, base + doff, payload);
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
		if (item->s.ip_src.s_addr != up->uh.u_conv) {
			continue;
		}

		item->last_alive = time(NULL);
		conn = item;
		goto found;
	}

	LIST_FOREACH(item, &_ipv6_header, entry) {
		if (item->s.ip_src.s_addr != up->uh.u_conv) {
			continue;
		}

		item->last_alive = time(NULL);
		conn = item;
		goto found;
	}

	if (__so_newconn) {
		conn = __so_newconn(up);
		if (conn != NULL) {
			goto found;
		}
	}

	return 0;

found:
	ops = (nat_conntrack_ops *)conn->ops;
	set_conversation(conn->s.ip_src.s_addr, &conn->udata);
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
		if (conn == NULL) return 0;
		conn->ops = ops;
	}

	set_conversation(conn->s.ip_src.s_addr, &conn->udata);
	if (ops == &ip_conntrack_ops) {
		return handle_client_to_server_v4(conn, ops, uh, packet, len, buf, limit);
	} else if (ops == &ip6_conntrack_ops) {
		return handle_client_to_server_v6(conn, ops, uh, packet, len, buf, limit);
	}

	assert(0);
	return 0;
}

