#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include "config.h"
#include <bsdinet/tcpup.h>

#include "tx_debug.h"
#include "portpool.h"
#include "conversation.h"

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

typedef struct _tcp_state_t {
	int flags;
	int pkt_sent;
	int byte_sent;

	int ip_sum;

	uint16_t th_sport;
	uint16_t th_dport;

	struct in_addr ip_dst;
	struct in_addr ip_src;

	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;

} tcp_state_t;

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

uint16_t get_client_id()
{
	static uint16_t _cksum = 0;
	struct {
		pid_t pid;
		time_t now;
		void * vptr;
	} _id;
	
	for (; _cksum == 0; sleep(1)) {
		_id.pid = getpid();
		_id.now = time(NULL);
		_id.vptr = malloc(sizeof(_id));
		_cksum = ip_checksum(&_id, sizeof(_id));
		free(_id.vptr);
	}

	return _cksum;
}

static port_pool_t _tcp_pool = {};

static void alloc_nat_slot(tcp_state_t *s, tcp_state_t *c, uint16_t port)
{
	uint16_t convs[2] = {};
	s->th_dport = convs[0] = use_nat_port(&_tcp_pool, port);
	s->th_sport = convs[1] = get_client_id();
	memcpy(&s->ip_src, convs, sizeof(s->ip_src));
	memcpy(&s->ip_dst, convs, sizeof(s->ip_dst));
	s->ip_sum = 0;
	return;
}

#define DIRECT_CLIENT_TO_SERVER 0x01
#define DIRECT_SERVER_TO_CLIENT 0x02

typedef struct _nat_conntrack_t {
	int probe;
	int last_dir;
	int tcp_wscale;
	int use_port;
	time_t last_alive;
	time_t last_sent;
	time_t last_recv;
	void *ops;
	void *udata;

	int track_len;
	int track_round;
	char track_buf[100];

	tcp_state_t c; /* client side tcp state */
	tcp_state_t s; /* server side tcp state */
	LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

typedef struct _nat_conntrack_ops {
	size_t (*get_hdr_len)(void);
	size_t (*set_hdr_buf)(void *buf, int proto, size_t total, tcp_state_t *st);

	size_t (*set_relay_info)(void *buf, tcp_state_t *st);
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
			item->last_sent = time(NULL);
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

	return 300;
}

#define P(x) ip2text(x)
const char *ip2text(struct in_addr *ip)
{
	static int _si = 0;
	static char sbuf[4][16] = {};
	char *_sbuf = sbuf[_si++ % 4];
#ifndef WIN32
	return inet_ntop(AF_INET, ip, _sbuf, 16);
#else
	return inet_ntoa(*ip);
#endif
}

static int conngc_ipv4(int type, time_t now, nat_conntrack_t *skip)
{
	if (now < _ipv4_gc_time || now > _ipv4_gc_time + 120) {
		nat_conntrack_t *item, *next;

		_ipv4_gc_time = now;
		LIST_FOREACH_SAFE(item, &_ipv4_header, entry, next) {
			if (item == skip) {
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
				tcp_state_t *c = &item->c;
				log_verbose("free stream: %p total=%d idle=%ld %s:%d -> %s:%d, flags %x -> %x\n",
						item, _tcp_pool._nat_count, now - item->last_alive,
						P(&c->ip_src), htons(c->th_sport), P(&c->ip_dst), htons(c->th_dport), item->s.flags, item->c.flags);
				if (item->use_port) free_nat_port(&_tcp_pool, item->s.th_dport);
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
	unsigned short nat_port = alloc_nat_port(&_tcp_pool);

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

		conn->last_alive = now;
		conn->last_sent  = now;
		conn->use_port   = 1;
		conn->c.th_sport = sport;
		conn->c.th_dport = dport;

		conn->c.ip_src = ip->ip_src;
		conn->c.ip_dst = ip->ip_dst;

		log_verbose("new connection: %p, %s:%d -> %s:%d %d\n", conn, P(&ip->ip_src), htons(sport), P(&ip->ip_dst), htons(dport), _tcp_pool._nat_count);

		unsigned cksum = tcpip_checksum(0, &ip->ip_src, 4, 0);
		conn->c.ip_sum = tcpip_checksum(cksum, &ip->ip_dst, 4, 0);

		alloc_nat_slot(&conn->s, &conn->c, nat_port);
		LIST_INSERT_HEAD(&_ipv4_header, conn, entry);
	}

free_conn:
	conngc_ipv4(0, now, conn);

	return conn;
}

static size_t ipv4_hdr_len(void)
{
	return sizeof(nat_iphdr_t);
}

static size_t ipv4_hdr_setbuf(void *buf, int proto, size_t total, tcp_state_t *st)
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

static size_t ipv4_set_relay(void *buf, tcp_state_t *st)
{
	return set_relay_info(buf, RELAY_IPV4, &st->ip_dst, st->th_dport);
}

static nat_conntrack_ops ip_conntrack_ops = {
	.get_hdr_len = ipv4_hdr_len,
	.set_hdr_buf = ipv4_hdr_setbuf,
	.set_relay_info = ipv4_set_relay,
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
	LIST_FOREACH(item, &_ipv6_header, entry) {
		if (item->c.th_sport != sport ||
				item->c.th_dport != dport) {
			continue;
		}

		if (0 == memcmp(&item->c.ip6_src, &ip->ip6_src, sizeof(ip->ip6_src)) &&
				0 == memcmp(&item->c.ip6_dst, &ip->ip6_dst, sizeof(ip->ip6_dst))) {
			item->last_alive = time(NULL);
			item->last_sent  = time(NULL);
			return item;
		}
	}

	return NULL;
}

static int conngc_ipv6(int type, time_t now, nat_conntrack_t *skip)
{
	nat_conntrack_t *conn, *item, *next;

	if (now < _ipv6_gc_time || now > _ipv6_gc_time + 120) {
		_ipv6_gc_time = now;
		LIST_FOREACH_SAFE(item, &_ipv6_header, entry, next) {
			if (item == skip) {
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
				if (item->use_port) free_nat_port(&_tcp_pool, item->s.th_dport);
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
		conn->last_sent  = now;
		conn->use_port   = 1;
		conn->c.th_sport = sport;
		conn->c.th_dport = dport;

		conn->c.ip6_src = ip->ip6_src;
		conn->c.ip6_dst = ip->ip6_dst;

		unsigned cksum = tcpip_checksum(0, &ip->ip6_src, 16, 0);
		conn->c.ip_sum = tcpip_checksum(cksum, &ip->ip6_dst, 16, 0);

		log_verbose("new item %p\n", conn);
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

size_t ipv6_hdr_setbuf(void *buf, int proto, size_t total, tcp_state_t *st)
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

static size_t ipv6_set_relay(void *buf, tcp_state_t *st)
{
	return set_relay_info(buf, RELAY_IPV6, &st->ip6_dst, st->th_dport);
}

static nat_conntrack_ops ip6_conntrack_ops = {
	.get_hdr_len = ipv6_hdr_len,
	.set_hdr_buf = ipv6_hdr_setbuf,
	.set_relay_info = ipv6_set_relay,
	.lookup = lookup_ipv6,
	.newconn = newconn_ipv6
};

struct _sockaddr_union {
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

static int tcpup_expand_dest(struct _sockaddr_union *sau, uint8_t *dsaddr, size_t dslen)
{
	int len;
	uint8_t *p, buf[60];

	p = dsaddr;
	switch (*p) {
		case RELAY_IPV4:
			assert(p[1] == 0);
			sau->in.sin_family = AF_INET;
			p += 2;
			memcpy(&sau->in.sin_port, p, 2);
			p += 2;
			memcpy(&sau->in.sin_addr, p, 4);
			p += 4;
			assert (sizeof(sau->in.sin_addr) == 4);
			assert (sizeof(sau->in.sin_port) == 2);
			assert (p == dsaddr + dslen);
			break;

		case RELAY_IPV6:
			assert(p[1] == 0);
			sau->in6.sin6_family = AF_INET6;
			p += 2;
			memcpy(&sau->in6.sin6_port, p, 2);
			p += 2;
			memcpy(&sau->in6.sin6_addr, p, 16);
			p += 16;
			assert (sizeof(sau->in6.sin6_addr) == 16);
			assert (sizeof(sau->in6.sin6_port) == 2);
			assert (p == dsaddr + dslen);
			break;

		default:
			assert(0);
			break;
	}

	return 1;
}

static nat_conntrack_t * newconn_tcpup(struct tcpuphdr *hdr)
{
	time_t now;
	uint16_t parts[2];

	struct tcpupopt to;
	struct _sockaddr_union sau;
	nat_conntrack_t *conn, *item, *next;

	now = time(NULL);
	tcpup_dooptions(&to, (u_char *)(hdr + 1), (hdr->th_opten << 2));
	if (!CHECK_FLAGS(to.to_flags, TOF_DESTINATION)) {
		return NULL;
	}

	if (!tcpup_expand_dest(&sau, to.to_dsaddr, to.to_dslen)) {
		return NULL;
	}

	conn = ALLOC_NEW(nat_conntrack_t);
	if (conn != NULL) {
		conn->last_alive = now;
		conn->last_sent  = now;

		memcpy(parts, &hdr->th_conv, 4);
		conn->s.th_dport = parts[0];
		conn->s.th_sport = parts[1];
		conn->s.ip_src.s_addr = hdr->th_conv;
		conn->s.ip_dst.s_addr = hdr->th_conv;

		log_verbose("new item %p\n", conn);
		if (sau.in.sin_family == AF_INET) {
			conn->c.th_sport = sau.in.sin_port;
			conn->c.ip_src   = sau.in.sin_addr;

			conn->c.th_dport = parts[0];
			conn->c.ip_dst.s_addr = htonl(parts[1]| 0x64400000);

			unsigned cksum = tcpip_checksum(0, &conn->c.ip_src, 4, 0);
			conn->c.ip_sum = tcpip_checksum(cksum, &conn->c.ip_dst, 4, 0);

			conngc_ipv4(0, now, conn);
			conn->ops = (nat_conntrack_ops *)&ip_conntrack_ops;
			LIST_INSERT_HEAD(&_ipv4_header, conn, entry);
		} else if (sau.in6.sin6_family == AF_INET6) {
			conn->c.th_sport = sau.in6.sin6_port;
			conn->c.ip6_src   = sau.in6.sin6_addr;

			conn->c.th_dport = parts[0];
			/* conn->c.ip6_dst  = htonl(parts[1]); */

			unsigned cksum = tcpip_checksum(0, &conn->c.ip6_src, 16, 0);
			conn->c.ip_sum = tcpip_checksum(cksum, &conn->c.ip6_dst, 16, 0);

			conngc_ipv6(0, now, conn);
			conn->ops = (nat_conntrack_ops *)&ip6_conntrack_ops;
			LIST_INSERT_HEAD(&_ipv6_header, conn, entry);
		} else {
			assert(0);
		}
	}

	return conn;
}

static nat_conntrack_t * (*__so_newconn)(struct tcpuphdr *hdr) = newconn_tcpup;

ssize_t tcp_frag_rst(nat_tcphdr_t *th, uint8_t *packet)
{
	int acc = 0;
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

	th->th_off = (sizeof(*th) >> 2);
	th->th_urp = 0;
	th->th_win = 0;
	th->th_sum = 0;

	xchg(th->th_sport, th->th_dport, u_int16_t);

	unsigned cksum = 0;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	if (ip->ip_v == VERSION_IPV4) {
		cksum = tcpip_checksum(cksum, &ip->ip_dst, 4, 0);
		cksum = tcpip_checksum(cksum, &ip->ip_src, 4, 0);
		th->th_sum = tcp_checksum(cksum, th, sizeof(*th));

		ip->ip_sum = 0;
		ip->ip_len = ntohs(d_off(th +1, packet));
		xchg(ip->ip_src, ip->ip_dst, struct in_addr);
		ip->ip_sum = ip_checksum(ip, sizeof(*ip));
	} else if (ip->ip_v == VERSION_IPV6) {
		nat_ip6hdr_t *ip6 = (nat_ip6hdr_t *)packet;
		cksum = tcpip_checksum(cksum, &ip6->ip6_dst, 16, 0);
		cksum = tcpip_checksum(cksum, &ip6->ip6_src, 16, 0);
		th->th_sum = tcp_checksum(cksum, th, sizeof(*th));

		ip6->ip6_plen = ntohs(d_off(th +1, th));
		xchg(ip6->ip6_src, ip6->ip6_dst, struct in6_addr);
	} else {
		return 0;
	}

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

static char _pkt_buf[2048];
static size_t _tcpup_len = 0;

static char _tcp_buf[2048];
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
		to.to_dslen  = (*ops->set_relay_info)(_null_, &conn->c);
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

	_tcpup_len = sizeof(*up) + offset + count;
	assert(_tcpup_len < sizeof(_pkt_buf));
	memcpy(((u_char *)(up + 1)) + offset, data_start, count);

	up->th_conv = conn->s.ip_src.s_addr;
	if (count > 0 || CHECK_FLAGS(up->th_flags, TH_SYN| TH_FIN| TH_RST)) {
		conn->last_dir = DIRECT_CLIENT_TO_SERVER;
		conn->c.byte_sent += count;
		conn->c.pkt_sent ++;
		conn->track_len = 0;
	} else {
		struct tcpuphdr *tuh = (struct tcpuphdr *)conn->track_buf;
		assert(sizeof(conn->track_buf) >= sizeof(*up) + offset);

		memcpy(conn->track_buf, up, sizeof(*up) + offset);
		conn->track_len = sizeof(*tuh) + offset;
#if 1
		tuh->th_opten = 0;
		conn->track_len = sizeof(*tuh);
#endif
	}

	return 0;
}

static int handle_server_to_client(nat_conntrack_t *conn,
		nat_conntrack_ops *ops, struct tcpuphdr *up, uint8_t *packet, size_t len)
{
	const uint8_t *data_start = NULL;

	int count, offset;
	struct tcpupopt to = {0};
	nat_tcphdr_t *th = (nat_tcphdr_t *)(_tcp_buf + (*ops->get_hdr_len)());
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
	_tcpip_len = sizeof(*th) + (*ops->get_hdr_len)() + offset + count;

	assert(_tcpip_len < sizeof(_tcp_buf));
	memcpy(((u_char *)(th + 1)) + offset, data_start, count);

	assert (ops == conn->ops);
	th->th_sum = tcp_checksum(conn->c.ip_sum, th, sizeof(*th) + offset + count);
	(*ops->set_hdr_buf)(_tcp_buf, IPPROTO_TCP, sizeof(*th) + offset + count, &conn->c);

	if (count > 0) {
		conn->last_dir = DIRECT_SERVER_TO_CLIENT;
		conn->s.byte_sent += count;
		conn->s.pkt_sent ++;
	} else if (CHECK_FLAGS(th->th_flags, TH_RST) || 
			conn->last_dir == DIRECT_SERVER_TO_CLIENT) {
		/* conn->s.pkt_sent ++; */
		conn->last_dir = 0;
	}

	return 0;
}

ssize_t tcpup_frag_input(void *packet, size_t len, size_t limit)
{
	struct tcpuphdr *up;
	nat_conntrack_ops *ops;
	nat_conntrack_t *item, *conn = NULL;

	up = (struct tcpuphdr *)packet;
	set_conversation(0, NULL);
	if (up->th_conv == htonl(TCPUP_PROTO_UDP)) {
		_tcpip_len = udpup_frag_input(packet, len, (uint8_t *)_tcp_buf, sizeof(_tcp_buf));
		return 0;
	}

	LIST_FOREACH(item, &_ipv4_header, entry) {
		if (item->s.ip_src.s_addr != up->th_conv) {
			continue;
		}

		item->last_alive = time(NULL);
		item->last_recv  = item->last_alive;
		conn = item;
		goto found;
	}

	LIST_FOREACH(item, &_ipv6_header, entry) {
		if (item->s.ip_src.s_addr != up->th_conv) {
			continue;
		}

		item->last_alive = time(NULL);
		item->last_recv  = item->last_alive;
		conn = item;
		goto found;
	}

#define TH_NEWCONN (TH_SYN| TH_ACK| TH_RST)
	if (__so_newconn &&
			TH_SYN == CHECK_FLAGS(up->th_flags, TH_NEWCONN)) {
		conn = __so_newconn(up);
		if (conn != NULL) {
			goto found;
		}
	}
#undef TH_NEWCONN

	return tcpup_frag_rst(up, packet);

found:
	ops = (nat_conntrack_ops *)conn->ops;
	handle_server_to_client(conn, ops, up, packet, len);
	conn->s.flags |= up->th_flags;
	set_conversation(conn->s.ip_src.s_addr, &conn->udata);

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

	set_conversation(0, NULL);
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
			log_verbose("missing SYN packet without connection\n");
			return 0;
		}

		conn = (*ops->newconn)(packet, th->th_sport, th->th_dport);
		if (conn == NULL) {
			log_verbose("receive SYN packet without connection, no availiable port\n");
			return tcp_frag_rst(th, packet);
		}

		conn->ops = ops;
	}

	handle_client_to_server(conn, ops, th, packet, len);
	conn->c.flags |= th->th_flags;
	set_conversation(conn->s.ip_src.s_addr, &conn->udata);
	return 0;

process_udp:
	_tcpup_len = udpip_frag_input(packet, len, (uint8_t *)_pkt_buf, sizeof(_pkt_buf));
	return 0;
}

static int _need_track = 0;
static int _last_track_round = 0;
static time_t _last_track_time = 0;

static int is_stall(nat_conntrack_t *item, time_t now)
{
	int limit = 120;

	if ((item->c.flags & TH_RST) ||
			(item->s.flags & (TH_RST| TH_FIN))) {
		return 0;
	}

	if ((item->c.flags & TH_FIN)) {
		limit = 30;
	}

	if (item->last_sent + limit < now) {
		return 0;
	}

	if (item->last_alive + 2 < now &&
			item->last_alive + limit > now &&
			item->track_len > 0 &&
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
		if (is_stall(item, now)) {
			log_verbose("tcpup_track_stage1: %d/%d %d/%d\n",
					item->c.byte_sent, item->c.pkt_sent,
					item->s.byte_sent, item->s.pkt_sent);
			_need_track = 1;
			goto cleanup;
		}
	}

	LIST_FOREACH(item, &_ipv6_header, entry) {
		if (is_stall(item, now)) {
			log_verbose("tcpup_track_stage1: %d/%d %d/%d\n",
					item->c.byte_sent, item->c.pkt_sent,
					item->s.byte_sent, item->s.pkt_sent);
			_need_track = 1;
			break;
		}
	}

cleanup:
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
			if (is_stall(item, now)) {
				if (item->track_round != _last_track_round) {
					full_item = item;
					goto found;
				} else {
					weak_item = item;
				}
			}
		}

		LIST_FOREACH(item, &_ipv6_header, entry) {
			if (is_stall(item, now)) {
				if (item->track_round != _last_track_round) {
					full_item = item;
					goto found;
				} else {
					weak_item = item;
				}
			}
		}

found:
		if (full_item == NULL) {
			full_item = weak_item;
			if (now != _last_track_time) {
				_last_track_time = now;
				_last_track_round++;
			} else {
				full_item = NULL;
				return 0;
			}
		}

		if (full_item != NULL) {
			_tcpup_len = full_item->track_len;
			full_item->track_round = _last_track_round;

			memcpy(_pkt_buf, full_item->track_buf, _tcpup_len);
			struct tcpuphdr *tuh = (struct tcpuphdr *)_pkt_buf;
			tuh->th_seq = htonl(ntohl(tuh->th_seq) -1);
			log_verbose("tcpup_track_stage2: %ld, %p, %x %x %s\n",
					_tcpup_len, full_item, full_item->c.flags, full_item->s.flags & TH_FIN, inet_ntoa(full_item->c.ip_dst));
			full_item->probe++;
			return 1;
		}

		log_verbose("not tcpup_track_stage2: %ld\n", _tcpup_len);
		_need_track = 0;
	}

	return 0;
}

