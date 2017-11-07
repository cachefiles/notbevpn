#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>

#include <config.h>

/*
 * TCP connect follow:
 *
 * client(kernel)    conntrack(user)      server(kernel)
 *  |  ------SYN----->   |   (seq = th_seq - 12)    |
 *  |                    |   ------SYN-------->     |
 *  |                    |   <----SYN|ACK------     |
 *  | <----SYN------ (clr ACK,  seq = th_seq + 12)  |
 *  | -----SYN|ACK--->   |                          |
 *  |                    | (inject meta to data)    |
 *  |                    |   -----ACK,meta----->    |
 *  |                    |   <----ACK,meta------    |
 *  | <---ACK,len=0----  |                          |
 *  | <--------------->  |   <------------------>   |
 *  |                    |                          |
 */

typedef unsigned char uint8_t;

typedef struct ip nat_iphdr_t;
typedef struct tcphdr nat_tcphdr_t;
typedef struct ip6_hdr nat_ip6hdr_t;

#define VERSION_IPV4 4
#define VERSION_IPV6 6
#define NEED_ACK_ADJUST 0x100

#define d_off(ptr, base) ((uint8_t *)(ptr) - (uint8_t *)(base))

#define CHECK_NAT_PROTOCOL(proto, expect) \
	do { if ((proto) != (expect)) return 0; } while (0)

#define SEQ_LT(a, b)     ((int)((a)-(b)) < 0)
#define SEQ_GEQ(a, b)    ((int)((a)-(b)) >= 0)
#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))

#define CHECK_NAT_FAIL_RETURN(expr) do { if (expr); else return 0; } while (0)

#define CHECK_FLAGS(flags, want) ((flags) & (want))
#define xchg(s, d, t) { t _t = d; d = s; s = _t; } 

#define log_verbose printf
#define log_error printf

typedef struct _tcp_state_t {
	int flags;
	tcp_seq rcv_nxt;
	tcp_seq snd_max;
	tcp_seq seq_meta;

	int th_sum;
	int ip_sum;

	uint16_t th_sport;
	uint16_t th_dport;

	struct in_addr ip_dst;
	struct in_addr ip_src;

	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;

} tcp_state_t;

#define NAT_C_ADDR _nat_c_addr
#define NAT_S_ADDR _nat_s_addr
#define NAT_S_PORT _nat_s_port

#define WEB_PORT  htons(80)
#define SSL_PORT htons(443)

#define NAT_WEB_PORT _nat_web_port
#define NAT_SSL_PORT _nat_ssl_port

static u_long _nat_c_addr = 0;
static u_long _nat_s_addr = 0;
static u_short _nat_s_port = 0;
static u_short _nat_web_port = 0;
static u_short _nat_ssl_port = 0;
static nat_ip6hdr_t ip6_tpl = {0};

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

	s->ip_dst.s_addr = NAT_C_ADDR;
	s->th_dport = use_nat_port(port);

	s->ip_src.s_addr = NAT_S_ADDR;
	s->th_sport = (NAT_S_PORT);

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

			int cflags = item->c.flags;
			int sflags = item->s.flags;
			int mflags = (TH_SYN| TH_FIN);
			int s_established = (sflags & mflags) == TH_SYN;
			int c_established = (cflags & mflags) == TH_SYN;
			int timeout = (s_established && c_established)? establish_timeout(_nat_count): 60;

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
	.ip_nat = ip_nat_ipv6,
	.lookup = lookup_ipv6,
	.newconn = newconn_ipv6
};

static nat_conntrack_t * lookup_nat(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	nat_conntrack_t *item;

	LIST_FOREACH(item, &_ipv4_header, entry) {
		if (item->s.th_dport == dport) {
			return item;
		}
	}

	LIST_FOREACH(item, &_ipv6_header, entry) {
		if (item->s.th_dport == dport) {
			return item;
		}
	}

	return NULL;
}

static nat_conntrack_t * newconn_nat(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	return NULL;
}

static nat_conntrack_ops cok_conntrack_ops = {
	.ip_nat = ip_nat_ipv4,
	.adjust = adjust_ipv4,
	.lookup = lookup_nat,
	.newconn = newconn_nat
};

static nat_conntrack_ops cok6_conntrack_ops = {
	.ip_nat = ip_nat_ipv6,
	.adjust = adjust_ipv6,
	.lookup = lookup_nat,
	.newconn = newconn_nat
};

static int ip_nat_fast(tcp_state_t *tcpcb, uint8_t *packet)
{
	uint16_t d0, d1;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;
	xchg(ip->ip_src, ip->ip_dst, struct in_addr);
	return 0;
}

static nat_conntrack_t * lookup_fast(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;
	static nat_conntrack_t st;

	if (sport == NAT_SSL_PORT) {
		st.c.th_dport = SSL_PORT;
		st.c.th_sport = dport;
	} else if (sport == NAT_WEB_PORT) {
		st.c.th_dport = WEB_PORT;
		st.c.th_sport = dport;
	} else if (dport == SSL_PORT) {
		st.c.th_sport = NAT_SSL_PORT;
		st.c.th_dport = sport;
	} else if (dport == WEB_PORT) {
		st.c.th_sport = NAT_WEB_PORT;
		st.c.th_dport = sport;
	}

	st.c.th_sum  = sport - st.c.th_sport;
	st.c.th_sum += dport - st.c.th_dport;

	return &st;
}

static nat_conntrack_ops fast_conntrack_ops = {
	.ip_nat = ip_nat_fast,
	.adjust = NULL,
	.lookup = lookup_fast,
	.newconn = NULL
};

void *m_off(void *ptr, int off) 
{
	uint8_t *m = (uint8_t *)ptr;
	return (m + off);
}

#define NAT_MODE_CLIENT_TO_SERVER 0x2
#define NAT_MODE_SERVER_TO_CLIENT 0x3
#define NAT_MODE_STATELESS_FAST   0x4
#define NAT_MODE_NOT_SUPPORT      0x5

static int nat_get_mode(const nat_iphdr_t *ip, const nat_tcphdr_t *th, nat_conntrack_ops **ops)
{
	if (ip->ip_v == VERSION_IPV4 &&
			ip->ip_dst.s_addr == NAT_C_ADDR &&
			ip->ip_src.s_addr == NAT_S_ADDR && th->th_sport == NAT_S_PORT) {
		*ops = &cok_conntrack_ops;
		return NAT_MODE_SERVER_TO_CLIENT;
	}

#if 0 
	if (ip->ip_v == VERSION_IPV4 &&
			ip->ip_dst.s_addr != NAT_C_ADDR &&
			ip->ip_src.s_addr == NAT_S_ADDR &&
			(th->th_sport == NAT_WEB_PORT || th->th_dport == WEB_PORT ||
			 th->th_sport == NAT_SSL_PORT || th->th_dport == SSL_PORT)) {
		*ops = &fast_conntrack_ops;
		return NAT_MODE_STATELESS_FAST;
	}
#endif

	if (ip->ip_dst.s_addr == NAT_C_ADDR) {
		*ops = &fast_conntrack_ops;
		return NAT_MODE_NOT_SUPPORT;
	}

	return NAT_MODE_CLIENT_TO_SERVER;
}

enum {
	TCPS_SYN_SENT,
	TCPS_SYN_RECVD,
	TCPS_ESTABLISHED,
	TCPS_CLOSED
};

static int tcp_state(int tcpflags)
{
	int flag;
#if 0
	int mask = TH_SYN| TH_ACK| TH_FIN| TH_RST;
#else
	int mask = TH_SYN| TH_ACK| TH_RST;
#endif

	flag = (tcpflags & mask);

	switch (flag) {
		case TH_SYN:
			return TCPS_SYN_SENT;

		case (TH_SYN| TH_ACK):
			return TCPS_SYN_RECVD;

		case TH_ACK:
			return TCPS_ESTABLISHED;

		default:
			return TCPS_CLOSED;
	}

	return TCPS_ESTABLISHED;
}

#define inject_len 13

ssize_t tcp_frag_rst(nat_tcphdr_t *th, uint8_t *packet);
#if 0
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
#endif

__attribute__((weak)) int socks5_cmd(void *buf, nat_iphdr_t *ip, nat_tcphdr_t *tcp)
{
	char *cmdp = (char *)buf;

	*cmdp++ = 0x05;
	*cmdp++ = 0x01;
	*cmdp++ = 0x00;

	*cmdp++ = 0x05;
	*cmdp++ = 0x01;
	*cmdp++ = 0x00;
	*cmdp++ = 0x01;

	memcpy(cmdp, &ip->ip_dst, 4);
	cmdp += 4;

	memcpy(cmdp, &tcp->th_dport, 2);
	cmdp += 2;

	return cmdp - (char *)buf;
}

static int handle_server_to_client(nat_conntrack_t *conn, nat_conntrack_ops *ops, nat_tcphdr_t *th, uint8_t *packet, size_t len)
{
	nat_tcphdr_t h1;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	int data_acked;
	int datalen, seq_flag;
	uint16_t old_len_flag, new_len_flag;
	int state = tcp_state(th->th_flags);

	switch (state) {
		case TCPS_SYN_RECVD:
			/* nat: server -> client, dec seq=seq + 12, clear SYN */
			h1.th_seq  = ntohl(th->th_seq);
			conn->s.snd_max = h1.th_seq +1;
			conn->s.seq_meta = h1.th_seq +13;
			conn->last_meta  = time(NULL);
			conn->s.flags   |= NEED_ACK_ADJUST;

			th->th_seq = htonl(h1.th_seq + 12);
			th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_seq), th->th_seq));

			old_len_flag = *(uint16_t *) m_off(th, 12);
			th->th_flags &= ~TH_ACK;
			new_len_flag = *(uint16_t *) m_off(th, 12);
			th->th_sum = update_cksum(th->th_sum, old_len_flag - new_len_flag);
			break;

		case TCPS_ESTABLISHED:
			/* nat: server -> client */
			h1.th_seq  = ntohl(th->th_seq);
			h1.th_ack  = ntohl(th->th_ack);
			datalen = d_off(m_off(packet, len), th) - (th->th_off << 2);

			if (SEQ_LT(conn->s.rcv_nxt, h1.th_ack)) {
				conn->s.rcv_nxt = h1.th_ack;
			}

			h1.th_flags = th->th_flags;
			seq_flag = (CHECK_FLAGS(h1.th_flags, TH_SYN) > 0) + (CHECK_FLAGS(h1.th_flags, TH_FIN) > 0);
			if (SEQ_LT(conn->s.snd_max, h1.th_seq + datalen + seq_flag)) {
				conn->s.snd_max = h1.th_seq + datalen + seq_flag;
				if (SEQ_LT(conn->s.seq_meta, conn->s.snd_max)) {
					conn->s.flags &= ~NEED_ACK_ADJUST;
				}
			}

			if (((conn->c.flags & NEED_ACK_ADJUST) ||
						(conn->last_meta + 120 > time(NULL))) &&
					SEQ_LT(h1.th_seq, conn->c.rcv_nxt) &&
					SEQ_LT(h1.th_seq, conn->s.seq_meta) &&
					SEQ_GEQ(h1.th_seq, conn->s.seq_meta - 12)) {
				conn->last_meta = time(NULL);
				if (SEQ_LT(conn->c.rcv_nxt, h1.th_seq + datalen)) {
					int off = (th->th_off << 2);
					int adj = (int)(conn->c.rcv_nxt - h1.th_seq);

					if (th->th_flags & TH_FIN) {
						conn->c.flags |= TH_RST;
						return tcp_frag_rst(th, packet);
					}

					th->th_seq = htonl(conn->c.rcv_nxt);
					th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_seq), th->th_seq));

					uint8_t *mem = m_off(th, off);
					th->th_sum = update_cksum(th->th_sum, -cksum_delta(mem, adj));
					th->th_sum = update_cksum(th->th_sum, htons(adj));
					memmove(mem, mem + adj, datalen - adj);
					len -= adj;

					(*ops->adjust)(packet, -adj);
					assert(1 & ~adj);
				} else if (datalen > 0 || SEQ_GEQ(h1.th_ack, conn->c.seq_meta)) {
					th->th_seq = htonl(conn->c.rcv_nxt -(datalen > 0 && CHECK_FLAGS(th->th_flags, TH_ACK| TH_FIN) == TH_ACK));
					th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_seq), th->th_seq));

					th->th_sum = update_cksum(th->th_sum, -cksum_delta(m_off(packet, len - datalen), datalen));
					th->th_sum = update_cksum(th->th_sum, htons(datalen));
					len -= datalen;

					(*ops->adjust)(packet, -datalen);
				} else {
					if (th->th_flags & TH_FIN) {
						conn->c.flags |= TH_RST;
						return tcp_frag_rst(th, packet);
					}
					log_verbose("just ignore\n");
					return 0;
				}
			}

			break;

		case TCPS_CLOSED:
			h1.th_ack  = ntohl(th->th_ack);
			if (SEQ_GEQ(conn->c.snd_max, h1.th_ack) &&
					SEQ_LT(conn->c.snd_max, h1.th_ack + inject_len)) {
#if 0
				th->th_ack = htonl(h1.th_ack + inject_len);
				th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_ack), th->th_ack));
#else
				conn->c.flags |= TH_RST;
				return tcp_frag_rst(th, packet);
#endif
			}
			break;

		default:
			break;

	}

	return len;
}

static int handle_client_to_server(nat_conntrack_t *conn, nat_conntrack_ops *ops, nat_tcphdr_t *th, uint8_t *packet, size_t len)
{
	nat_tcphdr_t h1;
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	uint16_t tlen;
	int sublen, datalen, seq_flag;
	uint16_t old_len_flag, new_len_flag;
	int state = tcp_state(th->th_flags);

	switch (state) {
		case TCPS_SYN_SENT:
			/* nat: client -> server, dec seq=seq - inject length */
			h1.th_seq  = ntohl(th->th_seq);
			conn->c.snd_max = h1.th_seq +1;
			conn->c.seq_meta = h1.th_seq +1;
			conn->c.flags   |= NEED_ACK_ADJUST;

			sublen = socks5_cmd(m_off(packet, len), ip, th);
			th->th_seq = htonl(h1.th_seq - sublen);
			th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_seq), th->th_seq));
			break;

		case TCPS_SYN_RECVD:
			/* nat: client -> server, dec seq=seq - 13, clear SYN */
			h1.th_seq  = ntohl(th->th_seq);
			h1.th_ack  = ntohl(th->th_ack);
			conn->c.rcv_nxt = h1.th_ack;

			sublen = socks5_cmd(m_off(packet, len), ip, th);
			th->th_ack = htonl(h1.th_ack - 12);
			th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_ack), th->th_ack));
			th->th_seq = htonl(h1.th_seq - sublen + 1);
			th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_seq), th->th_seq));
			th->th_sum = update_cksum(th->th_sum, cksum_delta(m_off(packet, len), sublen));
			th->th_sum = update_cksum(th->th_sum, -htons(sublen));
			len += sublen;

			old_len_flag = *(uint16_t *) m_off(th, 12);
			th->th_flags &= ~TH_SYN;
			new_len_flag = *(uint16_t *) m_off(th, 12);
			th->th_sum = update_cksum(th->th_sum, old_len_flag - new_len_flag);

			(*ops->adjust)(packet, sublen);
			break;

		case TCPS_ESTABLISHED:
			/* nat: client -> server */
			h1.th_ack  = ntohl(th->th_ack);
			h1.th_seq  = ntohl(th->th_seq);
			datalen = d_off(m_off(packet, len), th) - (th->th_off << 2);

			if (SEQ_LT(conn->c.rcv_nxt, h1.th_ack)) {
				conn->c.rcv_nxt = h1.th_ack;
				if (SEQ_LT(conn->c.seq_meta, conn->c.rcv_nxt)) {
					conn->c.flags &= ~NEED_ACK_ADJUST;
				}
			}

			h1.th_flags = th->th_flags;
			seq_flag = (CHECK_FLAGS(h1.th_flags, TH_SYN) > 0) + (CHECK_FLAGS(h1.th_flags, TH_FIN) > 0);
			if (SEQ_LT(conn->c.snd_max, h1.th_seq + datalen + seq_flag)) {
				conn->c.snd_max = h1.th_seq + datalen + seq_flag;
			}

			if ((conn->s.flags & NEED_ACK_ADJUST) &&
					SEQ_GEQ(h1.th_ack, conn->s.seq_meta)) {
				th->th_ack = htonl(conn->s.snd_max);
				th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_ack), th->th_ack));
				log_verbose("from client snd_max %x th_ack %x\n", conn->s.snd_max, h1.th_ack);
			}
			break;

		case TCPS_CLOSED:
			if ((conn->s.flags & NEED_ACK_ADJUST) &&
					SEQ_GEQ(h1.th_ack, conn->s.seq_meta)) {
				conn->s.flags |= TH_FLAGS;
				return tcp_frag_rst(th, packet);
			}
			break;

		default:
			break;
	}

	return len;
}

#if defined(ENABLE_OUTLINE_META)
#define handle_client_to_server(a, b, c, d, l) (l)
#define handle_server_to_client(a, b, c, d, l) (l)
#endif

ssize_t tcp_frag_nat(void *packet, size_t len, size_t limit)
{
	int nat_mode;
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
		nat_mode = nat_get_mode(ip, th, &ops);
	} else if (ip->ip_v == VERSION_IPV6) {
		ip6 = (nat_ip6hdr_t *)packet;
		CHECK_NAT_PROTOCOL(ip6->ip6_nxt, IPPROTO_TCP);
		th  = (nat_tcphdr_t *)(ip6 + 1);
		ops = (nat_conntrack_ops *)&ip6_conntrack_ops;
		nat_mode = NAT_MODE_CLIENT_TO_SERVER;
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

	if (nat_mode == NAT_MODE_CLIENT_TO_SERVER) {
		tcpcb = &conn->s;
		len = handle_client_to_server(conn, ops, th, packet, len);
	} else if (nat_mode == NAT_MODE_SERVER_TO_CLIENT) {
		tcpcb = &conn->c;
		len = handle_server_to_client(conn, ops, th, packet, len);
	} else if (nat_mode == NAT_MODE_STATELESS_FAST) {
		/* state less, fast nat process */
		tcpcb = &conn->c;
	} else {
		/* reset unsupport tcp connection */
		return tcp_frag_rst(th, packet);
	}

	tcpcb->flags |= th->th_flags;
	/* process NAPT, update tcp src port and dst port, update src ip and dest ip also. */
	(*ops->ip_nat)(tcpcb, packet);
	th->th_sport = tcpcb->th_dport;
	th->th_dport = tcpcb->th_sport;
	th->th_sum = update_cksum(th->th_sum, tcpcb->th_sum);

	return len;
}

void tcp_nat_init(struct sockaddr_in *ifaddr, struct sockaddr_in *target)
{
	_nat_c_addr = ifaddr->sin_addr.s_addr;
	_nat_s_addr = target->sin_addr.s_addr;
	_nat_s_port = target->sin_port;

	_nat_ssl_port = htons(8080);
	_nat_web_port = htons(8443);
	init_ip6_tpl(&ip6_tpl);

	return;
}
