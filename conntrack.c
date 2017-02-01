#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

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
#define NEED_ACK_ADJUST 0x08

#define d_off(ptr, base) (((uint8_t *)ptr) - ((uint8_t *)base))

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
	int state;
	int rcv_win;
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

static u_long _nat_c_addr = 0;
static u_long _nat_s_addr = 0;
static u_short _nat_s_port = 0;
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

static void alloc_nat_slot(tcp_state_t *s, tcp_state_t *c, int is_ipv6)
{
	int i;
	uint16_t *src, *dst;
	uint16_t *nats, *natd;
	static unsigned port = 1024;

	s->ip_dst.s_addr = NAT_C_ADDR;
	s->ip_src.s_addr = NAT_S_ADDR;
	s->th_dport = htons(port++);
	s->th_sport = (NAT_S_PORT);

	s->th_sum = 0;
	s->ip_sum = 0;

	if (is_ipv6) {
		for (i = 0; i < 8; i++) {
		}
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
	int last_alive;
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
			return item;
		}
	}

	return NULL;
}

static nat_conntrack_t * newconn_ipv4(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	nat_iphdr_t *ip;
	nat_conntrack_t *conn = ALLOC_NEW(nat_conntrack_t);

	if (conn != NULL) {
		ip = (nat_iphdr_t *)packet;

		conn->c.th_sport = sport;
		conn->c.th_dport = dport;

		conn->c.ip_src = ip->ip_src;
		conn->c.ip_dst = ip->ip_dst;

		alloc_nat_slot(&conn->s, &conn->c, 0);
		LIST_INSERT_HEAD(&_ipv4_header, conn, entry);
	}

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
			return item;
		}
	}

	return NULL;
}

static nat_conntrack_t * newconn_ipv6(uint8_t *packet, uint16_t sport, uint16_t dport)
{
	nat_ip6hdr_t *ip;
	nat_conntrack_t *conn = ALLOC_NEW(nat_conntrack_t);

	if (conn != NULL) {
		ip = (nat_ip6hdr_t *)packet;

		conn->c.th_sport = sport;
		conn->c.th_dport = dport;

		conn->c.ip6_src = ip->ip6_src;
		conn->c.ip6_dst = ip->ip6_dst;

		alloc_nat_slot(&conn->s, &conn->c, 1);
		LIST_INSERT_HEAD(&_ipv6_header, conn, entry);
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

void *m_off(void *ptr, int off) 
{
	uint8_t *m = (uint8_t *)ptr;
	return (m + off);
}

#define NAT_MODE_CLIENT_TO_SERVER 0x2
#define NAT_MODE_SERVER_TO_CLIENT 0x3

static int nat_get_mode(const nat_iphdr_t *ip, const nat_tcphdr_t *th, nat_conntrack_ops **ops)
{
	if (ip->ip_v == VERSION_IPV4 &&
			ip->ip_dst.s_addr == NAT_C_ADDR &&
			ip->ip_src.s_addr == NAT_S_ADDR && th->th_sport == NAT_S_PORT) {
		*ops = &cok_conntrack_ops;
		return NAT_MODE_SERVER_TO_CLIENT;
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

ssize_t tcp_frag_rst(nat_tcphdr_t *th, uint8_t *packet)
{
	nat_iphdr_t *ip = (nat_iphdr_t *)packet;

	th->th_flags = TH_RST;
	th->th_off = (sizeof(*th) >> 2);
	th->th_seq = th->th_ack;
	th->th_ack = 0;
	th->th_urp = 0;
	th->th_win = 0;
	th->th_sum = 0;

	xchg(th->th_sport, th->th_dport, u_int16_t);
	th->th_sum = update_cksum(0xffff, cksum_delta(th, sizeof(*th)));

	/* TODO: update tcp/ip checksum */

	ip->ip_sum = 0;
	ip->ip_len = htons(d_off(th +1, packet));
	xchg(ip->ip_src, ip->ip_dst, struct in_addr);
	ip->ip_sum = update_cksum(0xffff, cksum_delta(packet, sizeof(*ip)));

	return d_off(th +1, packet);
}

static int socks5_cmd(void *buf, nat_iphdr_t *ip, nat_tcphdr_t *tcp)
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
		log_error("invlid ip protocol version: %d", ip->ip_v);
		return 0;
	}

	conn = (*ops->lookup)(packet, th->th_sport, th->th_dport);

	if (conn == NULL) {
		if (th->th_flags & TH_RST) {
			log_verbose("receive RST packet without connection");
			return 0;
		}

		if (th->th_flags & TH_ACK) {
			log_error("receive ACK packet without connection");
			return tcp_frag_rst(th, packet);
		}

		if (!CHECK_FLAGS(th->th_flags, TH_SYN)) {
			log_verbose("receive SYN packet without connection");
			return 0;
		}

		conn = (*ops->newconn)(packet, th->th_sport, th->th_dport);
		CHECK_NAT_FAIL_RETURN(conn != NULL);
	}

	if (nat_mode == NAT_MODE_CLIENT_TO_SERVER) {
		uint16_t tlen;
		int sublen, datalen, seq_flag;
		uint16_t old_len_flag, new_len_flag;
		int state = tcp_state(th->th_flags);

		tcpcb = &conn->s;
		switch (state) {
			case TCPS_SYN_SENT:
				/* nat: client -> server, dec seq=seq - inject length */
				h1.th_seq  = ntohl(th->th_seq);
				conn->c.snd_max = h1.th_seq;
				conn->c.seq_meta = h1.th_seq +1;

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
					fprintf(stderr, "from client snd_max %x th_ack %x\n", conn->s.snd_max, h1.th_ack);
				}
				break;

			case TCPS_CLOSED:
				break;

			default:
				break;
		}
	} else {
		int data_acked;
		int datalen, seq_flag;
		uint16_t old_len_flag, new_len_flag;
		int state = tcp_state(th->th_flags);

		tcpcb = &conn->c;
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

				if (SEQ_LT(h1.th_seq, conn->c.rcv_nxt) &&
						(conn->last_meta + 120 > time(NULL)) &&
						SEQ_LT(h1.th_seq, conn->s.seq_meta) &&
						SEQ_GEQ(h1.th_seq, conn->s.seq_meta - 12)) {
					conn->last_meta = time(NULL);
					if (SEQ_LT(conn->c.rcv_nxt, h1.th_seq + datalen)) {
						int off = (th->th_off << 2);
						int adj = (int)(conn->c.rcv_nxt - h1.th_seq);
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
						fprintf(stderr, "just ignore\n");
						return 0;
					}
				}

				break;

			case TCPS_CLOSED:
				h1.th_ack  = ntohl(th->th_ack);
				if (SEQ_GEQ(conn->c.snd_max, h1.th_ack) &&
						SEQ_LT(conn->c.snd_max, h1.th_ack + inject_len)) {
					th->th_ack = htonl(h1.th_ack + inject_len);
					th->th_sum = update_cksum(th->th_sum, cksum_long_delta(htonl(h1.th_ack), th->th_ack));
				}
				break;

			default:
				break;
			
		}
	}

	/* process NAPT, update tcp src port and dst port, update src ip and dest ip also. */
	(*ops->ip_nat)(tcpcb, packet);
	th->th_sport = tcpcb->th_dport;
	th->th_dport = tcpcb->th_sport;
	th->th_sum = update_cksum(th->th_sum, tcpcb->th_sum);

	return len;
}

void module_init(void)
{
	_nat_c_addr = inet_addr("10.2.0.15");
	_nat_s_addr = inet_addr("10.2.0.2");
	_nat_s_port = htons(8000);
	init_ip6_tpl(&ip6_tpl);

	return;
}
