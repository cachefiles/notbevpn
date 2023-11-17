#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>

#include <config.h>
#include <base_link.h>
#include <bsdinet/tcpup.h>

#include "dnsproto.h"
#include "natimpl.h"
#include "portpool.h"

#ifndef WIN32
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif

typedef struct ip nat_iphdr_t;
typedef struct tcphdr nat_tcphdr_t;
typedef struct udphdr nat_udphdr_t;
typedef struct ip6_hdr nat_ip6hdr_t;

static port_pool_t _nat_pool = {};

#define DOTOFEXT 2
#define LENOFEXT (sizeof(SUFFIXES) - 1)
static char SUFFIXES[] = "cootail.com";

struct resolv_t {
	int flags;
	uint16_t ident;
	struct sockaddr_in6 from;
	struct sockaddr_in6 dest;
};

static int _wheel = 0;
struct resolv_t _pending_table_0[16];
struct resolv_t _pending_table_1[512];

static int resolv_record(int ident, struct sockaddr_in6 *from, struct sockaddr_in6 *dest, int flags)
{
	int i;
	int wheel = _wheel;

	for (i = 0; i < 16; i++) {
		if (ident == _pending_table_0[i].ident) {
			_pending_table_0[i].from = *from;
			_pending_table_0[i].flags = flags;
			goto check_continue;
		}
	}

	_wheel = (wheel + 1) & 0xF;
	_pending_table_0[wheel].from = *from;
	_pending_table_0[wheel].dest = *dest;
	_pending_table_0[wheel].ident = ident;
	_pending_table_0[wheel].flags = flags;

	i = (ident & 0x1FF);
	_pending_table_1[i].from = *from;
	_pending_table_1[i].dest = *dest;
	_pending_table_1[i].ident = ident;
	_pending_table_1[i].flags = flags;

	return 0;

check_continue:
	i = (ident & 0x1FF);
	if (ident == _pending_table_1[i].ident) {
		_pending_table_1[i].from = *from;
		_pending_table_1[i].flags = flags;
	}

	return 0;
}

static struct sockaddr_in6 * resolv_fetch(int ident, struct sockaddr_in6 *from, int *pflags)
{
	int i;

	i = (ident & 0x1FF);
	if (_pending_table_1[i].ident == ident) {
		if (_pending_table_1[i].flags)
			*from = _pending_table_1[i].dest;
		if (pflags)
			*pflags = _pending_table_1[i].flags;
		return &_pending_table_1[i].from;
	}

	for (i = 0; i < 16; i++) {
		if (ident == _pending_table_0[i].ident) {
			if (_pending_table_0[i].flags)
				*from = _pending_table_0[i].dest;
			if (pflags)
				*pflags = _pending_table_0[i].flags;
			return &_pending_table_0[i].from;
		}
	}

	return 0;
}

static const char *_tld1[] = {
	"ten.", "ude.", "oc.", "gro.", "moc.", "vog.", NULL
};

static const char *_tld0[] = {
	"net.", "edu.", "co.", "org.", "com.", "gov.", NULL
};

static int dns_contains(const char *domain, const char *table[])
{
	int i;

	for (i = 0; table[i]; i++) {
		if (strncmp(domain, table[i], 4) == 0) {
			return 1;
		}
	}

	if (strncmp(domain, "co.", 3) == 0 && table == _tld0) {
		return 1;
	}

	if (strncmp(domain, "oc.", 3) == 0 && table == _tld1) {
		return 1;
	}

	return 0;
}

static const char *domain_rewrap(struct dns_parser *p1, const char *domain)
{
	int ndot = 0;
	char *limit, *optp;
	char *dots[8] = {}, title[256];
	const char *iter = NULL;

	optp = title;
	dots[ndot & 0x7] = title;

	limit = title + sizeof(title);
	for (iter = domain; *iter; iter++) {
		switch(*iter) {
			case '.':
				if (optp > dots[ndot & 0x7]) ndot++;
				assert(optp < limit);
				*optp++ = *iter;
				dots[ndot & 0x7] = optp;
				break;

			default:
				assert(optp < limit);
				*optp++ = *iter;
				break;
		}
	}

	*optp = 0;
	if (optp > dots[ndot & 0x7]) ndot++;

	if (ndot < 2) {
		return domain;
	}

	assert(ndot >= 2);
	if (ndot < DOTOFEXT || !strcasecmp(dots[(ndot - DOTOFEXT) & 0x7], SUFFIXES)) {
		return 0;
	}

	assert(optp < limit);
	snprintf(optp, limit - optp, ".%s", SUFFIXES);

	limit = optp - 1;
	ndot--;
	optp = dots[ndot & 0x7];

	if (ndot < 1) {
		LOG_DEBUG("dns_rewrap warning %s XX", title);
		return add_domain(p1, title);
	}

	int cc = 0;
	if (optp + 1 == limit) {
		limit = dots[ndot & 0x7] -2;
		ndot--;
		optp = dots[ndot & 0x7];
		cc = 1;
	}

	if (cc == 0 || dns_contains(optp, _tld0)) {
		for (; *optp && optp < limit; optp++) {
			char t = *optp;
			*optp = *limit;
			*limit-- = t;
		}

		if (ndot < 1) {
			LOG_DEBUG("dns_rewrap ork %s", title);
			return add_domain(p1, title);
		}

		limit = dots[ndot & 0x7] -2;
		ndot--;
		optp = dots[ndot & 0x7];
	}

	char t = *optp;
	memmove(optp, optp + 1, limit - optp);
	*limit = t;

	LOG_DEBUG("dns_rewrap title=%s cc=%d", title, cc);
	return add_domain(p1, title);
}

static const char *domain_unwrap(struct dns_parser *p1, const char *domain)
{
	int ndot = 0;
	char *limit, *optp;
	char *dots[8] = {}, title[256];
	const char *iter = domain;

	optp = title;
	dots[ndot & 0x7] = title;

	limit = title + sizeof(title);
	for (iter; *iter; iter++) {
		switch(*iter) {
			case '.':
				if (optp > dots[ndot & 0x7]) ndot++;
				assert(optp < limit);
				*optp++ = *iter;
				dots[ndot & 0x7] = optp;
				break;

			default:
				assert(optp < limit);
				*optp++ = *iter;
				break;
		}
	}

	*optp = 0;
	if (optp > dots[ndot & 0x7]) ndot++;

	if (ndot < 2 + DOTOFEXT) {
		return domain;
	}

	assert(ndot >= DOTOFEXT);
	if (strcmp(dots[(ndot - DOTOFEXT) & 0x7], SUFFIXES)) {
		return domain;
	}

	ndot -= DOTOFEXT;
	limit = dots[ndot & 0x7] -2;
	limit[1] = 0;
	ndot--;
	optp = dots[ndot & 0x7];

	if (ndot < 1) {
		LOG_DEBUG("dns_unwrap warning %s XX", title);
		return add_domain(p1, title);
	}

	int cc = 0;
	if (optp + 1 == limit) {
		limit = dots[ndot & 0x7] -2;
		ndot--;
		optp = dots[ndot & 0x7];
		cc = 1;
	}

	if (cc == 0 || dns_contains(optp, _tld1)) {
		for (; *optp && optp < limit; optp++) {
			char t = *optp;
			*optp = *limit;
			*limit-- = t;
		}

		if (ndot < 1) {
			LOG_DEBUG("dns_unwrap ork %s", title);
			return add_domain(p1, title);
		}

		limit = dots[ndot & 0x7] -2;
		ndot--;
		optp = dots[ndot & 0x7];
	}

	char t = *limit;
	memmove(optp + 1, optp, limit - optp);
	*optp = t;

	LOG_DEBUG("dns_unwrap title=%s cc=%d", title, cc);
	return add_domain(p1, title);
}

static int get_dns_server(struct sockaddr_in6 *dest)
{
	char *ptr, _dummy[512];
	static int dns_override = 0;
	static struct sockaddr_in6 _relay = {.sin6_family = AF_INET6};

	if (dns_override == 0 && getenv("DNSRELAY")) {
		strcpy(_dummy, getenv("DNSRELAY"));
		_relay.sin6_port   = htons(53);

		if (*_dummy == '[') {
			ptr = strchr(_dummy, ']');
			*ptr++= 0;
			_relay.sin6_port = htons(atoi(ptr + 1));
			inet_pton(AF_INET6, _dummy + 1, &_relay.sin6_addr);
		} else if (strchr(_dummy, ':') == NULL) {
			snprintf(_dummy, sizeof(_dummy), "::ffff:%s", getenv("DNSRELAY"));
			inet_pton(AF_INET6, _dummy, &_relay.sin6_addr);
		} else if (strrchr(_dummy, ':') != strchr(_dummy, ':')) {
			inet_pton(AF_INET6, _dummy, &_relay.sin6_addr);
		} else {
			ptr = strchr(_dummy, ':');
			*ptr++= 0;
			_relay.sin6_port = htons(atoi(ptr + 1));
			inet_pton(AF_INET, _dummy, &_relay.sin6_addr);
			inet_4to6(&_relay.sin6_addr, &_relay.sin6_addr);
		}

		dns_override = 1;
	}

	if (dns_override) {
		*dest = _relay;
		return 1;
	}

	return 0;
}

int resolv_invoke(int dnsfd, char *packet, size_t len, struct sockaddr_in6 *dest, struct sockaddr_in6 *from, int tethering)
{
	int i;
	int error;
	int dupout = 0;
	int flags = 0;
	int oldlen = len;
	char sndbuf[2048];

	struct dns_parser parser;
	struct dns_question *que;

	struct dns_parser *pp = dns_parse(&parser, (uint8_t *)packet, len);

	if (NULL ==  pp) {
		LOG_VERBOSE("resolv_invoke, parse failue");
		return -1;
	}

	for (i = 0; i < parser.head.question; i++) {
		que = &pp->question[i];
		assert(que->domain);

		if (que->type != NSTYPE_AAAA && que->type != NSTYPE_A) {
			continue;
		}

		dupout = (NSTYPE_A == que->type);

		if (getenv("REFUSED_AAAA")) {
			continue;
		}

		size_t off = strlen(que->domain);
		if (off < LENOFEXT || 0 != strcmp(que->domain + off - LENOFEXT, SUFFIXES)) {
			const char *origin = que->domain;
			que->domain = domain_rewrap(pp, que->domain);
			flags = (origin != que->domain) << 1;
		}
	}

	len = dns_build(&parser, (uint8_t *)sndbuf, sizeof(sndbuf));
	if (len <= 0) {
		return -1;
	}

	struct sockaddr_in6 _save_addr = *dest;

#ifdef __ANDROID__
	_save_addr = *dest;
	// flags = get_dns_addr(dest, tethering);
	inet_pton(AF_INET6, getenv("NAMESERVER"), &dest->sin6_addr);
	flags |= 1;
#else
	_save_addr = *dest;
	inet_pton(AF_INET6, getenv("NAMESERVER"), &dest->sin6_addr);
	flags |= 1;
#ifdef SO_BINDTODEVICE
	if (get_dns_server(dest))
		setsockopt(dnsfd, SOL_SOCKET, SO_BINDTODEVICE, "", 0);
#else
	if (get_dns_server(dest))
		LOG_DEBUG("get dns server is good");
#endif
#endif

	resolv_record(parser.head.ident, from, &_save_addr, flags);
	error = sendto(dnsfd, sndbuf, len, 0, (struct sockaddr *)dest, sizeof(*dest));
	if (dupout) 
		error = sendto(dnsfd, packet, oldlen, 0, (struct sockaddr *)dest, sizeof(*dest));
	return error;
}

static int ip4_mktpl(nat_iphdr_t *ip, struct sockaddr_in6 *from, struct sockaddr_in6 *dest, size_t len)
{
	unsigned char tmp[] = {
		0x45, 0x00, 0x00, 0x50, 0x3e, 0x65, 0x00, 0x00,
		0x32, 0x11, 0x8c, 0x27, 0xd3, 0x90, 0x0a, 0x6a,
		0xca, 0x05, 0x16, 0x11
	};

	memcpy(ip, tmp, sizeof(*ip));
	inet_6to4(&ip->ip_src, &from->sin6_addr);
	inet_6to4(&ip->ip_dst, &dest->sin6_addr);
	ip->ip_len = htons(len + 8 + 20);
	ip->ip_sum = 0;
	ip->ip_sum = ip_checksum(ip, sizeof(*ip));

	return 0;
}

static int udp_mktpl(nat_udphdr_t *uh, struct sockaddr_in6 *from, struct sockaddr_in6 *dest, size_t len)
{
	int ip_sum;
	unsigned cksum;

	uh->uh_sport = from->sin6_port;
	uh->uh_dport = dest->sin6_port;
	uh->uh_ulen  = htons(len + 8);

	cksum = tcpip_checksum(0, &from->sin6_addr, 16, 0);
	ip_sum = tcpip_checksum(cksum, &dest->sin6_addr, 16, 0);

	uh->uh_sum   = 0;
    uh->uh_sum = udp_checksum(ip_sum, uh, sizeof(*uh) + len);
	return 0;
}

#if defined(__ANDROID__) || defined(WIN32)
static int add_dns_route(const uint8_t *dest)
{
	LOG_DEBUG("not supported");
	return 0;
}

static int free_dns_route(void)
{
	return 0;
}
#else

static int _pending_count = 0;
static int _pending_route[512];
static pid_t _add_route_proc = -1;

static int free_dns_route(void)
{
	int exitcode = 0;

	if (_add_route_proc != -1 &&
			waitpid(_add_route_proc, &exitcode,  WNOHANG) == _add_route_proc) {
		_add_route_proc = -1;
	}

	return 0;
}

static int add_dns_route(const uint8_t *dest)
{
	int total;
	int exitcode = 0;

	total = _pending_count;
	if (_add_route_proc != -1) {
		if (waitpid(_add_route_proc, &exitcode,  WNOHANG) == _add_route_proc) {
			_add_route_proc = -1;
			// _pending_count = 0;
		} else {
			if (_pending_count < 512)
				_pending_route[_pending_count++] = *(int *)dest;
			LOG_VERBOSE("waitpid failure: %d\n", errno);
			return 0;
		}
	}
	LOG_DEBUG("add_dns_route: %x\n", dest[0]);

	_add_route_proc = fork();
	if (_add_route_proc > 0) {
		_pending_count = 0;
		return 0;
	}

	if (_add_route_proc == 0) {
#if 1
		int i;
		char subnet[160];
		snprintf(subnet, sizeof(subnet), "route add -net %d.%d.%d.0/24 -interface utun1", dest[0], dest[1], dest[2]);
		LOG_DEBUG("cmd_0 %s\n", subnet);
		system(subnet);

		for (i = 0; i < _pending_count; i++) {
			dest = (uint8_t *)&_pending_route[i];
			snprintf(subnet, sizeof(subnet), "route add -net %d.%d.%d.0/24 -interface utun1", dest[0], dest[1], dest[2]);
			LOG_DEBUG("cmd_1 %s\n", subnet);
			system(subnet);
		}
#endif
		exit(0);
	}

	return 0;
}
#endif


struct dns_cname {
    const char *alias;
};

int resolv_return(int maxsize, char *packet, size_t len, struct sockaddr_in6 *from)
{
	int i, flags = 0;
	struct dns_parser parser;
	struct dns_question *que;
	struct dns_resource *res;
	struct sockaddr_in6 *dest;

	char sndbuf[2048];
	const char *origin = NULL;

	struct dns_parser *pp = dns_parse(&parser, (uint8_t *)packet, len);
	if (NULL == pp) {
		LOG_DEBUG("ressolv_return parser failure");
		return -1;
	}

	dest = resolv_fetch(parser.head.ident, from, &flags);
	if (dest == NULL) {
		LOG_DEBUG("ressolv record not found");
		return -1;
	}

	for (i = 0; i < parser.head.question; i++) {
		que = &pp->question[i];
		
		if (strlen(que->domain) < LENOFEXT || !(flags & 2)) {
			LOG_DEBUG("ignore: %d %s %d %d", que->type, que->domain, strlen(que->domain), LENOFEXT);
			continue;
		}

		const char *domain = domain_unwrap(&parser, que->domain);
		if (domain == que->domain) {
			origin = NULL;
		} else if (domain) {
			origin = que->domain;
			que->domain = domain;
		}
	}

	assert(que);
	if (origin == NULL && 
			que->type == NSTYPE_A && parser.head.answer == 1) {
		parser.head.answer = 0;
		return -1;
	}

	int nanswer = 0;
	for (i = 0; origin != NULL && i < parser.head.answer; i++) {
		res = &parser.answer[i];
		struct dns_cname *ptr = (struct dns_cname *)res->value;

		LOG_VERBOSE("an %d: %s T%d\n", i, res->domain, res->type);
		if (res->type == NSTYPE_CNAME &&
				res->domain == origin && que->domain == ptr->alias) {
			continue;
		}

		if (res->domain == origin) {
			res->domain = que->domain;
		}

#if 0
		if (res->type == NSTYPE_A && have_suffixes == 0) {
			// add_dns_route(res->value);

			uint16_t ipnat = 0;
			uint32_t ipnatfull = 0;
			uint32_t ipresolv = *(uint32_t*)res->value;

			if (nat_map(res->value, &ipresolv)) { 
				ipnat = alloc_nat_port(&_nat_pool);
				ipnatfull = htonl(ipnat) | inet_addr("10.10.0.0");
				nat_create(ipresolv, ipnatfull);
				use_nat_port(&_nat_pool, ipnat);
				*(uint32_t *)res->value = ipnatfull;
			}
		}

		if (res->type == NSTYPE_A && have_suffixes == 1) {
			add_dns_route(res->value);
		}
#endif
		if (nanswer++ < i)
			parser.answer[nanswer - 1] = *res;
	}

	if (origin != NULL) {
		parser.head.answer = nanswer;
	}

#define NSFLAG_RCODE 0x000F

#define RCODE_NXDOMAIN 3
#define RCODE_SERVFAIL 2
#define RCODE_REFUSED  5

	if (getenv("REFUSED_AAAA")) {
		parser.head.flags &= ~NSFLAG_RCODE;
		parser.head.flags |= RCODE_REFUSED;
		parser.head.answer = 0;
		parser.head.author = 0;
		parser.head.addon = 0;
	}

	nat_iphdr_t *ip;
	nat_udphdr_t *uh;

	ip = (nat_iphdr_t *)sndbuf;
	uh = (nat_udphdr_t *)(ip + 1);

	len = dns_build(&parser, (uint8_t *)(uh + 1), sizeof(sndbuf) - sizeof(*uh) - sizeof(*ip));
	if (len <= 0) {
		return -1;
	}

	ip4_mktpl(ip, from, dest, len);
	udp_mktpl(uh, from, dest, len);
	if (len + sizeof(*uh) + sizeof(*ip) < maxsize) {
		maxsize = len + sizeof(*uh) + sizeof(*ip);
		memcpy(packet, ip, maxsize);
		return maxsize;
	}

	free_dns_route();
	return -1;
}
