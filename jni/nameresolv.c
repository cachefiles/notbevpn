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

static char SUFFIXES[128] = ".pac.yrli.bid";
static port_pool_t _nat_pool = {};
#define __unmap_code(x) __map_code(x)

static int __map_code(int c)
{
    int cc = (c & 0xFF);

    if ('A' <= cc && cc <= 'Z') {
        return 'A' + (cc - 'A' + 13) % 26;
    }

    if ('a' <= cc && cc <= 'z') {
        return 'a' + (cc - 'a' + 13) % 26;
    }

    return cc;
}

static void domain_rewrap(char *dst, const char *src)
{
    char *d = dst;
    const char *s = src;

    while (*s) {
        *d++ = __unmap_code(*s);
        s++;
    }

    strcpy(d, SUFFIXES);
    return;
}

static char * domain_unwrap(char *name)
{
	int l;
    char *n = name;
    size_t ln = -1;
    size_t lt = strlen(SUFFIXES);

    if (n == NULL || *n == 0) {
        return NULL;
    }

    ln = strlen(n);
    if (lt < ln && strcasecmp(n + ln - lt, SUFFIXES) == 0) {
        n[ln - lt] = 0;
        for (l = 0; l < ln - lt; l++) n[l] = __map_code(n[l]);
        return name;
    }

    return NULL;
}

struct resolv_t {
	int flags;
	uint16_t ident;
	struct sockaddr_in6 from;
	struct sockaddr_in6 dest;
};

static int _wheel = 0;
struct resolv_t _pending_resolv[512];

static int resolv_record(int ident, struct sockaddr_in6 *from, struct sockaddr_in6 *dest, int flags)
{
	int i;
	int wheel = _wheel;

	for (i = 0; i < 512; i++) {
		if (ident == _pending_resolv[i].ident) {
			_pending_resolv[i].from = *from;
			_pending_resolv[i].flags = flags;
			return 0;
		}
	}

	_wheel = (wheel + 1) & 0x1FF;
	_pending_resolv[wheel].from = *from;
	_pending_resolv[wheel].dest = *dest;
	_pending_resolv[wheel].ident = ident;
	_pending_resolv[wheel].flags = flags;
	return 0;
}

static struct sockaddr_in6 * resolv_fetch(int ident, struct sockaddr_in6 *from)
{
	int i;

	for (i = 0; i < 512; i++) {
		if (ident == _pending_resolv[i].ident) {
			if (_pending_resolv[i].flags)
				*from = _pending_resolv[i].dest;
			return &_pending_resolv[i].from;
		}
	}

	return 0;
}


int resolv_invoke(int dnsfd, char *packet, size_t len, struct sockaddr_in6 *dest, struct sockaddr_in6 *from, int tethering)
{
	int i;
	int error;

	char crypt[256];
	char sndbuf[2048];

	struct dns_parser parser;
	struct dns_question *que;

	if (NULL == dns_parse(&parser, (uint8_t *) packet, len)) {
		return -1;
	}

	for (i = 0; i < parser.head.question; i++) {
		que = &parser.question[i];

		domain_rewrap(crypt, que->domain);
		que->domain = add_domain(&parser, crypt);
	}

	len = dns_build(&parser, (uint8_t *)sndbuf, sizeof(sndbuf));
	if (len <= 0) {
		return -1;
	}

	int flags = 0;
	struct sockaddr_in6 _save_addr = *dest;

#ifdef __ANDROID__
	_save_addr = *dest;
	// flags = get_dns_addr(dest, tethering);
	inet_pton(AF_INET6, &dest->sin6_addr, "::ffff:114.114.114.114");
	flags = 1;
#else
	_save_addr = *dest;
	inet_pton(AF_INET6, &dest->sin6_addr, "::ffff:114.114.114.114");
	flags = 1;

	static int dns_override = 0;
	static struct sockaddr_in6 _relay = {};
	if (dns_override || getenv("DNSRELAY")) {
		char *ptr, _dummy[512];
		if (dns_override == 0) {
			strcpy(_dummy, getenv("DNSRELAY"));
			_relay.sin6_family = AF_INET6;
			_relay.sin6_port   = htons(53);
			ptr = strchr(_dummy, ':');
			if (ptr != NULL) {
				*ptr++= 0;
				_relay.sin6_port = htons(atoi(ptr));
			}
			inet_pton(AF_INET6, &_relay.sin6_addr, _dummy);
			dns_override = 1;
		}
#ifdef SO_BINDTODEVICE
		setsockopt(dnsfd, SOL_SOCKET, SO_BINDTODEVICE, "", 0);
#endif
		*dest = _relay;
	}
#endif

	resolv_record(parser.head.ident, from, &_save_addr, flags);
	error = sendto(dnsfd, sndbuf, len, 0, (struct sockaddr *)dest, sizeof(*dest));
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
	int total = 0;
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
	int i;
	int have_suffixes = 0;

	char name[256];
	char sndbuf[2048];
	char * crypt = NULL;
	char * plain = NULL;

	struct dns_parser parser;
	struct dns_question *que;
	struct dns_resource *res;
	struct sockaddr_in6 *dest;

	if (NULL == dns_parse(&parser, (uint8_t *) packet, len)) {
		return -1;
	}

	for (i = 0; i < parser.head.question; i++) {
		que = &parser.question[i];

		strcpy(name, que->domain);
		domain_unwrap(name);

		crypt = que->domain;
		que->domain = plain = add_domain(&parser, name);
		if (que->domain == NULL) {
			return -1;
		}
	}

	int nanswer = 0;
	for (i = 0; i < parser.head.answer; i++) {
		res = &parser.answer[i];
		struct dns_cname *ptr = (struct dns_cname *)res->value;

		LOG_VERBOSE("an %d: %s T%d\n", i, res->domain, res->type);
		if (strcasecmp(res->domain, crypt) == 0) {
			res->domain = parser.question[0].domain;
		}

		if (res->type == NSTYPE_CNAME && strstr(ptr->alias, "yrli.bid") == NULL) {
			have_suffixes = 1;
			if (strcasecmp(plain, ptr->alias) == 0) {
				continue;
			}
		}

		if (strcasecmp(crypt, res->domain) == 0) {
			res->domain = plain;
		}

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

		if (nanswer++ < i)
			parser.answer[nanswer - 1] = *res;

#if 0
		if (res->type == NSTYPE_A && have_suffixes == 1) {
			add_dns_route(res->value);
			res->value = 
		}
#endif
	}
	parser.head.answer = nanswer;

	nat_iphdr_t *ip;
	nat_udphdr_t *uh;

	ip = (nat_iphdr_t *)sndbuf;
	uh = (nat_udphdr_t *)(ip + 1);

	len = dns_build(&parser, (uint8_t *)(uh + 1), sizeof(sndbuf) - sizeof(*uh) - sizeof(*ip));
	if (len <= 0) {
		return -1;
	}

	dest = resolv_fetch(parser.head.ident, from);
	if (dest == NULL) {
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
