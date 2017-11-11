#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <base_link.h>

#include <config.h>

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	int i;
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	for (i = 0; i < len; i++) {
		*fdst++ = (*fsrc++ ^ d0);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	return 0;
}

int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	int i;
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	for (i = 0; i < len; i++) {
		*fdst++ = (*fsrc++ ^ d0);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	return 0;
}

static int _last_proto = 0;
static char _last_head[4] = {};
static struct sockaddr_in _last_dest = {};

int protect_match(void *buf, size_t len)
{
	int match = 0;
	struct ip *iph = (struct ip *)buf;

	if (iph->ip_v == 0x4 &&
			iph->ip_p == _last_proto &&
			iph->ip_dst.s_addr == _last_dest.sin_addr.s_addr) {
		struct udphdr *uh = (struct udphdr *)(iph + 1); 
		switch (_last_proto) {
			case IPPROTO_UDP:
				match = (uh->uh_dport == _last_dest.sin_port);
				break;

			case IPPROTO_ICMP:
			case IPPROTO_TCP:
				match = (memcmp(_last_head, iph + 1, 4) == 0);
				break;
		}
	}

	if (match == 1) {
		LOG_DEBUG("loop detected");
	}

	return match;
}

int protect_reset(int proto, void *buf, size_t len, const struct sockaddr *ll_addr, socklen_t ll_len)
{
	_last_proto = proto;
	memcpy(_last_head, buf, 4);
	memcpy(&_last_dest, ll_addr, ll_len);
	return 0;
}
