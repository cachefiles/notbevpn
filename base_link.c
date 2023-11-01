#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <base_link.h>

#include <config.h>

static int _ack_type = ACK_TYPE_NONE;

int get_ack_type()
{
	return _ack_type;
}

int set_ack_type(int type)
{
	return _ack_type = type;
}

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	// memmove(dst, src, len);
	uint8_t * fdst = dst, * fsrc = src;

	for (int i = 0; i < len; i++) fdst[i] = fsrc[i] ^ 0x0f;
	return 0;
}

int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	// memmove(dst, src, len);
	uint8_t * fdst = dst, * fsrc = src;

	for (int i = 0; i < len; i++) fdst[i] = fsrc[i] ^ 0x0f;
	return 0;
}

static int _last_proto = 0;
static char _last_head[4] = {};
static struct sockaddr_in6 _last_dest = {};

int protect_match(void *buf, size_t len)
{
	int match = 0;
	struct ip *iph = (struct ip *)buf;
	struct in_addr d;

	inet_6to4(&d, &_last_dest.sin6_addr);
	if (iph->ip_v == 0x4 &&
			iph->ip_p == _last_proto &&
			memcmp(&iph->ip_dst, &d, 4)) {
		struct udphdr *uh = (struct udphdr *)(iph + 1); 
		switch (_last_proto) {
			case IPPROTO_UDP:
				match = (uh->uh_dport == _last_dest.sin6_port);
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

int inet_4to6(void *dst, const void *src)
{
	char *v6ip = (char *)dst;
	const char *v4ip = (const char *)src;

	memmove(v6ip + 12, v4ip, 4);
	memset(v6ip + 10, 0xff, 2);
	memset(v6ip, 0, 10);
	return 0;
}

int inet_6to4(void *dst, const void *src)
{
	char *v4ip = (char *)dst;
	const char *v6ip = (const char *)src;

	if (IN6_IS_ADDR_V4MAPPED(src))
		memmove(v4ip, v6ip + 12, 4);

	return 0;
}

const char *ntop6(const void *v6ip)
{
	static char buf[256];
	return inet_ntop(AF_INET6, v6ip, buf, sizeof(buf));
}
