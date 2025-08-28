#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <base_link.h>

#include <config.h>
#include <bsdinet/tcpup.h>

static int _ack_type = ACK_TYPE_NONE;
extern uint32_t _tcpup_sum;

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
        int i;
	uint8_t * fdst = dst;
        const uint8_t * fsrc = src;

	for (i = 0; i < len; i++) fdst[i] = fsrc[i] ^ 0x0f;
	return 0;
}

int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	// memmove(dst, src, len);
        int i;
	uint8_t * fdst = dst;
        const uint8_t * fsrc = src;

	for (i = 0; i < len; i++) fdst[i] = fsrc[i] ^ 0x0f;
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
	uint32_t *v4ip = (uint32_t *)dst;
	const uint32_t *v6ip = (const uint32_t *)src;

	if (v6ip[2] == htonl(0xffff))
                *v4ip = v6ip[3];

	return 0;
}

const char *ntop6(const void *v6ip)
{
	static char buf[256];
	return inet_ntop(AF_INET6, v6ip, buf, sizeof(buf));
}

static unsigned char dns_filling_byte[] = {
	0xf1, 0xb0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 'c',  'n',  0x00,
	0x00, 0x01, 0x00, 0x01
};

static uint8_t dns_filling_ipv4[] = {
	0xf1, 0xb0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00
};

static uint8_t dns_filling_ipv6[] = {
	0xf1, 0xb0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1c, 0x00,
	0x01, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static int dns_filling_len = sizeof(dns_filling_byte);
static void *dns_filling_buf = dns_filling_byte;

size_t get_link_header(void **ptr)
{
	size_t retval = dns_filling_len;
	*ptr = dns_filling_buf;

	*(uint16_t *)dns_filling_buf = csum_fold(_tcpup_sum);

	dns_filling_len = sizeof(dns_filling_byte);
	dns_filling_buf = dns_filling_byte;
	return retval;
}

int set_relay_info(u_char *target, int type, void *host, u_short port)
{
	(void)target;

	if (type == RELAY_IPV4) {
		memcpy(dns_filling_ipv4 + 0x18, &port, 2);
		memcpy(dns_filling_ipv4 + 0x1c, host, 4);
		dns_filling_len = sizeof(dns_filling_ipv4);
		dns_filling_buf = dns_filling_ipv4;
	} else if (type == RELAY_IPV6) {
		memcpy(dns_filling_ipv6 + 0x18, &port, 2);
		memcpy(dns_filling_ipv6 + 0x1c, host, 16);
		dns_filling_len = sizeof(dns_filling_ipv6);
		dns_filling_buf = dns_filling_ipv6;
	}

	return 0;
}

size_t parse_link_header(uint8_t *packet, size_t len)
{
	uint32_t link_magic = 0x2636e00;
	struct link_header *link = (struct link_header *)packet;

	if (link->yn == htons(1)) {
		switch(packet[14]) {
			case 0x1c:
#if 0
				memcpy(builtin_target6 + 2, packet + 0x18, 2);
				memcpy(builtin_target6 + 4, packet + 0x1c, 16);
#endif
				LOG_DEBUG("IPV6 HEADER");
				return sizeof(dns_filling_ipv6);

			case 0x1:
#if 0
				memcpy(builtin_target + 2, packet + 0x18, 2);
				memcpy(builtin_target + 4, packet + 0x1c, 4);
#endif
				LOG_DEBUG("IPV4 HEADER");
				return sizeof(dns_filling_ipv4);

			default:
				LOG_DEBUG("BAD HEADER");
				return len;
		}
	}

	if (link->content == htonl(link_magic)) {
		return sizeof(dns_filling_byte);
	}

	return len;
}
