#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

#include <config.h>
#include <base_link.h>

#define LEN_PADDING_ICMP sizeof(struct icmphdr)

struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	union {
		unsigned int pair;
		struct {
			unsigned short ident;
			unsigned short seqno;
		};
	} u0;
	/* just reserved for expend, not part of icmp protocol. */
	unsigned int   reserved[2];
};

#define ICMP_CLIENT_FILL 0xecececec
#define ICMP_SERVER_FILL 0xcececece
#define ICMP_NATYPE_CODE 0x0

static int IPHDR_SKIP_LEN = 0;

int icmp_low_link_recv_data(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len)
{
	struct icmphdr *hdr;
	unsigned short key = 0;
	char _plain_stream[2048], *packet;

	int count = recvfrom(devfd, _plain_stream, sizeof(_plain_stream), MSG_DONTWAIT, ll_addr, ll_len);

	if (count <= 0) return count;
	if (count <= IPHDR_SKIP_LEN) return -1;
	LOG_VERBOSE("icmp_low_link_recv_data: %d\n", count);

	packet = _plain_stream + IPHDR_SKIP_LEN;
	count -= IPHDR_SKIP_LEN;

	if (count <= sizeof(*hdr)) return -1;
	count -= sizeof(*hdr);

	hdr = (struct icmphdr *)(packet);
	if ((hdr->reserved[0] != ICMP_SERVER_FILL)
			&& (hdr->reserved[1] != ICMP_SERVER_FILL)) return -1;
	if (IPHDR_SKIP_LEN != 0 && hdr->u0.ident != (getpid() & 0xffff)) return -1;
	if (hdr->code == 0x08) return -1;

	memcpy(&key, &packet[14], sizeof(key));
	count = MIN(count, len);
	packet_decrypt(htons(key), buf, packet + sizeof(*hdr), count);

	return count;
}

int ip_checksum(void *buf, size_t len);

static int icmp_low_link_send_data(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len)
{
	unsigned short key = rand();
	struct icmphdr *hdr = NULL;

	uint8_t _crypt_stream[MAX_PACKET_SIZE];

	hdr = (struct icmphdr *)_crypt_stream;
	hdr->type = 0x08; // icmp echo request
	hdr->code = ICMP_NATYPE_CODE;
	hdr->u0.ident = getpid();
	hdr->reserved[0] = ICMP_CLIENT_FILL;
	hdr->reserved[1] = ICMP_CLIENT_FILL;

	memcpy(_crypt_stream + 14, &key, 2);
	assert (len + sizeof(*hdr) < sizeof(_crypt_stream));
	packet_encrypt(htons(key), _crypt_stream + sizeof(*hdr), buf, len);

	hdr->checksum = 0;
	hdr->checksum = ip_checksum(_crypt_stream, len + sizeof(*hdr));

	protect_reset(IPPROTO_ICMP, _crypt_stream, len, ll_addr, ll_len);
	return sendto(devfd, _crypt_stream, len + sizeof(*hdr), 0, ll_addr, ll_len);
}

static int icmp_low_link_create(void)
{
	int devfd, bufsiz, flags;

#ifdef __linux__
	devfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
#else
	devfd = -1;
#endif
	if (devfd == -1) {
		devfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		IPHDR_SKIP_LEN = 20;
	}

	bufsiz = 384 * 1024;
	setsockopt(devfd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsiz, sizeof(bufsiz));
	setsockopt(devfd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsiz, sizeof(bufsiz));

	setblockopt(devfd, 0);
	return devfd;
}

static int icmp_low_link_adjust(void)
{
	return LEN_PADDING_ICMP;
}

struct low_link_ops icmp_ops = {
	.create = icmp_low_link_create,
	.get_adjust = icmp_low_link_adjust,
	.send_data = icmp_low_link_send_data,
	.recv_data = icmp_low_link_recv_data
};

