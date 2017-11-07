#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

#include <base_link.h>

static unsigned char TUNNEL_PADDIND_DNS[] = {
	0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x77, 0x77, 0x77,
	0x77, 0x00, 0x00, 0x01, 0x00, 0x01
};

#define LEN_PADDING_DNS sizeof(TUNNEL_PADDIND_DNS)

static int udp_low_link_create(void)
{
	int error;
	int bufsiz, devfd, flags;

	devfd = socket(AF_INET, SOCK_DGRAM, 0);

	LOG_DEBUG("UDP created: %d\n", devfd);
	TUNNEL_PADDIND_DNS[2] &= ~0x80;
	TUNNEL_PADDIND_DNS[3] &= ~0x80;

	bufsiz = 384 * 1024;
	setsockopt(devfd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsiz, sizeof(bufsiz));
	setsockopt(devfd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsiz, sizeof(bufsiz));

	setblockopt(devfd, 0);
	return devfd;
}

static int udp_low_link_recv_data(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len)
{
	unsigned short key = 0;
	char _plain_stream[MAX_PACKET_SIZE], *packet;

	int count = recvfrom(devfd, _plain_stream, sizeof(_plain_stream), MSG_DONTWAIT, ll_addr, ll_len);

	if (count <= 0) return count;

	packet = _plain_stream;

	if (count <= sizeof(TUNNEL_PADDIND_DNS)) return -1;
	count -= sizeof(TUNNEL_PADDIND_DNS);

	LOG_VERBOSE("recv: %ld\n", count + LEN_PADDING_DNS);
	memcpy(&key, &packet[14], sizeof(key));
	count = MIN(count, len);
	packet_decrypt(htons(key), buf, packet + sizeof(TUNNEL_PADDIND_DNS), count);

	return count;
}

static int udp_low_link_send_data(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len)
{
	unsigned short key = rand();
	uint8_t _crypt_stream[MAX_PACKET_SIZE];

	assert (len + sizeof(TUNNEL_PADDIND_DNS) < sizeof(_crypt_stream));
	memcpy(_crypt_stream, TUNNEL_PADDIND_DNS, sizeof(TUNNEL_PADDIND_DNS));
	memcpy(_crypt_stream + 14, &key, 2);
	packet_encrypt(htons(key), _crypt_stream + sizeof(TUNNEL_PADDIND_DNS), buf, len);
	return sendto(devfd, _crypt_stream, len + sizeof(TUNNEL_PADDIND_DNS), 0, ll_addr, ll_len);
}

static int udp_low_link_adjust(void)
{
	/* sizeof(struct udphdr) == 8 */
	return LEN_PADDING_DNS + 8;
}

struct low_link_ops udp_ops = {
	.create = udp_low_link_create,
	.get_adjust = udp_low_link_adjust,
	.send_data = udp_low_link_send_data,
	.recv_data = udp_low_link_recv_data
};
