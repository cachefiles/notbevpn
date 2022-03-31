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

static int _ack_count = 0;
static time_t _ack_start_time = 0;

static unsigned char TUNNEL_PADDIND_DNS[] = {
        '.', 'K', 'L', 'O', 'I', 'M', 'H', 'V'
};

#define LEN_PADDING_DNS sizeof(TUNNEL_PADDIND_DNS)

static int udp_low_link_create(void)
{
	int bufsiz, devfd;

	devfd = socket(AF_INET, SOCK_DGRAM, 0);

	LOG_DEBUG("UDP created: %d %d\n", devfd, _ack_count);
	TUNNEL_PADDIND_DNS[2] &= ~0x80;
	TUNNEL_PADDIND_DNS[3] &= ~0x80;

	bufsiz = 384 * 1024;
	setsockopt(devfd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsiz, sizeof(bufsiz));
	setsockopt(devfd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsiz, sizeof(bufsiz));

	setblockopt(devfd, 0);
	_ack_count = 0;
	return devfd;
}

static int udp_low_link_recv_data(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len)
{
	unsigned short key = 0;
	char _plain_stream[MAX_PACKET_SIZE], *packet;

	int count = recvfrom(devfd, _plain_stream, sizeof(_plain_stream), MSG_DONTWAIT, ll_addr, ll_len);

	if (count <= 0) return count;

	packet = _plain_stream;


	if (count <= LEN_PADDING_DNS) return -1;
	count -= LEN_PADDING_DNS;

	LOG_VERBOSE("recv: %ld\n", count + LEN_PADDING_DNS);
	memcpy(&key, &packet[14], sizeof(key));
	count = MIN(count, len);
	packet_decrypt(htons(key), buf, packet + LEN_PADDING_DNS, count);

	_ack_start_time = 0;
	_ack_count = 0;

	return count;
}

static int udp_low_link_send_data(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len)
{
	unsigned short key = rand();
	uint8_t _crypt_stream[MAX_PACKET_SIZE];

	assert (len + LEN_PADDING_DNS < sizeof(_crypt_stream));
	memcpy(_crypt_stream, TUNNEL_PADDIND_DNS, LEN_PADDING_DNS);
	// memcpy(_crypt_stream + 14, &key, 2);
	packet_encrypt(htons(key), _crypt_stream + LEN_PADDING_DNS, buf, len);

	if (get_ack_type() != ACK_TYPE_NONE) {
		if (++_ack_count < 11) {
			_ack_start_time = time(NULL);
		} else if (_ack_start_time + 2 < time(NULL)) {
			sendto(devfd, _crypt_stream, len + LEN_PADDING_DNS, 0, ll_addr, ll_len);
			return -1;
		}
	}

	protect_reset(IPPROTO_UDP, _crypt_stream, len, ll_addr, ll_len);
	return sendto(devfd, _crypt_stream, len + LEN_PADDING_DNS, 0, ll_addr, ll_len);
}

static int udp_low_link_adjust(void)
{
	/* sizeof(struct udphdr) == 8 */
	return LEN_PADDING_DNS + 8;
}

static int udp_low_link_bind_addr(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in zero_addr = {};
	if (_ack_count < 11)
		return bind(sockfd, addr, addrlen);
	zero_addr.sin_family = AF_INET;
	zero_addr.sin_port   = 0;
	zero_addr.sin_addr.s_addr   = htonl(INADDR_ANY);
	return bind(sockfd, (const struct sockaddr *)&zero_addr, addrlen);
}

struct low_link_ops udp_ops = {
	.create = udp_low_link_create,
	.get_adjust = udp_low_link_adjust,
	.send_data = udp_low_link_send_data,
	.recv_data = udp_low_link_recv_data,
	.bind_addr = udp_low_link_bind_addr
};
