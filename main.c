#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>

void module_init(void);
void * get_tcpup_data(int *len);
void * get_tcpip_data(int *len);

int vpn_tun_alloc(const char *dev);
int tun_read(int fd, void *buf, size_t len);
int tun_write(int fd, void *buf, size_t len);

ssize_t tcpup_frag_input(void *packet, size_t len, size_t limit);
ssize_t tcpip_frag_input(void *packet, size_t len, size_t limit);

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

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	for (int i = 0; i < len; i++) {
		*fdst++ = (*fsrc++ ^ d0);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	return 0;
}

int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	for (int i = 0; i < len; i++) {
		*fdst++ = (*fsrc++ ^ d0);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	return 0;
}

#define IPHDR_SKIP_LEN 20

int low_link_recv_data(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len)
{
	struct icmphdr *hdr;
	unsigned short key = 0;
	char _plain_stream[1500], *packet;

	int count = recvfrom(devfd, _plain_stream, sizeof(_plain_stream), MSG_DONTWAIT, ll_addr, ll_len);

	if (count <= 0) return count;
	if (count <= IPHDR_SKIP_LEN) return -1;

	packet = _plain_stream + IPHDR_SKIP_LEN;
	count -= IPHDR_SKIP_LEN;

	if (count <= sizeof(*hdr)) return -1;
	count -= sizeof(*hdr);

	hdr = (struct icmphdr *)(packet);
	if (hdr->reserved[0] == ICMP_CLIENT_FILL) return -1;
	if (hdr->reserved[1] == ICMP_CLIENT_FILL) return -1;
	if (hdr->u0.ident != (getpid() & 0xffff)) return -1;
	if (hdr->code == 0x08) return -1;

	memcpy(&key, &packet[14], sizeof(key));
	packet_decrypt(htons(key), buf, packet + sizeof(*hdr), count);

	return count;
}

int low_link_send_data(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len)
{
	unsigned short key = rand();
	struct icmphdr *hdr = NULL;

	uint8_t _crypt_stream[1500];

	hdr = (struct icmphdr *)_crypt_stream;
	hdr->type = 0x08; // icmp echo request
	hdr->code = ICMP_NATYPE_CODE;
	hdr->u0.ident = getpid();
	hdr->reserved[0] = ICMP_CLIENT_FILL;
	hdr->reserved[1] = ICMP_CLIENT_FILL;

	memcpy(_crypt_stream + 14, &key, 2);
	packet_encrypt(htons(key), _crypt_stream + sizeof(*hdr), buf, len);

	return sendto(devfd, _crypt_stream, len + sizeof(*hdr), 0, ll_addr, ll_len);
}

int main(int argc, char *argv[])
{
	char buf[2048];
	int tun, len;

	int devfd, error;
	struct sockaddr_in ll_addr = {};
	struct sockaddr_in so_addr = {};

	tun = vpn_tun_alloc("utun0");
	if (tun == -1) {
		return -1;
	}

	module_init();

	system("ifconfig utun0 10.2.0.2/24 10.2.0.15 up");
	system("route add -net 119.75.217.0/24 10.2.0.15");
	system("route add -net 1.0.0.0/24 10.2.0.15");

	devfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	so_addr.sin_family = AF_INET;
	so_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(devfd, (struct sockaddr *)&so_addr, sizeof(so_addr));
	assert(error == 0);

	so_addr.sin_addr.s_addr = inet_addr("114.215.99.157");
	so_addr.sin_addr.s_addr = inet_addr("62.210.116.63");

	for (; ; ) {
		int nready;
		fd_set readfds;
		char * packet;

		FD_ZERO(&readfds);
		FD_SET(tun, &readfds);
		FD_SET(devfd, &readfds);
		nready = select(tun < devfd? devfd +1: tun +1, &readfds, NULL, NULL, NULL);
		if (nready == -1) {
			perror("select");
			break;
		}

		packet = (buf + 60);
		if (FD_ISSET(devfd, &readfds)) {
			int bufsize = 1500;
			socklen_t ll_len = sizeof(ll_addr);
			assert(bufsize + 60 < sizeof(buf));
			len = low_link_recv_data(devfd, packet, bufsize, (struct sockaddr *)&ll_addr, &ll_len); 
			if ((len > 0) && (len = tcpup_frag_input(packet, len, 1500)) > 0) {
				low_link_send_data(devfd, packet, len, (struct sockaddr *)&ll_addr, ll_len);
			}
		}

		packet = get_tcpip_data(&len);
		if (packet != NULL) {
			len = tun_write(tun, packet, len);
		}

		packet = (buf + 60);
		while (FD_ISSET(tun, &readfds)) {
			len = tun_read(tun, packet, 1500);
			if (len < 0) {
				fprintf(stderr, "read tun failure\n");
				goto clean;
			}

			len = tcpip_frag_input(packet, len, 1500);
			if (len <= 0) {
				break;
			}

			len = tun_write(tun, packet, len);
			if (len <= 0) {
				fprintf(stderr, "write tun failure: %d\n", errno);
			}

			break;
		}

		packet = get_tcpup_data(&len);
		if (packet != NULL) {
			low_link_send_data(devfd, packet, len, (struct sockaddr *)&so_addr, sizeof(so_addr));
		}
	}

clean:
	close(devfd);
	close(tun);

	return 0;
}
