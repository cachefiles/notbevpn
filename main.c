#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define SOT(addr) (struct sockaddr *)addr
#define MAX_PACKET_SIZE 2048
#define MIN(a, b) ((a) < (b)? (a): (b))

int tcpup_track_stage1(void);
int tcpup_track_stage2(void);
char * get_tcpup_data(int *len);
char * get_tcpip_data(int *len);

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

static int IPHDR_SKIP_LEN = 0;

int icmp_low_link_recv_data(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len)
{
	struct icmphdr *hdr;
	unsigned short key = 0;
	char _plain_stream[2048], *packet;

	int count = recvfrom(devfd, _plain_stream, sizeof(_plain_stream), MSG_DONTWAIT, ll_addr, ll_len);

	if (count <= 0) return count;
	if (count <= IPHDR_SKIP_LEN) return -1;

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

int icmp_low_link_send_data(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len)
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

	return sendto(devfd, _crypt_stream, len + sizeof(*hdr), 0, ll_addr, ll_len);
}

#define DEFAULT_TUN_NAME "tun0"

static void usage(const char *prog_name)
{
	fprintf(stderr, "%s [options] <server>!\n", prog_name);
	fprintf(stderr, "\t-h print this help!\n");
	fprintf(stderr, "\t-p <proto> select low link layer support, icmp/udp/tcp\n");
	fprintf(stderr, "\t-t <tun-device> use this as tun device name, default tun0!\n");
	fprintf(stderr, "\t-s <config-script> the path to config this interface when tun is up, default ./ifup.tun0!\n");
	fprintf(stderr, "\t-i <interface-address> interface address, local address use for outgoing/incoming packet!\n");
	fprintf(stderr, "\tall @address should use this format <host:port> OR <port>\n");
	fprintf(stderr, "\n");

	return;
}

int parse_sockaddr_in(struct sockaddr_in *info, const char *address)
{
    const char *last;

#define FLAG_HAVE_DOT    1
#define FLAG_HAVE_ALPHA  2
#define FLAG_HAVE_NUMBER 4
#define FLAG_HAVE_SPLIT  8

    int flags = 0;
    char host[128] = {};

    info->sin_family = AF_INET;
    info->sin_port   = htons(0);
    info->sin_addr.s_addr = htonl(0);

    for (last = address; *last; last++) {
        if (isdigit(*last)) flags |= FLAG_HAVE_NUMBER;
        else if (*last == ':') flags |= FLAG_HAVE_SPLIT;
        else if (*last == '.') flags |= FLAG_HAVE_DOT;
        else if (isalpha(*last)) flags |= FLAG_HAVE_ALPHA;
        else { fprintf(stderr, "get target address failure!\n"); return -1;}
    }


    if (flags == FLAG_HAVE_NUMBER) {
        info->sin_port = htons(atoi(address));
        return 0;
    }

    if (flags == (FLAG_HAVE_NUMBER| FLAG_HAVE_DOT)) {
        info->sin_addr.s_addr = inet_addr(address);
        return 0;
    }

    struct hostent *host0 = NULL;
    if ((flags & ~FLAG_HAVE_NUMBER) == (FLAG_HAVE_ALPHA | FLAG_HAVE_DOT)) {
        host0 = gethostbyname(address);
        if (host0 != NULL)
            memcpy(&info->sin_addr, host0->h_addr, 4);
        return 0;
    }

    if (flags & FLAG_HAVE_SPLIT) {
        const char *split = strchr(address, ':');
        info->sin_port = htons(atoi(split + 1));

        if (strlen(address) < sizeof(host)) {
            strncpy(host, address, sizeof(host));
            host[split - address] = 0;

            if (flags & FLAG_HAVE_ALPHA) {
                host0 = gethostbyname(host);
                if (host0 != NULL) memcpy(&info->sin_addr, host0->h_addr, 4);
                return 0;
            }

            info->sin_addr.s_addr = inet_addr(host);
        }
    }

    return 0;
}

static void run_config_script(const char *ifname, const char *script, const char *gateway)
{
	char setup_cmd[8192];
	sprintf(setup_cmd, "%s %s %s", script, ifname, gateway);
	system(setup_cmd);
	return;
}

int set_tcp_mss_by_mtu(int mtu);

int get_device_mtu(int sockfd, struct sockaddr *dest, socklen_t dlen, int def_mtu)
{
	int val;
	int total = 0;

	int sht = 2;
	int mtu = def_mtu;
	char buf[1024 * 4];
	static int dev_mtu = 0;

#if defined(IP_DONTFRAG)
	val = 1;
	setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val));
#endif

#if defined(IP_MTU_DISCOVER)
	val = IP_PMTUDISC_DO;
	setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#else
	goto cleanup;
#endif

	if (dev_mtu > 0) {
		return dev_mtu;
	}

	while (mtu > 512) {
		int save_mtu = mtu;
		for (sht = 2; mtu > (1 << sht); sht++) {
			int error  = sendto(sockfd, buf, mtu - 28, 0, dest, dlen);
			if (error > 0) {
				total += error;
				goto next;
			} else if (errno == EMSGSIZE) {
				save_mtu = mtu;
				mtu -= (1 << sht);
			} else {
				goto cleanup;
			}
		}
		mtu = save_mtu;
	}

next:
	for (; sht >= 2 && mtu > 512; sht--) {
		int mid  = mtu + (1 << sht);
		int error  = sendto(sockfd, buf, mid - 28, 0, dest, dlen);
		if (error > 0) {
			total += error;
			mtu = mid;
		} else if (errno != EMSGSIZE) {
			goto cleanup;
		}
	}

	dev_mtu = mtu;
cleanup:
	return mtu;
}

#define LEN_PADDING_ICMP sizeof(struct icmphdr)

int update_tcp_mss(struct sockaddr *local, struct sockaddr *remote, size_t adjust)
{
	int err = 0;
	int mtu = 1500;
	int udpfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (udpfd != -1) {
		err = bind(udpfd, local, sizeof(struct sockaddr_in));
		assert(err == 0);

		mtu = get_device_mtu(udpfd, remote, sizeof(struct sockaddr_in), 1500);
		close(udpfd);
	}

	set_tcp_mss_by_mtu(mtu - 20 - adjust);
	return 0;
}

struct low_link_ops {
	int (*create)(void);
	int (*get_adjust)(void);
	int (*send_data)(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len);
	int (*recv_data)(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len);
};

static int icmp_low_link_create(void)
{
	int devfd, bufsiz;

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
	return devfd;
}

static int icmp_low_link_adjust(void)
{
	return LEN_PADDING_ICMP;
}

static struct low_link_ops icmp_ops = {
	.create = icmp_low_link_create,
	.get_adjust = icmp_low_link_adjust,
	.send_data = icmp_low_link_send_data,
	.recv_data = icmp_low_link_recv_data
};

static unsigned char TUNNEL_PADDIND_DNS[] = {
	0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x77, 0x77, 0x77,
	0x77, 0x00, 0x00, 0x01, 0x00, 0x01
};

#define LEN_PADDING_DNS sizeof(TUNNEL_PADDIND_DNS)

static int udp_low_link_create(void)
{
	int bufsiz, devfd;

	devfd = socket(AF_INET, SOCK_DGRAM, 0);

	fprintf(stderr, "UDP created: %d\n", devfd);
	TUNNEL_PADDIND_DNS[2] &= ~0x80;
	TUNNEL_PADDIND_DNS[3] &= ~0x80;

	bufsiz = 384 * 1024;
	setsockopt(devfd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsiz, sizeof(bufsiz));
	setsockopt(devfd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsiz, sizeof(bufsiz));
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

	// fprintf(stderr, "recv: %d\n", count + LEN_PADDING_DNS);
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

static struct low_link_ops udp_ops = {
	.create = udp_low_link_create,
	.get_adjust = udp_low_link_adjust,
	.send_data = udp_low_link_send_data,
	.recv_data = udp_low_link_recv_data
};

ssize_t tcp_frag_nat(void *packet, size_t len, size_t limit);
void tcp_nat_init(struct sockaddr_in *ifaddr, struct sockaddr_in *target);

static int run_tun2socks(int tun, struct sockaddr_in *from, struct sockaddr_in *target)
{
	int len;
	char buf[MAX_PACKET_SIZE];

	tcp_nat_init(from, target);
	for (; ; ) {
		char *packet = (buf + 60);
		len = tun_read(tun, packet, 1500);
		if (len < 0) {
			fprintf(stderr, "read tun failure\n");
			break;
		}

		len = tcp_frag_nat(packet, len, 1500);
		if (len <= 0) {
			fprintf(stderr, "nat failure\n");
			continue;
		}

		len = tun_write(tun, packet, len);
		if (len <= 0) {
			fprintf(stderr, "write tun failure: %d\n", errno);
			continue;
		}
	}

	return 0;
}

static int _reload = 0;
static void handle_reload(int sig)
{
	_reload = 1;
	return;
}

int main(int argc, char *argv[])
{
	int i;
	int tun, len;
	const char *proto = "icmp";
	const char *script = NULL;
	const char *tun_name = DEFAULT_TUN_NAME;
	char buf[MAX_PACKET_SIZE];

	int devfd, error, have_target = 0;
	struct sockaddr_in ll_addr = {};
	struct sockaddr_in so_addr = {};
	struct sockaddr_in tmp_addr = {};
	struct low_link_ops *link_ops = &icmp_ops;

	so_addr.sin_family = AF_INET;
	so_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else if (strcmp(argv[i], "-mtu") == 0 && i + 1 < argc) {
			int mtu = atoi(argv[i + 1]);
			if (mtu > 0 && mtu < 1500) set_tcp_mss_by_mtu(mtu - 20 - sizeof(struct icmphdr));
			i++;
		} else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
			script = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			proto = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
			tun_name = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			parse_sockaddr_in(&so_addr, argv[i + 1]);
			i++;
		} else {
			parse_sockaddr_in(&ll_addr, argv[i]);
			have_target = 1;
			continue;
		}
	}

	if (have_target == 0 || ll_addr.sin_addr.s_addr == 0) {
		usage(argv[0]);
		return 0;
	}

	tun = vpn_tun_alloc(tun_name);
	if (tun == -1) {
		perror("vpn_tun_alloc: ");
		return -1;
	}

	int save_uid = getuid();
	setuid(0);
	run_config_script(tun_name, script, inet_ntoa(ll_addr.sin_addr));

	if (0 == strcmp(proto, "tcp")) {
		return run_tun2socks(tun, &so_addr, &ll_addr);
	} else if (0 == strcmp(proto, "udp")) {
		link_ops = &udp_ops;
	} else if (0 == strcmp(proto, "icmp")) {
		link_ops = &icmp_ops;
	} else {
		usage(argv[0]);
		exit(0);
	}

	update_tcp_mss((struct sockaddr *)&so_addr, SOT(&ll_addr), (*link_ops->get_adjust)());
	devfd = (*link_ops->create)();
	assert(devfd != -1);

	setreuid(save_uid, save_uid);
	error = bind(devfd, SOT(&so_addr), sizeof(so_addr));
	assert(error == 0);

	int last_track_count = 0;
	int last_track_enable = 0;
	time_t last_track_time = time(NULL);

	signal(SIGHUP, handle_reload);

	for ( ; ; ) {
		int newfd, nready;
		fd_set readfds;
		char * packet;
		struct timeval timeo = {};

		FD_ZERO(&readfds);
		FD_SET(tun, &readfds);
		FD_SET(devfd, &readfds);

		timeo.tv_sec  = 1;
		timeo.tv_usec = 0;

		if (last_track_enable &&
				tcpup_track_stage2() &&
				(packet = get_tcpup_data(&len)) != NULL) {
			fprintf(stderr, "send probe data: %d\n", len);
			(*link_ops->send_data)(devfd, packet, len, SOT(&ll_addr), sizeof(ll_addr));
			last_track_enable = 0;
		}

		nready = select(tun < devfd? devfd +1: tun +1, &readfds, NULL, NULL, &timeo);
		if (nready == -1) {
			perror("select");
			if (errno == EINTR) continue;
			break;
		}

		if (nready == 0 || ++last_track_count >= 10) {
			time_t now = time(NULL);
			if (now < last_track_time || last_track_time + 4 < now) { 
				tcpup_track_stage1();
				last_track_time  = now;
				last_track_count = 0;
			}

			if (nready == 0) {
				if (_reload && (newfd = (*link_ops->create)()) != -1) {
					if (bind(newfd, SOT(&so_addr), sizeof(so_addr)) == 0) {
						close(devfd);
						devfd = newfd;
						_reload = 0;
					} else {
						perror("rebind");
						fprintf(stderr, "bindto: %s:%d\n", inet_ntoa(so_addr.sin_addr), htons(so_addr.sin_port));
						fprintf(stderr, "family: %d %d\n", so_addr.sin_family, newfd);
					}
				}
				continue;
			}
		}

		packet = (buf + 60);
		if (FD_ISSET(devfd, &readfds)) {
			int bufsize = 1500;
			socklen_t tmp_alen = sizeof(tmp_addr);
			assert(bufsize + 60 < sizeof(buf));
			len = (*link_ops->recv_data)(devfd, packet, bufsize, SOT(&tmp_addr), &tmp_alen); 
			if ((len > 0) && (len = tcpup_frag_input(packet, len, 1500)) > 0) {
				(*link_ops->send_data)(devfd, packet, len, SOT(&tmp_addr), tmp_alen);
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

			if ((len > 0) && (len = tcpip_frag_input(packet, len, 1500)) > 0) {
				len = tun_write(tun, packet, len);
			}

			break;
		}

		packet = get_tcpup_data(&len);
		if (packet != NULL) {
			(*link_ops->send_data)(devfd, packet, len, SOT(&ll_addr), sizeof(ll_addr));
			last_track_enable = 1;
		}
	}

clean:
	close(devfd);
	close(tun);

	return 0;
}
