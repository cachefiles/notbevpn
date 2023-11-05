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
#include "conversation.h"

#ifndef EMSGSIZE
#define EMSGSIZE -100
#define SIGHUP SIGINT
#define getuid() 0
#define setuid(x)
#define setreuid(x, y)
#endif

int tcpup_track_stage1(void);
int tcpup_track_stage2(void);
char * get_tcpup_data(int *len, u_long *dest);
char * get_tcpip_data(int *len);

int vpn_tun_alloc(const char *dev);
int tun_read(int fd, void *buf, size_t len);
int tun_write(int fd, void *buf, size_t len);

ssize_t tcpup_frag_input(void *packet, size_t len, size_t limit);
ssize_t tcpip_frag_input(void *packet, size_t len, size_t limit);
int check_blocked_normal(int tunfd, int dnsfd, char *packet, size_t len, int *failure);
int resolv_return(int tunfd, char *packet, size_t len, struct sockaddr_in6 *from);

int set_linkfailure()
{
	return 0;
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
	fprintf(stderr, "\t-I <bind-to-device> only valid for linux!\n");
	fprintf(stderr, "\tall @address should use this format <host:port> OR <port>\n");
	fprintf(stderr, "\n");

	return;
}

int parse_sockaddr_in(struct sockaddr_in6 *info, const char *address)
{
    const char *last;

#define FLAG_HAVE_DOT    1
#define FLAG_HAVE_ALPHA  2
#define FLAG_HAVE_NUMBER 4
#define FLAG_HAVE_SPLIT  8
#define FLAG_HAVE_LEFT  16
#define FLAG_HAVE_RIGHT 32

    int flags = 0;
    char host[128] = {};

    info->sin6_family = AF_INET6;
    info->sin6_port   = htons(0);
    info->sin6_addr   = in6addr_any;

    for (last = address; *last; last++) {
        if (isdigit(*last)) flags |= FLAG_HAVE_NUMBER;
        else if (*last == '[') flags |= FLAG_HAVE_LEFT;
        else if (*last == ']') flags |= FLAG_HAVE_RIGHT;
        else if (*last == ':') flags |= FLAG_HAVE_SPLIT;
        else if (*last == '.') flags |= FLAG_HAVE_DOT;
        else if (isalpha(*last)) flags |= FLAG_HAVE_ALPHA;
        else { LOG_DEBUG("get target address failure!\n"); return -1;}
    }


    if (flags == FLAG_HAVE_NUMBER) {
        info->sin6_port = htons(atoi(address));
        return 0;
    }

    if (flags == (FLAG_HAVE_NUMBER| FLAG_HAVE_DOT)) {
		struct in_addr d = {};
		inet_pton(AF_INET, address, &d);
		inet_4to6(&info->sin6_addr, &d);
		LOG_DEBUG("target is %s %s %d", ntop6(&info->sin6_addr), address, __LINE__);
        return 0;
    }

    struct hostent *host0 = NULL;
    if ((flags & ~FLAG_HAVE_NUMBER) == (FLAG_HAVE_ALPHA | FLAG_HAVE_DOT)) {
        host0 = gethostbyname(address);
        if (host0 != NULL)
            inet_4to6(&info->sin6_addr, host0->h_addr);
		LOG_DEBUG("target is %s %s %d", ntop6(&info->sin6_addr), address, __LINE__);
        return 0;
    }

    if (flags & FLAG_HAVE_SPLIT) {
        const char *split = strchr(address, ':');
        info->sin6_port = htons(atoi(split + 1));

        if (strlen(address) < sizeof(host)) {
            strncpy(host, address, sizeof(host));
            host[split - address] = 0;

            if (flags & FLAG_HAVE_ALPHA) {
                host0 = gethostbyname(host);
                if (host0 != NULL) inet_4to6(&info->sin6_addr, host0->h_addr);
				LOG_DEBUG("target is %s %s %d", ntop6(&info->sin6_addr), address, __LINE__);
                return 0;
            }

			struct in_addr d = {};
			inet_pton(AF_INET, host, &d);
			inet_4to6(&info->sin6_addr, &d);
			LOG_DEBUG("target is %s %s %d", ntop6(&info->sin6_addr), address, __LINE__);
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
	int total = 0;

	int sht = 2;
	int mtu = def_mtu;
	char buf[1024 * 4];
	static int dev_mtu = 0;

#if defined(IP_DONTFRAG)
	int val = 1;
	setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val));
#endif

#if defined(IP_MTU_DISCOVER)
	int val = IP_PMTUDISC_DO;
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

int update_tcp_mss(struct sockaddr *local, struct sockaddr *remote, size_t adjust)
{
	int err = 0;
	int mtu = 1500;
	int udpfd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (udpfd != -1) {
		err = bind(udpfd, local, sizeof(struct sockaddr_in6));
		assert(err == 0);

		mtu = get_device_mtu(udpfd, remote, sizeof(struct sockaddr_in6), 1500);
		close(udpfd);
	}

	set_tcp_mss_by_mtu(mtu - 20 - adjust);
	return 0;
}

extern int rx_sum_drop;
extern struct low_link_ops udp_ops;
extern struct low_link_ops icmp_ops;

ssize_t tcp_frag_nat(void *packet, size_t len, size_t limit);
void tcp_nat_init(struct sockaddr_in6 *ifaddr, struct sockaddr_in6 *target);

static int run_tun2socks(int tun, struct sockaddr_in6 *from, struct sockaddr_in6 *target)
{
	int len;
	char buf[MAX_PACKET_SIZE];

	tcp_nat_init(from, target);
	for (; ; ) {
		char *packet = (buf + 60);
		len = tun_read(tun, packet, 1500);
		if (len < 0) {
			LOG_DEBUG("read tun failure\n");
			break;
		}

		len = tcp_frag_nat(packet, len, 1500);
		if (len <= 0) {
			LOG_DEBUG("nat failure\n");
			continue;
		}

		len = tun_write(tun, packet, len);
		if (len <= 0) {
			LOG_DEBUG("write tun failure: %d\n", errno);
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

static void bind_to_device(int sockfd, const char *iface)
{
	if (iface == NULL) {
		return;
	}

#ifdef SO_BINDTODEVICE
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) +1) == -1)  {
		perror("setsockopt SO_BINDTODEVICE");
	}
#endif

#ifdef  IP_RECVIF
	const int on = 1;
	if (setsockopt(sockfd, IPPROTO_IP, IP_RECVIF, &on, sizeof(on)) < 0) {
		perror("setsockopt IP_RECVIF");
	}
#endif

	return;
}

int main(int argc, char *argv[])
{
	int i;
	int tunfd, len;
	int busy_loop = 0;
	int new_dev_mtu = -1;
	const char *fdb = NULL;
	const char *iface = NULL;
	const char *proto = "icmp";
	const char *script = NULL;
	const char *tun_name = DEFAULT_TUN_NAME;
	char buf[MAX_PACKET_SIZE];

	int netfd, dnsfd, error, have_target = 0;
	struct sockaddr_in6 ll_addr = {};
	struct sockaddr_in6 so_addr = {};
	struct sockaddr_in6 tmp_addr = {};
	struct low_link_ops *link_ops = &icmp_ops;

	so_addr.sin6_family = AF_INET6;
	so_addr.sin6_addr = in6addr_any;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else if (strcmp(argv[i], "-I") == 0 && i + 1 < argc) {
			iface = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
			fdb = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "-mtu") == 0 && i + 1 < argc) {
			int mtu = atoi(argv[i + 1]);
			if (mtu > 0 && mtu < 1500) new_dev_mtu = mtu;
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
			have_target = 1;
			const char *server = argv[i];
			if (strncmp(argv[i], "cafe:", 5) == 0) {
				have_target = 2;
				server += 5;
			}
			parse_sockaddr_in(&ll_addr, server);
			continue;
		}
	}

	if (have_target == 0 || !memcmp(&ll_addr.sin6_addr, &in6addr_any, 16)) {
		usage(argv[0]);
		return 0;
	}

	setenv("NAMESERVER", "::ffff:114.114.114.114", 0);
	tunfd = vpn_tun_alloc(tun_name);
	if (tunfd == -1) {
		perror("vpn_tun_alloc: ");
		return -1;
	}

	int save_uid = getuid();
	setuid(0);
	run_config_script(tun_name, script, ntop6(&ll_addr.sin6_addr));

	if (0 == strcmp(proto, "tcp")) {
		return run_tun2socks(tunfd, &so_addr, &ll_addr);
	} else if (0 == strcmp(proto, "udp")) {
		link_ops = &udp_ops;
	} else if (0 == strcmp(proto, "icmp")) {
		link_ops = &icmp_ops;
	} else {
		usage(argv[0]);
		exit(0);
	}

	if (fdb != NULL) {
		int prefix;
		char dest_buf[64];
		/* -b 192.168.1.0/24 */
		sscanf(fdb, "%[^/]/%d@%x", dest_buf, &prefix);
	}

	update_tcp_mss(SOT(&so_addr), SOT(&ll_addr), (*link_ops->get_adjust)());
	if (new_dev_mtu != -1) {
		set_tcp_mss_by_mtu(new_dev_mtu - 20 - link_ops->get_adjust());
		LOG_DEBUG("update mtu to: %d\n", new_dev_mtu);
	}

	netfd = (*link_ops->create)();
	assert(netfd != -1);

	dnsfd = (*udp_ops.create)();
	assert(dnsfd != -1);

	setreuid(save_uid, save_uid);
	bind_to_device(netfd, iface);
	if (have_target == 2) {
		error = bind(netfd, SOT(&so_addr), sizeof(so_addr));
		assert(error == 0);
	}

	int last_track_count = 0;
	int last_track_enable = 0;
	time_t last_track_time = time(NULL);

	signal(SIGHUP, handle_reload);

	setblockopt(netfd, 0);
	setblockopt(tunfd, 0);
	setblockopt(dnsfd, 0);

	int nready = 0;
	fd_set readfds;

	FD_ZERO(&readfds);
	set_default_gate(SOT(&ll_addr), sizeof(ll_addr));
	for ( ; ; ) {
		int ignore;
		int newfd;
		char * packet;
		struct timeval timeo = {};

		int maxfd, bug_check = 0;
		if (nready <= 0 || ++busy_loop > 1000) {
			if (last_track_enable && tcpup_track_stage2()) {
				u_long dest = 0;
				last_track_enable = 0;
				if ((packet = get_tcpup_data(&len, &dest)) != NULL) {
					error = (*link_ops->send_data)(netfd, packet, len, SOT(&ll_addr), sizeof(ll_addr));
					LOG_DEBUG("send probe data: %d\n", len);
					if (error == -1) _reload = 2;
				}
			}

			FD_ZERO(&readfds);
			FD_SET(tunfd, &readfds);
			FD_SET(netfd, &readfds);
			FD_SET(dnsfd, &readfds);
			maxfd = MAX(tunfd, netfd);
			maxfd = MAX(maxfd, dnsfd);

			timeo.tv_sec  = 1;
			timeo.tv_usec = 0;

			bug_check++;
			busy_loop = 0;
			nready = select_call(maxfd, netfd, dnsfd, &readfds, &timeo);
			if (nready == -1) {
				LOG_DEBUG("select failure");
				if (errno == EINTR) continue;
				break;
			}

			if (nready == 0 || ++last_track_count >= 10 || _reload == 2) {
				time_t now = time(NULL);
				if (now < last_track_time || last_track_time + 4 < now) { 
					tcpup_track_stage1();
					last_track_time  = now;
					last_track_count = 0;
				}

				if (nready == 0 || _reload == 2) {
					if (_reload && (newfd = (*link_ops->create)()) != -1) {
						close(netfd);
						netfd = newfd;
						bind_to_device(netfd, iface);
						if (rx_sum_drop > 5) { rx_sum_drop = 0; so_addr.sin6_port = 0; }
						if (bind(newfd, SOT(&so_addr), sizeof(so_addr)) == 0) {
							setblockopt(netfd, 0);
							nready = _reload = 0;
						} else {
							LOG_DEBUG("bindto: %s:%d\n", ntop6(&so_addr.sin6_addr), htons(so_addr.sin6_port));
							LOG_DEBUG("family: %d %d\n", so_addr.sin6_family, newfd);
							perror("rebind");
						}
					}
					continue;
				}
			}
		}

		if (FD_ISSET(netfd, &readfds)) {
			int bufsize = 1500;
			u_long dest = 0;
			socklen_t tmp_alen = sizeof(tmp_addr);

			bug_check++;
			packet = (buf + 60);
			assert(bufsize + 60 < sizeof(buf));
			len = (*link_ops->recv_data)(netfd, packet, bufsize, SOT(&tmp_addr), &tmp_alen); 
			if (len < 0) {
				// LOG_VERBOSE("read netfd failure %d\n", WSAGetLastError());
				// if (WSAGetLastError() != WSAEWOULDBLOCK) goto clean;
				FD_CLR(netfd, &readfds);
				nready--;
				continue;
			}

			if (len > 0) {
				len = tcpup_frag_input(packet, len, 1500);
				if (len <= 0 && have_target == 2) ll_addr = tmp_addr;
				ignore = (len <= 0)? 0: (*link_ops->send_data)(netfd, packet, len, SOT(&tmp_addr), tmp_alen);
				if (ignore == -1 || rx_sum_drop > 10) _reload = 2;
				LOG_VERBOSE("send_data: %d\n", ignore);

			}

			packet = get_tcpip_data(&len);
			if (packet != NULL) {
				if (len > 0) rx_sum_drop = 0;
				len = tun_write(tunfd, packet, len);
				LOG_VERBOSE("tun_write: %d\n", len);
				push_conversation(SOT(&tmp_addr), tmp_alen);
			}
		}

		if (FD_ISSET(tunfd, &readfds)) {
			bug_check++;
			u_long dest = 0;
			packet = (buf + 60);
			len = tun_read(tunfd, packet, 1500);
			if (len < 0) {
				LOG_VERBOSE("read tunfd failure\n");
				if (errno != EAGAIN) goto clean;
				FD_CLR(tunfd, &readfds);
				nready--;
				continue;
			}

			int ignore = 0;
			if (check_blocked_normal(tunfd, dnsfd, packet, len, &ignore)) {
				LOG_VERBOSE("ignore blocked data\n");
				continue;
			}

			if (len > 0 && !protect_match(packet, len)) {
				len = tcpip_frag_input(packet, len, 1500);
				ignore = (len <= 0)? 0: tun_write(tunfd, packet, len);
				LOG_VERBOSE("tun_write: %d\n", ignore);
			}

			packet = get_tcpup_data(&len, &dest);
			if (packet != NULL) {
				// SOT(&ll_addr), sizeof(ll_addr));
				struct sockaddr *target = pull_conversation(dest);
				error = (*link_ops->send_data)(netfd, packet, len, target, sizeof(ll_addr));
				if (error == -1) _reload = 2;
				last_track_enable = 1;
				LOG_VERBOSE("send_data: %d\n", len);
			}
		}

		if (FD_ISSET(dnsfd, &readfds)) {
			int bufsize = 1500;
			packet = (buf + 60);
			socklen_t tmp_alen = sizeof(tmp_addr);
			bug_check++;

			LOG_VERBOSE("receive dns data\n");
			len = recvfrom(dnsfd, packet, bufsize, 0, SOT(&tmp_addr), &tmp_alen); 
			if (len < 0) {
				FD_CLR(dnsfd, &readfds);
				nready--;
				continue;
			}

			len = resolv_return(bufsize, packet, len, &tmp_addr);
			if (len > 0) {
				len = tun_write(tunfd, packet, len);
			}
		}

		assert(bug_check > 0);
	}

clean:
	close(netfd);
	close(dnsfd);
	vpn_tun_free(tunfd);

	LOG_VERBOSE("exit");
	return 0;
}
