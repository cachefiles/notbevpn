#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <net/if.h>
#include <net/if_tun.h>

#define err(fmt) fprintf(stderr, fmt)
#define errf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

int vpn_tun_alloc(const char *dev)
{
	int fd;
	char devname[32]={0,};
	snprintf(devname, sizeof(devname), "/dev/%s", dev);
	if ((fd = open(devname, O_RDWR)) < 0) {
		err("open");
		errf("can not open %s", devname);
		return -1;
	}
	int i = IFF_POINTOPOINT | IFF_MULTICAST;
	if (ioctl(fd, TUNSIFMODE, &i) < 0) {
		err("ioctl[TUNSIFMODE]");
		errf("can not setup tun device: %s", dev);
		close(fd);
		return -1;
	}
	i = 0;
	if (ioctl(fd, TUNSIFHEAD, &i) < 0) {
		err("ioctl[TUNSIFHEAD]");
		errf("can not setup tun device: %s", dev);
		close(fd);
		return -1;
	}
	return fd;
}

int tun_read(int fd, void *buf, size_t len)
{
    return read(fd, buf, len);
}

int tun_write(int fd, void *buf, size_t len)
{
    return write(fd, buf, len);
}

int setblockopt(int devfd, int block)
{
	int flags;

	flags = fcntl(devfd, F_GETFL);
	if ((block? 0: O_NONBLOCK) ^ (flags & O_NONBLOCK)) {
		flags = fcntl(devfd, F_SETFL, flags^O_NONBLOCK);
	}

	return flags;
}
