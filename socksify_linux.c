#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <linux/if_tun.h>

#define err(fmt) fprintf(stderr, fmt)
#define errf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

int vpn_tun_alloc(const char *dev) {
	struct ifreq ifr;
	int fd, e;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		err("open");
		errf("can not open /dev/net/tun");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	 */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if(*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((e = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		err("ioctl[TUNSETIFF]");
		errf("can not setup tun device: %s", dev);
		close(fd);
		return -1;
	}
	// strcpy(dev, ifr.ifr_name);
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
