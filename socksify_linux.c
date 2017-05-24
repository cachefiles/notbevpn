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
#define tun_read(...) read(__VA_ARGS__)
#define tun_write(...) write(__VA_ARGS__)

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

void module_init(void);
ssize_t tcp_frag_nat(void *packet, size_t len, size_t limit);

int main(int argc, char *argv[])
{
	char buf[2048];
	int tun, len;

	tun = vpn_tun_alloc(argc > 1? argv[1]: "utun0");
	if (tun == -1) {
		return -1;
	}

	module_init();

	system("ifconfig utun0 10.2.0.2/24 10.2.0.15 up");
	system("route add -net 119.75.217.0/24 10.2.0.15");
	system("route add -net 31.193.132.0/24 10.2.0.15");

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

