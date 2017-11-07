#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#include <netinet/ip.h>
#include <sys/uio.h>

#include <arpa/inet.h>

#define err(fmt) fprintf(stderr, fmt)
#define errf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#define utun_read  tun_read
#define utun_write tun_write

static inline int utun_modified_len(int len)
{
	if (len > 0)
		return (len > sizeof (u_int32_t)) ? len - sizeof (u_int32_t) : 0;
	else
		return len;
}

int utun_write(int fd, void *buf, size_t len)
{
	u_int32_t type;
	struct iovec iv[2];
	struct ip *iph;

	iph = (struct ip *) buf;

	if (iph->ip_v == 6)
		type = htonl(AF_INET6);
	else
		type = htonl(AF_INET);

	iv[0].iov_base = &type;
	iv[0].iov_len = sizeof(type);
	iv[1].iov_base = buf;
	iv[1].iov_len = len;

	return utun_modified_len(writev(fd, iv, 2));
}

int utun_read(int fd, void *buf, size_t len)
{
	u_int32_t type;
	struct iovec iv[2];

	iv[0].iov_base = &type;
	iv[0].iov_len = sizeof(type);
	iv[1].iov_base = buf;
	iv[1].iov_len = len;

	return utun_modified_len(readv(fd, iv, 2));
}

int vpn_tun_alloc(const char *dev)
{
	struct ctl_info ctlInfo;
	struct sockaddr_ctl sc;
	int fd;
	int utunnum;

	if (dev == NULL) {
		errf("utun device name cannot be null");
		return -1;
	}
	if (sscanf(dev, "utun%d", &utunnum) != 1) {
		errf("invalid utun device name: %s", dev);
		return -1;
	}

	memset(&ctlInfo, 0, sizeof(ctlInfo));
	if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
			sizeof(ctlInfo.ctl_name)) {
		errf("can not setup utun device: UTUN_CONTROL_NAME too long");
		return -1;
	}

	fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

	if (fd == -1) {
		err("socket[SYSPROTO_CONTROL]");
		return -1;
	}

	if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
		close(fd);
		err("ioctl[CTLIOCGINFO]");
		return -1;
	}

	sc.sc_id = ctlInfo.ctl_id;
	sc.sc_len = sizeof(sc);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_unit = utunnum + 1;

	if (connect(fd, (struct sockaddr *) &sc, sizeof(sc)) == -1) {
		close(fd);
		err("connect[AF_SYS_CONTROL]");
		return -1;
	}

	return fd;
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
