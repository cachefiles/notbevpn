#ifndef _CONFIG_H_
#define _CONFIG_H_
#define FD_MAX(a, b) (((a) < (b))? (b): (a))

#ifdef WIN32
#include <win32cfg.h>
#define __BSD_VISIBLE 1
#define	__packed	__attribute__((__packed__))
#define	__aligned(x)	__attribute__((__aligned__(x)))
#include <bsd/queue.h>
#include <bsdinet/ip.h>
#include <bsdinet/ip6.h>
#include <bsdinet/tcp.h>
#include <bsdinet/udp.h>
int select_call(int tunfd, int netfd, /* int dnsfd,*/ fd_set *readfds, struct timeval *timeo);
int vpn_tun_free(int tunfd);
#endif

#ifdef __linux__
#define __BSD_VISIBLE 1
#define	__packed	__attribute__((__packed__))
#define	__aligned(x)	__attribute__((__aligned__(x)))
#include <netdb.h>
#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <bsd/queue.h>
#include <bsdinet/ip.h>
#include <bsdinet/ip6.h>
#include <bsdinet/tcp.h>
#include <bsdinet/udp.h>
#define select_call(tunfd, netfd, /* dnsfs,*/ readfds, timeo) select(FD_MAX(tunfd, netfd) + 1, readfds, NULL, NULL, timeo)
#define vpn_tun_free(p) close(p)
#endif

#if defined(__FreeBSD__) || !defined(__BSD_VISIBLE)
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
#define select_call(tunfd, netfd, /*dnsfd,*/ readfds, timeo) select(FD_MAX(tunfd, netfd) + 1, readfds, NULL, NULL, timeo)
#define vpn_tun_free(p) close(p)
#endif

#define ACK_TYPE_NONE 0
#define ACK_TYPE_NEED 1
#define ACK_TYPE_MUST 2

int get_ack_type(void);
int set_ack_type(int type);

#endif
