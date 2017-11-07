#ifndef _CONFIG_H_
#define _CONFIG_H_

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
#endif

#ifdef __linux__
#define __BSD_VISIBLE 1
#define	__packed	__attribute__((__packed__))
#define	__aligned(x)	__attribute__((__aligned__(x)))
#include <netdb.h>
#include <arpa/inet.h>
#include <bsd/queue.h>
#include <bsdinet/ip.h>
#include <bsdinet/ip6.h>
#include <bsdinet/tcp.h>
#include <bsdinet/udp.h>
#endif

#ifndef __BSD_VISIBLE
#include <netdb.h>
#include <sys/queue.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

#endif
