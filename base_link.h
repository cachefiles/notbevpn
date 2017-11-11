#ifndef _BASE_LINK_H_
#define _BASE_LINK_H_

#include <stdint.h>
#ifdef WIN32
#include <winsock.h>
typedef int socklen_t;
#define MSG_DONTWAIT 0
#else
#include <sys/socket.h>
#endif

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len);
int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len);

#define SOT(addr) (struct sockaddr *)addr
#define MAX_PACKET_SIZE 2048

#ifdef __ANDROID__
#include <android/log.h>
#define LOG_TAG "WalleyeService"
#define LOG_DEBUG(fmt, args...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args)
#if 0
#define LOG_VERBOSE(fmt, args...)  __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, fmt, ##args)
#endif
#endif


#ifndef LOG_DEBUG
int log_tag_putlog(const char *tag, const char *fmt, ...);
#define LOG_DEBUG(fmt, args...)   log_tag_putlog("D", fmt, ##args)
#endif

#ifndef LOG_VERBOSE
#define LOG_VERBOSE(fmt, args...) log_tag_putlog("V", fmt, ##args)
#endif

#define MIN(a, b) ((a) < (b)? (a): (b))
#define MAX(a, b) ((a) < (b)? (b): (a))

struct low_link_ops {
	int (*create)(void);
	int (*get_adjust)(void);
	int (*send_data)(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len);
	int (*recv_data)(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len);
};

int setblockopt(int fd, int block);
int protect_match(void *buf, size_t len);
int protect_reset(int proto, void *buf, size_t len, const struct sockaddr *ll_addr, socklen_t ll_len);

#endif
