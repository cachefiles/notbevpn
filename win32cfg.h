#ifndef _WIN32CFG_H_
#define _WIN32CFG_H_

#include <sys/param.h>
#include <stdint.h>
#include <ws2tcpip.h>
#include <winsock.h>

typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint32_t in_addr_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;

#define bcopy(s, d, l) memcpy(d, s, l)

#endif

