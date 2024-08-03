#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

       #include <sys/types.h>
       #include <sys/socket.h>
       #include <netdb.h>

#ifdef __ANDROID__
#include <android/log.h>
#define LOG_TAG "WalleyeService"
#define LOG_DEBUG(fmt, args...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args)
#define LOG_VERBOSE(fmt, args...)  __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, fmt, ##args)
#else
#define LOG_DEBUG(fmt, args...)  fprintf(stderr, fmt, ##args)
#define LOG_VERBOSE(fmt, args...) fprintf(stderr, fmt, ##args)
#endif

#define MAX_LISTEN 100

#define MAX(a, b) ((a) < (b)? (b): (a))

#define _family AF_INET

#if _family == AF_INET
#define INET_TYPE(f) f##_in
#define INET_FIELD(v, f) v.sin_##f
#endif

#if _family == AF_INET6
#define INET_TYPE(f) f##_in6
#define INET_FIELD(v, f) v.sin6_##f
#endif

const char http_response[] = 
"HTTP/1.1 200 OK\r\n"
"Server: bfe/1.0.8.18\r\n"
"Content-Type: text/html\r\n"
"Content-Length: 0\r\n"
"Connection: close\r\n"
"Accept-Ranges: bytes\r\n"
"\r\n"
;

static void handle_connection(int lfd)
{
	int newfd;
	int count;
	char buf[8192];
	char *buf_limit = buf + sizeof(buf) -1;

	newfd = accept(lfd, NULL, NULL);

	if (newfd != -1) {
		char *pbuf = buf;
		count = 0;

		usleep(1000);
		do {
			pbuf += count;
			count = recv(newfd, pbuf, buf_limit - pbuf, MSG_DONTWAIT);
		} while (count > 0 && pbuf < buf_limit);

		*pbuf = 0;
		if (strncmp("GET ", buf, 4) == 0
				|| strncmp("POST ", buf, 5) == 0) {
			pbuf = strstr(buf, "\r\n\r\n");
			if (pbuf == NULL) {
				pbuf = strstr(buf, "\r\n");
			}

			if (pbuf != NULL) {
				*pbuf = 0;
				LOG_DEBUG("%s\n", buf);
			}
		}

		send(newfd, http_response, sizeof(http_response) -1, 0);
		close(newfd);
	}

	return;
}


static void dump_getaddrinfo(const char *mydomain)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL, *rp;
    int sfd, s;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ssize_t nread;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = 0;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;


    s = getaddrinfo(mydomain, "80", &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char buf[123];
        struct sockaddr_in6 *inp6 = (struct sockaddr_in6*)rp->ai_addr;
        struct sockaddr_in  *inp4 = (struct sockaddr_in *)rp->ai_addr;
        if (rp->ai_family == AF_INET6) {
            fprintf(stderr, "getaddrinfo6: %s\n", inet_ntop(AF_INET6, &inp6->sin6_addr, buf, sizeof(buf)));
        }
        if (rp->ai_family == AF_INET) {
            fprintf(stderr, "getaddrinfo4: %s\n", inet_ntop(AF_INET, &inp4->sin_addr, buf, sizeof(buf)));
        }
    }

    freeaddrinfo(result);
}


int main(int argc, char *argv[])
{
	int i;
	int fd, error;
	int nfd = 0, fds[MAX_LISTEN];
	struct INET_TYPE(sockaddr) lladdr;

	signal(SIGPIPE, SIG_IGN);
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-b") == 0) {
			int error = daemon(0, 1);
			assert (error == 0);
			LOG_DEBUG("process pid: %d\n", getpid());
		} else if (strcmp(argv[i], "-h") == 0) {
			fprintf(stderr, "usage: %s [-b] [-l <port>]\n", argv[0]);
			fprintf(stderr, "\t [-b] run in background\n");
			fprintf(stderr, "\t [-l <port>] listen the port, can be multi times \n");
			fprintf(stderr, "\t\n");
			exit(0);
		} else if (strcmp(argv[i], "-t") == 0) {
                        dump_getaddrinfo(i == argc? "www.google.com": argv[i + 1]);
			exit(0);
		} else if (i + 1 < argc && strcmp(argv[i], "-l") == 0) {
			int port = atoi(argv[++i]);
			assert (port > 1024 && port < 65536);

			fd = socket(_family, SOCK_STREAM, 0);
			assert(fd != -1);

			INET_FIELD(lladdr, family) = _family;
			INET_FIELD(lladdr, port)   = htons(port);
			error = bind(fd, (struct sockaddr *)&lladdr, sizeof(lladdr));
			assert(error == 0);

			error = listen(fd, 5);
			assert(error == 0);

			assert(nfd < MAX_LISTEN);
			fds[nfd++] = fd;
		}
	}

	int maxfd = -1;
	fd_set readfds = {};

	for (; nfd > 0;) {
		maxfd = -1;
		FD_ZERO(&readfds);
		for (i = 0; i < nfd; i++) {
			FD_SET(fds[i], &readfds);
			maxfd = MAX(maxfd, fds[i]);
		}

		error = select(maxfd +1, &readfds, NULL, NULL, NULL);
		if (error <= 0) {
			break;
		}

		for (i = 0; i < nfd && error > 0; i++) {
			if (FD_ISSET(fds[i], &readfds)) {
				handle_connection(fds[i]);
				error--;
			}
		}
	}

	for (i = 0; i < nfd; i++) {
		close(fds[i]);
	}

	return 0;
}

