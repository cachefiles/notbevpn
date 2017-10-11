#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#ifdef WIN32
#include <winsock.h>
typedef int socklen_t;
typedef unsigned long in_addr_t;
typedef unsigned short in_port_t;
#define MSG_DONTWAIT 0
#else
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

/*
 * stun.l.google.com:19302
 * stun.ekiga.net:3478
 */

enum {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,

    MAPPED_ADDRESS = 0x0001,
    CHANGE_REQUEST = 0x0003,
    SOURCE_ADDRESS = 0x0004,
    CHANGED_ADDRESS = 0x0005
};

#define STUN_MAX_REQUEST 64
#define STUN_FLAG_CTREAT 0x01
#define STUN_FLAG_FINISH 0x02
#define STUN_FLAG_READED 0x04
#define STUN_FLAG_TIMERD 0x08
#define STUN_FLAG_ERROR  0x10

struct request_context {
    int flags;
    size_t last_ticks;
    size_t retries_times;
    u_char request_ident[16];
    u_char request_source[128];
    struct sockaddr_in request_target;
};

static int carrier = 0;
// static int pending_timeout = 0;
static int pending_incoming = 0;
static struct request_context all_request_list[STUN_MAX_REQUEST];

static size_t utils_getticks(void)
{
#if defined(WIN32)
	DWORD ticks;

	ticks = GetTickCount();

	return ticks;
#elif defined(__APPLE__)
    clock_serv_t cclock;
    mach_timespec_t ts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &ts);
    mach_port_deallocate(mach_task_self(), cclock);
    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#else
	int err;
	struct timespec ts;

	err = clock_gettime(CLOCK_MONOTONIC, &ts);
	assert(err == 0);

	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
}

#define MIN_PACKET_LEN sizeof(struct stun_request_args_base)

struct stun_request_args_base {
    u_short binding_request, payload_length;
    u_char  request_session_key[16];
};

static void clear_carrier(void)
{
    while (carrier > 0) {
        fprintf(stderr, "\b");
        carrier--;
    }

    return;
}

static void output_carrier(void)
{
    fprintf(stderr, ".");
    carrier++;
    return;
}

static u_char *stun_pack(u_char *dst, u_short type, const void *src, size_t len)
{
    * (u_short *)dst = htons(type);
    dst += sizeof(u_short);

    * (u_short *)dst = htons(len);
    dst += sizeof(u_short);

    memcpy(dst, src, len);
    dst += len;

    return dst;
}

static void output_debug_attrib(u_short attrib, u_char *but, u_short len)
{
	struct {
		u_short family;
		u_short port;
		struct in_addr in1addr;
	} stun_addr;
	size_t cplen;

	cplen = sizeof(stun_addr);
	memcpy(&stun_addr, but, len > cplen? cplen: len);

	switch(attrib) {
		case CHANGED_ADDRESS:
			assert(len == 8);
			fprintf(stderr, "changed address: %s:%d\n",
					inet_ntoa(stun_addr.in1addr), htons(stun_addr.port));
			break;

		case SOURCE_ADDRESS:
			assert(len == 8);
			fprintf(stderr, "source address: %s:%d\n",
					inet_ntoa(stun_addr.in1addr), htons(stun_addr.port));
			break;

		case MAPPED_ADDRESS:
			assert(len == 8);
			fprintf(stderr, "mapped address: %s:%d\n",
					inet_ntoa(stun_addr.in1addr), htons(stun_addr.port));
			break;
	}

	return;
}

static void extract_stun_packet(u_char *but, size_t len)
{
	u_short attrib, length;
	u_char *limit = but + len;

	while (but + 4 <= limit) {
		attrib = *(u_short *)but;
		but += sizeof(u_short);
		attrib = htons(attrib);

		length = *(u_short *)but;
		but += sizeof(u_short);
		length = htons(length);

		if (but + length > limit) {
			fprintf(stderr, "extract stun attrib failure\n");
			break;
		}

		output_debug_attrib(attrib, but, length);
		but += length;
		continue;
	}

	return;
}

static u_int stun_do_packet(int fildes, u_char *but, size_t len, struct sockaddr *from, socklen_t fromlen)
{
	u_int flags = 0;
	size_t d_off = 0;
	struct stun_request_args_base args0;

	if (len > 0 && len < MIN_PACKET_LEN) {
		struct sockaddr_in so;
		clear_carrier();
		memcpy(&so, from, fromlen);
		fprintf(stderr, "incoming: %s:%d\n",
				inet_ntoa(so.sin_addr), ntohs(so.sin_port));
		return 0;
	}

	if (len < MIN_PACKET_LEN || len >= 1024) {
		clear_carrier();
#ifndef WIN32
		fprintf(stderr, "recv_len %ld, error %d", len, errno);
#else
		fprintf(stderr, "recv_len %ld, error %d", len, GetLastError());
#endif
		return 0;
	}

	{
		struct sockaddr_in so;
		clear_carrier();
		memcpy(&so, from, fromlen);
		fprintf(stderr, "incoming: %s:%d\n",
				inet_ntoa(so.sin_addr), ntohs(so.sin_port));
	}

	d_off = sizeof(args0);
	memcpy(&args0, but, sizeof(args0));

	if (args0.binding_request == htons(BindingErrorResponse)
			|| args0.binding_request == htons(BindingResponse)) {
		extract_stun_packet(but + d_off, len - d_off);
		flags = STUN_FLAG_READED;
		return flags;
	}

	if (args0.binding_request == htons(BindingRequest)) {
		int error;
		size_t len;
		u_char *adj;
		u_char d_buf[2048];
		struct sockaddr_in d_addr;
		socklen_t namelen = sizeof(d_addr);

		struct {
			u_short family;
			u_short port;
			u_int   address;
		} attrib_addr;

		adj = (d_buf + d_off);
		memcpy(&d_addr, from, fromlen);

		attrib_addr.family  = htons(1);
		attrib_addr.port    = d_addr.sin_port;
		attrib_addr.address = d_addr.sin_addr.s_addr;
		adj = stun_pack(adj, MAPPED_ADDRESS, &attrib_addr, sizeof(attrib_addr));

		error = getsockname(fildes, (struct sockaddr *)&d_addr, &namelen);
		assert(error == 0);

		attrib_addr.family  = htons(1);
		attrib_addr.port    = d_addr.sin_port;
		attrib_addr.address = d_addr.sin_addr.s_addr;
		adj = stun_pack(adj, SOURCE_ADDRESS, &attrib_addr, sizeof(attrib_addr));

		len = adj - d_buf;
		args0.payload_length = htons(len - d_off);
		args0.binding_request = htons(BindingResponse);
		memcpy(d_buf, &args0, d_off);

		(void)sendto(fildes, (char *)d_buf, len, 0, from, fromlen);
		fprintf(stderr, "output packet\n");
		return 0;
	}

	fprintf(stderr, "invalid packet\n");
	return flags;
}

static void outgoing_stun_request(struct request_context *ctx, int fildes, unsigned change_type)
{
	u_char *adj;
	size_t d_off;
	u_char d_buf[2048];
	struct stun_request_args_base arg0;

	// u_char  request_session_key[16];

	d_off = sizeof(arg0);
	arg0.binding_request = htons(BindingRequest);
	arg0.payload_length  = htons(0);

	adj = d_buf + d_off;

	if (change_type) {
		change_type = htonl(change_type);
		adj = stun_pack(adj, CHANGE_REQUEST, &change_type, sizeof(change_type));
	}

	ctx->last_ticks = utils_getticks();
	memcpy(arg0.request_session_key, ctx->request_ident, sizeof(ctx->request_ident));
	memcpy(arg0.request_session_key + 12, &ctx->last_ticks, 4);
	arg0.request_session_key[11] = ctx->retries_times++;
	arg0.payload_length = htons(adj - d_buf - d_off);

	memcpy(d_buf, &arg0, d_off);
	(void)sendto(fildes, (char *)d_buf, adj - d_buf, 0,
			(const struct sockaddr *)&ctx->request_target, sizeof(ctx->request_target));
	fprintf(stderr, "output request: %s\n", ctx->request_source);
	pending_incoming++;
	return;
}

static void stun_do_output(u_int flags, int fildes, size_t ticks, u_char *but, size_t len, u_int change_type)
{
	int index;
	int receive = 0;
	int timeout = 0;
	struct request_context *ctx;
	struct stun_request_args_base arg0;

	receive = (flags & STUN_FLAG_READED);
	timeout = (flags & STUN_FLAG_TIMERD);

	if (receive) 
		memcpy(&arg0, but, sizeof(arg0));

	if (timeout && pending_incoming)
		pending_incoming--;

	index = 0;
#define STUN_FLAG_DOING(flags) ((STUN_FLAG_CTREAT| STUN_FLAG_FINISH) & flags)
	for (; flags != 0 && index < STUN_MAX_REQUEST; index++) {
		ctx = all_request_list + index;
		if (STUN_FLAG_DOING(ctx->flags) != STUN_FLAG_CTREAT) {
			/* skip this context */
			continue;
		}

		if (receive != 0 &&
				0 == memcmp(ctx->request_ident, arg0.request_session_key, 11)) {
			ctx->flags |= STUN_FLAG_FINISH;
			pending_incoming--;
			receive = 0;
			continue;
		}

		if (pending_incoming < 3
				&& ctx->last_ticks + 1000 < ticks && ctx->retries_times < 3) {
			outgoing_stun_request(ctx, fildes, change_type);
		}

		if (pending_incoming >= 3 && receive == 0) {
			fprintf(stderr, "waiting for netxt retries\n");
			break;
		}
	}

	return;
}

static void load_stun_config(int argc, char *argv[])
{
	int i;
	int index = 0;
	char domainbuf[127];

	for (i = 1; i < argc; i++) {
        int j;
		int d_port = 3478;
		char *port = 0;
		char *hostname = NULL;
		in_addr_t target = 0;
		struct request_context *ctx = NULL;

		if (argv[i] == NULL) {
			/* use by option */
			continue;
		}

		strcpy(domainbuf, argv[i]);
		hostname = domainbuf;

		fprintf(stderr, "gethostname: %s\n", hostname);

		if (NULL != (port = strchr(domainbuf, ':'))) {
			*port++ = 0;
			d_port = atoi(port);
			if (d_port == -1) {
				fprintf(stderr, "get port failure: %s\n", argv[i]);
				continue;
			}
		}

		target = inet_addr(hostname);
		if (target == INADDR_ANY || target == INADDR_NONE) {
			struct hostent *phost = gethostbyname(hostname);
			if (phost == NULL) {
				fprintf(stderr, "get hostname failure: %s\n", argv[i]);
				continue;
			}
			memcpy(&target, phost->h_addr, sizeof(target));
		}

		ctx = &all_request_list[index++];
		strcpy((char *)ctx->request_source, argv[i]);
		ctx->last_ticks = 0;
		ctx->retries_times = 0;
		ctx->flags = STUN_FLAG_CTREAT;

		ctx->request_target.sin_family = AF_INET;
		ctx->request_target.sin_port   = htons(d_port);
		ctx->request_target.sin_addr.s_addr =  target;

		fprintf(stderr, "%s ", argv[i]);

		for (j = 0; j < 8; j++) {
			u_short *ident = (u_short *)ctx->request_ident;
			ident[j] = rand();
			fprintf(stderr, "%04x", htons(ident[j]));
		}

		fprintf(stderr, "\n");
	}

	return;
}

u_int stun_change_flag(const char *change_type)
{
	u_int type = 0;

	if (strcmp(change_type, "port") == 0) {
		type |= 0x2;
	} else if (strcmp(change_type, "ip") == 0) {
		type |= 0x4;
	} else if (strcmp(change_type, "all") == 0) {
		type |= 0x4;
		type |= 0x2;
	} else if (strcmp(change_type, "ip:port") == 0) {
		type |= 0x4;
		type |= 0x2;
	}

	return type;
}

int main(int argc, char *argv[])
{
	int i;
	int error;
	int fildes;
	u_int change_type = 0;
	fd_set readfds;
	fd_set writefds;
	size_t last_idle;
	size_t last_ticks;
	struct sockaddr yours;
	struct sockaddr_in mime;

#ifdef WIN32
	WSADATA data;
	WSAStartup(0x101, &data);
#endif

	fildes = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fildes != -1);

	mime.sin_family = AF_INET;
	mime.sin_port   = htons(9000);
	mime.sin_addr.s_addr = 0;

	for (i = 1; i < argc; i++) {
		if (0 == strncmp(argv[i], "-p", 2)) {
			int d_port = 3478;
			const char *opt = argv[i] + 2;

			if (*opt !=  0) {
				argv[i] = NULL;
				d_port = atoi(opt + (*opt == '='));
			} else if (argc > i + 1) {
				argv[i] = NULL;
				d_port = atoi(argv[++i]);
				argv[i] = NULL;
			}

			mime.sin_port = htons(d_port);
		} else if (0 == strncmp(argv[i], "-f", 2)) {
			const char *opt = argv[i] + 2;

			if (*opt !=  0) {
				argv[i] = NULL;
				change_type = stun_change_flag(opt + (*opt == '='));
			} else if (argc > i + 1) {
				argv[i] = NULL;
				change_type = stun_change_flag(argv[++i]);
				argv[i] = NULL;
			}
		}
	}

	error = bind(fildes, (const struct sockaddr *)&mime, sizeof(mime));
	assert(error == 0);

	last_idle = utils_getticks();
	last_ticks = utils_getticks();
	load_stun_config(argc, argv);

	stun_do_output(STUN_FLAG_TIMERD, fildes, last_ticks, NULL, 0, change_type);
	while (pending_incoming > 0 || last_idle + 48000 > last_ticks) {
		u_char but[1024];
		u_int  stun_flags;
		size_t stun_ticks;
		struct timeval tval;

		tval.tv_sec = 1;
		tval.tv_usec = 0;

		FD_ZERO(&readfds);
		FD_SET(fildes, &readfds);

		FD_ZERO(&writefds);
		FD_SET(fildes, &writefds);
		error = select(fildes + 1, &readfds, NULL, NULL, &tval);
		assert(error != -1);

		stun_flags = 0;
		if (error > 0 && FD_ISSET(fildes, &readfds)) {
			socklen_t yourlen = sizeof(yours);
			error = recvfrom(fildes, (char *)but, sizeof(but), MSG_DONTWAIT, &yours, &yourlen);
			stun_flags = stun_do_packet(fildes, but, error, &yours, yourlen);
			last_idle = utils_getticks();
		}

		stun_ticks = utils_getticks();
		if (stun_ticks > last_ticks + 1000) {
			stun_flags |= STUN_FLAG_TIMERD;
			last_ticks = stun_ticks;
			output_carrier();
		}

		stun_do_output(stun_flags, fildes, stun_ticks, but, error, change_type);
		continue;
	}


#if defined(WIN32)
	closesocket(fildes);
	WSACleanup();
#else
	close(fildes);
#endif

	clear_carrier();
	return 0; 
}


