#include <stdio.h>
#include <assert.h>
#include <android/log.h>
#include <jni.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <base_link.h>

#define tun_write write
#define tun_read  read
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

int tcpup_track_stage1(void);
int tcpup_track_stage2(void);
int check_blocked(int tunfd, char *packet, size_t len, time_t *limited);
int check_blocked_normal(int tunfd, char *packet, size_t len);

char * get_tcpup_data(int *len);
char * get_tcpip_data(int *len);

ssize_t tcpup_frag_input(void *packet, size_t len, size_t limit);
ssize_t tcpip_frag_input(void *packet, size_t len, size_t limit);

static int last_track_count = 0;
static int last_track_enable = 0;
static time_t last_track_time = 0;

static int _lostlink = 0;
static int _disconnected = 0;
static int _is_powersave = 0;
static int _off_powersave = 0;
static time_t _time_powersave = 0;

static struct sockaddr_in ll_addr = {};
static struct sockaddr_in tmp_addr = {};

static int _probe_sent = 0;
static int _invalid_recv = 0;
static int _invalid_sent = 0;

static int _total_tx_pkt = 0;
static int _total_tx_bytes = 0;

static int _total_rx_pkt = 0;
static int _total_rx_bytes = 0;

extern struct low_link_ops udp_ops, icmp_ops;

static int check_link_failure(int txretval)
{
	if (txretval == -1)
		return (errno != ENOBUFS && errno != EAGAIN);

	return 0;
}

static int is_blocked(int tunfd, char *packet, size_t len)
{
	int time_check = 0;
	time_t time_current = 0;

	if (_off_powersave) {
		return check_blocked(tunfd, packet, len, &_time_powersave);
	} else if (!_is_powersave) {
		return check_blocked_normal(tunfd, packet, len);
	}

	time(&time_current);
	_off_powersave = (_time_powersave > time_current) || (_time_powersave + 30 < time_current);
	check_blocked(-1, packet, len, &_time_powersave);

	return 0;
}

static int vpn_run_loop(int tunfd, int netfd, struct low_link_ops *link_ops)
{
	int len;
	int ignore;
	int nready = 0;
	int loop_try = 0;
	char buf[2048];
	fd_set readfds;
	int tun_nbytes = 0, tun_npacket = 0;
	int net_nbytes = 0, net_npacket = 0;

	FD_ZERO(&readfds);
	while ( !_disconnected && !_lostlink) {
		int test = 0;
		char * packet;
		struct timeval timeo = {};

		loop_try++;
		if (nready <= 0 || loop_try > 1000) {
			if (last_track_enable && tcpup_track_stage2()) {
				last_track_enable = 0;
				if ((packet = get_tcpup_data(&len)) != NULL
						&& _is_powersave == 0) {
					ignore = (*link_ops->send_data)(netfd, packet, len, SOT(&ll_addr), sizeof(ll_addr));
					LOG_DEBUG("send probe data: %d\n", len);
					_probe_sent++;
					if (check_link_failure(ignore)) return -1;
				}
			}

			FD_ZERO(&readfds);
			FD_SET(tunfd, &readfds);
			FD_SET(netfd, &readfds);

			timeo.tv_sec  = 1;
			timeo.tv_usec = 0;

			test++;
			loop_try = 0;
			nready = select(1 + MAX(tunfd, netfd), &readfds, NULL, NULL, &timeo);
			if (nready == -1) {
				LOG_VERBOSE("select failure");
				return -1;
			}

			if (nready == 0 || ++last_track_count >= 20) {
				time_t now = time(NULL);
				if (now < last_track_time || last_track_time + 4 < now) {
					tcpup_track_stage1();
					last_track_time  = now;
					last_track_count = 0;
				}
			}
		}

		packet = (buf + 60);
		if (FD_ISSET(netfd, &readfds)) {
			int bufsize = 1500;
			socklen_t tmp_alen = sizeof(tmp_addr);

			test++;
			assert(bufsize + 60 < sizeof(buf));
			len = (*link_ops->recv_data)(netfd, packet, bufsize, SOT(&tmp_addr), &tmp_alen); 
			if (len < 0) {
				LOG_VERBOSE("read netfd failure fd=%d, error: %s, %d/%d\n", netfd, strerror(errno), net_nbytes, net_npacket);
				net_npacket = net_nbytes = 0;
				FD_CLR(netfd, &readfds);
				nready--;
				continue;
			}

			if (len > 0) {
				net_npacket++;
				net_nbytes += len;
				len = tcpup_frag_input(packet, len, 1500);
				if (len > 0) _invalid_sent ++;
				ignore = (len <= 0)? 0: (*link_ops->send_data)(netfd, packet, len, SOT(&tmp_addr), tmp_alen);
				if (check_link_failure(ignore)) return -1;
			}

			packet = get_tcpip_data(&len);
			if (packet != NULL) {
				len = tun_write(tunfd, packet, len);
				// LOG_VERBOSE("write tun: %d\n", len);
				if (len > 0) {
					_total_rx_pkt++;
					_total_rx_bytes += len;
				}
			}

			if (packet == NULL) _invalid_recv++;
		}

		packet = (buf + 60);
		if (FD_ISSET(tunfd, &readfds)) {
			test++;
			len = tun_read(tunfd, packet, 1500);
			if (len < 0) {
				LOG_VERBOSE("read tunfd failure fd = %d, %s %d/%d\n", tunfd, strerror(errno), tun_nbytes, tun_npacket);
				tun_npacket = tun_nbytes = 0;
				FD_CLR(tunfd, &readfds);
				nready--;
				continue;
			}

			_total_tx_pkt++;
			_total_tx_bytes += len;
			if (is_blocked(tunfd, packet, len)) {
				LOG_VERBOSE("ignore blocked data\n");
				continue;
			}

			if (len > 0) {
				tun_nbytes += len;
				tun_npacket++;
				len = tcpip_frag_input(packet, len, 1500);
				ignore = (len <= 0)? 0: tun_write(tunfd, packet, len);
				if (len > 0) {
					_total_rx_pkt++;
					_total_rx_bytes += len;
				}
			}

			packet = get_tcpup_data(&len);
			if (packet != NULL) {
				ignore = (*link_ops->send_data)(netfd, packet, len, SOT(&ll_addr), sizeof(ll_addr));
				// LOG_VERBOSE("send data: %d\n", ignore);
				if (check_link_failure(ignore)) return -1;
				last_track_enable = 1;
			}
		}

		assert(test > 0);
	}

clean:
	return 0;
}

#define MAX_FDS 100
static int _alength = 0;
static int _elements[MAX_FDS] = {};

static int add_pending_fd(int fd)
{
	assert (_alength < MAX_FDS);
	_elements[_alength++] = fd;
	return 0;
}

static int get_pendingfds(int elements[], int length)
{
	if (length > _alength) {
		length = _alength;
		memcpy(elements, _elements, length * sizeof(int));
		_alength = 0;
		return length;
	}

	_alength -= length;
	memcpy(elements, _elements, length * sizeof(int));
	memmove(_elements, _elements + length, _alength * sizeof(int));
	return length;
}

static int _link_fd = -1;
static struct sockaddr_in _last_bind[10] = {};
static struct low_link_ops *_link_ops[10] = {NULL};

static int bind_last_address(int netfd, int which)
{
	int error;
	struct sockaddr_in sin_addr = _last_bind[which];

	sin_addr.sin_family = AF_INET;
	sin_addr.sin_addr.s_addr = 0;

	error = bind(netfd, (struct sockaddr *)&sin_addr, sizeof(sin_addr));
	if (error != 0) {
		goto ignore_error;
	}

	socklen_t slen = sizeof(sin_addr);
	error = getsockname(netfd, (struct sockaddr *)&_last_bind[which], &slen);
	LOG_DEBUG("getsockname: %s:%d, error = %d\n",
			inet_ntoa(sin_addr.sin_addr), htons(sin_addr.sin_port), error);

ignore_error:
	return 0;
}

static int vpn_jni_alloc(JNIEnv *env, jclass clazz, int type)
{
	int i;
	int index = -1;
	struct low_link_ops **link_ops = NULL;

	for (i = 0; i < ARRAY_SIZE(_link_ops); i++) {
		if (_link_ops[i] == NULL) {
			link_ops = &_link_ops[i];
			index = i;
			break;
		}
	}

	if (link_ops != NULL) {
		switch(type) {
			case IPPROTO_ICMP:
				*link_ops = &icmp_ops;
				break;

			case IPPROTO_UDP:
				*link_ops = &udp_ops;
				break;

			default:
				abort();
				break;
		}
	}

	return index;
}

static int vpn_jni_free(JNIEnv *env, jclass clazz, jint which)
{
	_link_ops[which] = NULL;
	close(_link_fd);
	_link_fd = -1;
	return 0;
}

static int vpn_jni_set_lostlink(JNIEnv *env, jclass clazz, jint which)
{
	_lostlink = 1;
	return 0;
}

int set_tcp_mss_by_mtu(int mtu);
static int vpn_jni_set_server(JNIEnv *env, jclass clazz, jint which, jstring server)
{
	char *port_ptr = NULL;
	char _domain[64] = {};
	const char *domain = (*env)->GetStringUTFChars(env, server, 0);

	strncpy(_domain, domain, sizeof(_domain) -1);
	ll_addr.sin_port   = htons(138);

	port_ptr = strchr(_domain, ':');
	if (port_ptr != NULL) {
		*port_ptr++ = 0;
		ll_addr.sin_port = htons(atoi(port_ptr));
	}

	ll_addr.sin_family = AF_INET;
	ll_addr.sin_addr.s_addr = inet_addr(_domain);

	(*env)->ReleaseStringUTFChars(env, server, domain);

	struct low_link_ops *link_ops = _link_ops[which];

	int adjust = (*link_ops->get_adjust)();
	_disconnected = 0;
	set_tcp_mss_by_mtu(1500 - 20 - adjust);

	return 0;
}

static int vpn_jni_set_disconnect(JNIEnv *env, jclass clazz, jint which)
{
	_disconnected = 1;
	return 0;
}

static int vpn_jni_set_powersave(JNIEnv *env, jclass clazz, jint which, jboolean save)
{
	LOG_DEBUG("invalid TX/RX %d/%d, probe TX %d\n", _invalid_sent, _invalid_recv, _probe_sent);
	time(&_time_powersave);
	_is_powersave = save;
	_off_powersave = 0;
	return 0;
}

#define PUT_ONE(index, length, array, value) \
	do { if (index < length) array[index++] = value; } while (0)

static int vpn_jni_get_statistics(JNIEnv *env, jclass clazz, jint which, jintArray fds)
{
	int count = 0;
	int length = (*env)->GetArrayLength(env, fds);
	jint *elements = (*env)->GetIntArrayElements(env, fds, 0);

	PUT_ONE(count, length, elements, _probe_sent);
	PUT_ONE(count, length, elements, _invalid_sent);
	PUT_ONE(count, length, elements, _invalid_recv);

	PUT_ONE(count, length, elements, _total_tx_pkt);
	PUT_ONE(count, length, elements, _total_tx_bytes);

	PUT_ONE(count, length, elements, _total_rx_pkt);
	PUT_ONE(count, length, elements, _total_rx_bytes);

	(*env)->ReleaseIntArrayElements(env, fds, elements, JNI_COMMIT);
	return count;
}

static int vpn_jni_get_pendingfds(JNIEnv *env, jclass clazz, jint which, jintArray fds)
{
	int count;
	int length = (*env)->GetArrayLength(env, fds);
	jint *elements = (*env)->GetIntArrayElements(env, fds, 0);
	count = get_pendingfds(elements, length);
	(*env)->ReleaseIntArrayElements(env, fds, elements, JNI_COMMIT);
	return count;
}

static int vpn_jni_loop_main(JNIEnv *env, jclass clazz, jint which, jint tunfd)
{
	int link_failure;
	int netfd = _link_fd;
	struct low_link_ops *link_ops = _link_ops[which];

	if (netfd == -1) {
		netfd = link_ops->create();
		assert (netfd != -1);
		bind_last_address(netfd, which);
		add_pending_fd(netfd);
		_link_fd = netfd;
	}

	if (_alength > 0) {
		return 1;
	}

	link_failure = vpn_run_loop(tunfd, netfd, link_ops);
	if (link_failure == -1
			&& _disconnected == 0) {
		close(netfd);
		netfd = link_ops->create();
		assert (netfd != -1);
		bind_last_address(netfd, which);
		add_pending_fd(netfd);
		_link_fd = netfd;
	}

	if (_alength > 0) {
		return 1;
	}

	return 0;
}

static const char className[] = "net/cachefiles/walleye/NotBeVPN";

static JNINativeMethod methods[] = {
	{"vpn_alloc", "(I)I", (void*)vpn_jni_alloc},

	{"vpn_set_server", "(ILjava/lang/String;)I", (void*)vpn_jni_set_server},
	{"vpn_set_lostlink", "(I)I", (void*)vpn_jni_set_lostlink},
	{"vpn_set_disconnect", "(I)I", (void*)vpn_jni_set_disconnect},

	{"vpn_get_statistics", "(I[I)I", (void*)vpn_jni_get_statistics},
	{"vpn_get_pendingfds", "(I[I)I", (void*)vpn_jni_get_pendingfds},

	{"vpn_set_powersave", "(IZ)I", (void*)vpn_jni_set_powersave},
	{"vpn_loop_main", "(II)I", (void*)vpn_jni_loop_main},
	{"vpn_free", "(I)I", (void*)vpn_jni_free}
};

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
	JNIEnv* env = NULL;
	jclass clazz;
	jint result = JNI_ERR;
	int nMethod = 0;

	if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_4) != JNI_OK) {
		LOG_VERBOSE("GetEnv failure\n");
		return JNI_ERR;
	}

	assert(env != NULL);
	clazz = (*env)->FindClass(env, className);
	if (clazz == NULL) {
		LOG_VERBOSE("FindClass %s failure", className);
		return JNI_ERR;
	}

	nMethod = sizeof(methods) / sizeof(methods[0]);
	if ((*env)->RegisterNatives(env, clazz, methods, nMethod) < 0) {
		LOG_VERBOSE("RegisterNatives %s failure", className);
		return JNI_ERR;
	}

	result = JNI_VERSION_1_4;
	return result;
}

void JNI_OnUnload(JavaVM* vm, void* reserved){
	LOG_VERBOSE("JNI_OnUnload"); 
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
