#include <stdio.h>
#include <assert.h>
#include <android/log.h>
#include <jni.h>
#include <unistd.h>
#include <stdlib.h>

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
char * get_tcpup_data(int *len);
char * get_tcpip_data(int *len);

ssize_t tcpup_frag_input(void *packet, size_t len, size_t limit);
ssize_t tcpip_frag_input(void *packet, size_t len, size_t limit);

static int last_track_count = 0;
static int last_track_enable = 0;
static time_t last_track_time = 0;

static int _lostlink = 0;
static int _disconnected = 0;

static struct sockaddr_in ll_addr = {};
static struct sockaddr_in tmp_addr = {};

extern struct low_link_ops udp_ops, icmp_ops;

static int vpn_run_loop(int tunfd, int netfd, struct low_link_ops *link_ops)
{
	int len;
	int ignore;
	int nready = 0;
	int loop_try = 0;
	char buf[2048];

	while ( !_disconnected && !_lostlink) {
		int test = 0;
		fd_set readfds;
		char * packet;
		struct timeval timeo = {};

		loop_try++;
		if (nready <= 0 || loop_try > 1000) {
			FD_ZERO(&readfds);
			FD_SET(tunfd, &readfds);
			FD_SET(netfd, &readfds);

			timeo.tv_sec  = 1;
			timeo.tv_usec = 0;

			if (last_track_enable && tcpup_track_stage2()) {
				last_track_enable = 0;
				if ((packet = get_tcpup_data(&len)) != NULL) {
					(*link_ops->send_data)(netfd, packet, len, SOT(&ll_addr), sizeof(ll_addr));
					LOG_VERBOSE("send probe data: %d\n", len);
				}
			}

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
				LOG_VERBOSE("read netfd failure\n");
				FD_CLR(netfd, &readfds);
				nready--;
				continue;
			}

			if (len > 0) {
				len = tcpup_frag_input(packet, len, 1500);
				ignore = (len <= 0)? 0: (*link_ops->send_data)(netfd, packet, len, SOT(&tmp_addr), tmp_alen);
			}

			packet = get_tcpip_data(&len);
			if (packet != NULL) {
				len = tun_write(tunfd, packet, len);
			}
		}

		packet = (buf + 60);
		if (FD_ISSET(tunfd, &readfds)) {
			test++;
			len = tun_read(tunfd, packet, 1500);
			if (len < 0) {
				LOG_VERBOSE("read tunfd failure\n");
				FD_CLR(tunfd, &readfds);
				nready--;
				continue;
			}

			if (len > 0) {
				len = tcpip_frag_input(packet, len, 1500);
				ignore = (len <= 0)? 0: tun_write(tunfd, packet, len);
			}

			packet = get_tcpup_data(&len);
			if (packet != NULL) {
				(*link_ops->send_data)(netfd, packet, len, SOT(&ll_addr), sizeof(ll_addr));
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

static struct low_link_ops *_link_ops[10] = {NULL};

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
	return 0;
}

static int vpn_jni_set_lostlink(JNIEnv *env, jclass clazz, jint which)
{
	return 0;
}

static int vpn_jni_set_server(JNIEnv *env, jclass clazz, jint which, jstring server)
{
	return 0;
}

static int vpn_jni_set_disconnect(JNIEnv *env, jclass clazz, jint which)
{
	return 0;
}

static int vpn_jni_get_pendingfds(JNIEnv *env, jclass clazz, jint which, jintArray fds)
{
	int count;
	int length = (*env)->GetArrayLength(env, fds);
	jint *elements = (*env)->GetIntArrayElements(env, fds, 0);
	count = get_pendingfds(elements, length);
	(*env)->ReleaseIntArrayElements(env, fds, elements, 0);
	return count;
}

static int vpn_jni_loop_main(JNIEnv *env, jclass clazz, jint which, jint tunfd)
{
	static int netfd = -1;
	struct low_link_ops *link_ops = _link_ops[which];

	if (netfd == -1) {
		netfd = link_ops->create();
		assert (netfd != -1);
		add_pending_fd(netfd);
	}

	if (_alength > 0) {
		return 1;
	}

	vpn_run_loop(tunfd, netfd, link_ops);
	if (_alength > 0) {
		return 1;
	}

	return 0;
}

static const char className[] = "net/cachefiles/powervpn/PtcpupVPN";

static JNINativeMethod methods[] = {
	{"vpn_alloc", "(I)I", (void*)vpn_jni_alloc},

	{"vpn_set_server", "(ILjava/lang/String;)I", (void*)vpn_jni_set_server},
	{"vpn_set_lostlink", "(I)I", (void*)vpn_jni_set_lostlink},
	{"vpn_set_disconnect", "(I)I", (void*)vpn_jni_set_disconnect},

	{"vpn_get_pendingfds", "(ILI;)I", (void*)vpn_jni_get_pendingfds},

	{"vpn_loop_main", "(II)I", (void*)vpn_jni_loop_main},
	{"vpn_free", "(I)I", (void*)vpn_jni_free},
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

