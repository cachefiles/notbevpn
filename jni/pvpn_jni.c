#include <stdio.h>
#include <assert.h>
#include <android/log.h>
#include <jni.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define SOT(addr) (struct sockaddr *)addr
#define MAX_PACKET_SIZE 2048
#define MIN(a, b) ((a) < (b)? (a): (b))
#define socklen_t size_t
#define LOG_VERBOSE(fmt, args...)

int tcpup_track_stage1(void);
int tcpup_track_stage2(void);
char * get_tcpup_data(int *len);
char * get_tcpip_data(int *len);

ssize_t tcpup_frag_input(void *packet, size_t len, size_t limit);
ssize_t tcpip_frag_input(void *packet, size_t len, size_t limit);

static int last_track_count = 0;
static int last_track_enable = 0;
static time_t last_track_time = 0;

struct low_link_ops {
	int (*create)(void);
	int (*get_adjust)(void);
	int (*send_data)(int devfd, void *buf, size_t len, const struct sockaddr *ll_addr, size_t ll_len);
	int (*recv_data)(int devfd, void *buf, size_t len, struct sockaddr *ll_addr, socklen_t *ll_len);
};

static struct sockaddr_in ll_addr = {};
static struct sockaddr_in tmp_addr = {};
static struct low_link_ops *link_ops = NULL;

static int vpn_run_loop(int tunfd, int netfd)
{
	int len;
	int ignore;
	int nready;
	char buf[2048];

	for ( ; ; ) {
		fd_set readfds;
		char * packet;
		struct timeval timeo = {};

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

		packet = (buf + 60);
		while (FD_ISSET(netfd, &readfds)) {
			int bufsize = 1500;
			socklen_t tmp_alen = sizeof(tmp_addr);

			assert(bufsize + 60 < sizeof(buf));
			len = (*link_ops->recv_data)(netfd, packet, bufsize, SOT(&tmp_addr), &tmp_alen); 
			if (len < 0) {
				LOG_VERBOSE("read netfd failure\n");
				break;
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
		while (FD_ISSET(tunfd, &readfds)) {
			len = tun_read(tunfd, packet, 1500);
			if (len < 0) {
				LOG_VERBOSE("read tunfd failure\n");
				break;
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
	}

clean:
	return 0;
}

static int vpn_jni_init(JNIEnv *env, jclass clazz)
{
	return 0;
}

static int vpn_jni_loop(JNIEnv *env, jclass clazz)
{
	return 0;
}

static const char className[] = "";

static JNINativeMethod methods[] = {
	{"init", "()I", (void*)vpn_jni_init},
#if 0
	{"do_handshake", "(I)V", (void*)do_handshake},
	{"set_dnsmode", "(I)V", (void*)set_dns_mode},
	{"get_configure", "(I)[B", (void*)get_configure},
	{"set_session", "(Ljava/lang/String;)V", (void*)set_session},
	{"set_cookies", "(Ljava/lang/String;)V", (void*)set_cookies},
	{"set_secret", "(Ljava/lang/String;)V", (void*)set_secret},
	{"set_server", "([BI)V", (void*)set_server},
	{"set_power_save", "(Z)V", (void*)set_power_save},

	{"do_close", "(I)I", (void*)do_close},
	{"do_open_udp", "()I", (void*)do_open_udp},
	{"do_open", "()I", (void*)do_open},
#endif
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

