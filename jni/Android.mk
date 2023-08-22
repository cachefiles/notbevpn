LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := libpvpn_jni
LOCAL_SRC_FILES := pvpn_jni.c router.c firewall.c nameresolv.c ../dnsproto.c ../conntrack.c ../conntcpup.c ../tcpuputils.c ../conndgram.c ../portpool.c ../base_link.c ../udp_link.c ../icmp_link.c ../conversation.c ../natimpl.c ../udp6_link.c
LOCAL_CFLAGS += -I$(LOCAL_PATH)/.. -fPIC
LOCAL_LDFLAGS += -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := httplogd
LOCAL_SRC_FILES := httplogd.c
LOCAL_CFLAGS += -I$(LOCAL_PATH)/.. -fPIE
LOCAL_LDFLAGS += -fPIE -pie -llog
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
include $(call all-makefiles-under,$(LOCAL_PATH))
