THIS_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CFLAGS += -g -Wall
CFLAGS += -I$(THIS_PATH) -I$(THIS_PATH)/jni
VPATH  := $(THIS_PATH)
LDLIBS := -lws2_32

ifneq ($(TARGET),)
CC := $(TARGET)-gcc
LD := $(TARGET)-ld
AR := $(TARGET)-ar
CXX := $(TARGET)-g++
RANLIB := $(TARGET)-ranlib
endif

BIN_FMT_TARGET := $(shell $(THIS_PATH)/getos.sh CC=$(CC))

toyclient: conntrack.o conntcpup.o socksify.o tcpuputils.o conndgram.o portpool.o udp_link.o icmp_link.o base_link.o jni/firewall.o jni/router.o tx_debug.o conversation.o tcp_link.o main.o
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

socksify.o: socksify_$(BIN_FMT_TARGET).c
	$(CC) -o $@ -c $(CFLAGS) $^

clean:
	-rm conntrack.o socksify.o socksify
