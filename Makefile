THIS_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CFLAGS += -g -Wall -D_GNU_SOURCE
CFLAGS += -I$(THIS_PATH) -I$(THIS_PATH)/jni
VPATH  := $(THIS_PATH)

ifneq ($(TARGET),)
CC := $(TARGET)-gcc
LD := $(TARGET)-ld
AR := $(TARGET)-ar
CXX := $(TARGET)-g++
RANLIB := $(TARGET)-ranlib
endif

BIN_FMT_TARGET := $(shell $(THIS_PATH)/getos.sh CC=$(CC))
ifneq ($(BIN_FMT_TARGET),freebsd)
LDLIBS = -lresolv
endif

toyclient: dnsproto.o jni/nameresolv.o jni/firewall.o

toyclient: conntrack.o conntcpup.o socksify.o tcpuputils.o conndgram.o portpool.o udp_link.o icmp_link.o base_link.o jni/router.o tx_debug.o conversation.o main.o win32stub.o
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

socksify.o: socksify_$(BIN_FMT_TARGET).c
	$(CC) -o $@ -c $(CFLAGS) $^

clean:
	-rm conntrack.o socksify.o socksify
