THIS_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CFLAGS += -g
CFLAGS += -I$(THIS_PATH) -I$(THIS_PATH)/jni
VPATH  := $(THIS_PATH)

BIN_FMT_TARGET := $(shell $(THIS_PATH)/getos.sh CC=$(CC))

toyclient: main.o conntrack.o conntcpup.o socksify.o tcpuputils.o conndgram.o portpool.o udp_link.o icmp_link.o base_link.o jni/firewall.o jni/router.o tx_debug.o conversation.o tcp_link.o
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

socksify.o: socksify_$(BIN_FMT_TARGET).c
	$(CC) -o $@ -c $(CFLAGS) $^

clean:
	-rm conntrack.o socksify.o socksify
