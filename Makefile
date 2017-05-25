THIS_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CFLAGS += -g
CFLAGS += -I$(THIS_PATH)
VPATH  := $(THIS_PATH)

BIN_FMT_TARGET := $(shell $(THIS_PATH)/getos.sh CC=$(CC))

toyclient: conntcpup.o socksify.o tcpuputils.o
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

socksify: conntrack.o socksify.o
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

socksify.o: socksify_$(BIN_FMT_TARGET).c
	$(CC) -o $@ -c $(CFLAGS) $^

clean:
	-rm conntrack.o socksify.o socksify
