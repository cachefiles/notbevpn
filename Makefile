CFLAGS += -g
CFLAGS += -I$(shell pwd)

BIN_FMT_TARGET := $(shell ./getos.sh CC=$(CC))

socksify: conntrack.o socksify.o
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

socksify.o: socksify_$(BIN_FMT_TARGET).c
	$(CC) -o $@ -c $(CFLAGS) $^

clean:
	-rm conntrack.o socksify.o socksify
