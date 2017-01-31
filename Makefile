CFLAGS = -g

socksify: conntrack.o socksify.o

clean:
	-rm conntrack.o socksify.o socksify
