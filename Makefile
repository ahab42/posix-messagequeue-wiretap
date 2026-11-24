CC     := zig cc
CFLAGS := -O2 -Wall -Wextra -pthread

all: libhook.so listener

libhook.so: hook.c mqwt_proto.h
	$(CC) -target arm-linux-gnueabihf.2.31 -shared -fPIC \
	      -fno-builtin -fno-stack-protector $(CFLAGS) $< -o $@

listener: listener.c
LDLIBS := -lsqlite3

clean:
	rm -f libhook.so listener

.PHONY: all clean
