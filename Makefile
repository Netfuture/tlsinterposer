PROJECT = tlsinterposer

SHAREDLIB = tlsinterposer.so
CFILES = tlsinterposer.c
PREFIX = /usr/local
LIBDIR = $(PREFIX)/lib

TARGETS = $(SHAREDLIB)


all:	$(TARGETS)

install: $(SHAREDLIB)
	install -m 644 $(SHAREDLIB) $(LIBDIR)

$(SHAREDLIB): $(CFILES)
	$(CC) -g -Wall -fPIC -shared -o $(SHAREDLIB) $(CFILES) -ldl

clean:
	find . -name "*.so" | xargs --no-run-if-empty rm -v

distclean: clean

# vim: set noexpandtab tabstop=4 :
