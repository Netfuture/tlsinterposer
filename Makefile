PROJECT = tlsinterposer

## The version is based on the last tag set on the current branch.
VERSION = $(shell sed -n -e 's/^\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p' CHANGES.txt | tail -1)
MAJOR = $(word 1, $(subst ., , $(VERSION)))

SHAREDLIB = lib$(PROJECT).so
SONAME    = $(SHAREDLIB).$(MAJOR)
CFILES = tlsinterposer.c
GENHDR = libssl-version.h
HFILES = $(GENHDR)
PREFIX = /usr/local
LIBDIR = $(PREFIX)/lib
INSTALL = install
DESTDIR =
CFLAGS  = -g -Wall -O2
LDCONFIG= /sbin/ldconfig
# Generated files from previous releases
LEGACY = ssl-version.h

TARGETS = $(SHAREDLIB)

# targets which are not filenames:
.PHONY:	all install clean distclean

all:	$(TARGETS) install

install: $(SHAREDLIB)
	mkdir -p $(DESTDIR)$(LIBDIR)
	$(INSTALL) -p -m755 $(SHAREDLIB) $(DESTDIR)$(LIBDIR)/$(SHAREDLIB).$(VERSION)
	ln -sf $(SHAREDLIB).$(VERSION) $(DESTDIR)$(LIBDIR)/$(SONAME)
	ln -sf $(SONAME) $(DESTDIR)$(LIBDIR)/$(SHAREDLIB)

libssl-version.h: /etc/ld.so.cache
	$(LDCONFIG) -p | sed -n -e 's/^\t*\(libssl\.so\.[0-9.]*\).*/#define DEFAULT_LIBSSL "\1"/p' > $@
	@if [ ! -s $@ ]; then rm $@; exit 1; fi

$(SHAREDLIB): $(CFILES) $(HFILES)
	$(CC) $(CFLAGS) -fPIC -shared -o $(SHAREDLIB) $(CFILES) -ldl

clean:
	find . \( -name "*.so" $(patsubst %.h,-o -name %.h,$(GENHDR) $(LEGACY)) \) -print0 | xargs -0 --no-run-if-empty rm -v

distclean: clean

# vim: set noexpandtab tabstop=4 :
