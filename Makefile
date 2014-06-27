PROJECT = tlsinterposer

## The version is based on the last tag set on the current branch.
VERSION = $(shell sed -n -e 's/^\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p' CHANGES.txt | tail -1)
MAJOR = $(word 1, $(subst ., , $(VERSION)))

SHAREDLIB = lib$(PROJECT).so
SONAME    = $(SHAREDLIB).$(MAJOR)
CFILES = tlsinterposer.c
GENHDR = ssl-version.h
HFILES = $(GENHDR)
PREFIX = /usr/local
LIBDIR = $(PREFIX)/lib
INSTALL = install
DESTDIR =

TARGETS = $(SHAREDLIB)

# targets which are not filenames:
.PHONY:	all install clean distclean

all:	$(TARGETS) install

install: $(SHAREDLIB)
	mkdir -p $(DESTDIR)$(LIBDIR)
	$(INSTALL) -p -m755 $(SHAREDLIB) $(DESTDIR)$(LIBDIR)/$(SHAREDLIB).$(VERSION)
	ln -sf $(SHAREDLIB).$(VERSION) $(DESTDIR)$(LIBDIR)/$(SONAME)
	ln -sf $(SONAME) $(DESTDIR)$(LIBDIR)/$(SHAREDLIB)

ssl-version.h: CHANGES.txt
	ldconfig -p | sed -n -e 's/^\t*\(libssl\.so\.[0-9]\.[0-9]\.[0-9]\).*/#define DEFAULT_SSLLIB "\1"/p' > $@

$(SHAREDLIB): $(CFILES) $(HFILES)
	$(CC) -g -Wall -fPIC -shared -o $(SHAREDLIB) $(CFILES) -ldl

clean:
	find . \( -name "*.so" $(patsubst %.h,-o -name %.h,$(GENHDR)) \) -print0 | xargs -0 --no-run-if-empty rm -v

distclean: clean

# vim: set noexpandtab tabstop=4 :
