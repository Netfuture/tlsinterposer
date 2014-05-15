PROJECT = tlsinterposer

## The version is based on the last tag set on the current branch.
VERSION = $(shell git describe --tags | cut -f1 -d '-' | sed 's/^v//' )
MAJOR = $(word 1, $(subst ., , $(VERSION)))

SHAREDLIB = lib$(PROJECT).so
SONAME    = $(SHAREDLIB).$(MAJOR)
CFILES = tlsinterposer.c
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
	ln -s $(SHAREDLIB).$(VERSION) $(DESTDIR)$(LIBDIR)/$(SONAME)
	ln -s $(SONAME) $(DESTDIR)$(LIBDIR)/$(SHAREDLIB)


$(SHAREDLIB): $(CFILES)
	$(CC) -g -Wall -fPIC -shared -o $(SHAREDLIB) $(CFILES) -ldl

clean:
	find . -name "*.so" | xargs --no-run-if-empty rm -v

distclean: clean

# vim: set noexpandtab tabstop=4 :
