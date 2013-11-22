LIB	= tlsinterposer.so
CFILES	= tlsinterposer.c
PREFIX = /usr/local
LIBDIR = ${PREFIX}/lib

all:	${LIB}

install:${LIB}
	install -m 644 ${LIB} ${LIBDIR}

${LIB}: ${CFILES}
	gcc -g -Wall -fPIC -shared -o ${LIB} ${CFILES} -ldl

# vim: set noexpandtab tabstop=4 :
