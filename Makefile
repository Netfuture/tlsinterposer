LIB	= libtlsinterposer.so
CFILES	= tlsinterposer.c

all:	${LIB}

libtlsinterposer.so: ${CFILES}
	gcc -g -Wall -fPIC -shared -o ${LIB} ${CFILES} -ldl
