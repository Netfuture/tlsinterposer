LIB	= tlsinterposer.so
CFILES	= tlsinterposer.c

all:	${LIB}

${LIB}: ${CFILES}
	gcc -g -Wall -fPIC -shared -o ${LIB} ${CFILES} -ldl
