all:main test 

CFLAGS += `pkg-config --cflags openssl`
LDFLAGS += `pkg-config --libs openssl`
CC=gcc

#PKG_CONFIG_PATH='/usr/local/openssl/lib/pkgconfig'
#pkg-config --libs --cflags openssl
#gcc  -o main  main.c `pkg-config --libs --cflags openssl` 
main:main.c
	${CC} ${CFLAGS} -o main main.c ${LDFLAGS}
	
main2:main2.c
	${CC} ${CFLAGS} -o main2 main2.c ${LDFLAGS}

test:test.c
	${CC} ${CFLAGS} -o test test.c ${LDFLAGS}

clean:
	-rm main

