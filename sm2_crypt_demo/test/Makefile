all:main 

CFLAGS += `pkg-config --cflags openssl`
LDFLAGS += `pkg-config --libs openssl`
CC=gcc

#PKG_CONFIG_PATH='/usr/local/openssl/lib/pkgconfig'
#pkg-config --libs --cflags openssl
#gcc  -o main  main.c `pkg-config --libs --cflags openssl` 

objects := $(wildcard *.c)

main: ${objects}
	${CC} ${CFLAGS} -o main ${objects} ${LDFLAGS}

clean:
	-rm main

