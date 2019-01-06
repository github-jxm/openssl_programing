all:main 

CFLAGS += `pkg-config --cflags openssl`
LDFLAGS += `pkg-config --libs openssl`
CC=gcc

#PKG_CONFIG_PATH='/usr/local/openssl/lib/pkgconfig'
#pkg-config --libs --cflags openssl
#gcc  -o main  main.c `pkg-config --libs --cflags openssl` 

#objects := $(wildcard *.c)
objects := main.c sm2_crypt.c

main: ${objects}
	${CC} ${CFLAGS} -o main ${objects} ${LDFLAGS}

sm2_api: sm2_api.c sm2_crypt.c
	${CC} ${CFLAGS} -o sm2_api sm2_api.c sm2_crypt.c ${LDFLAGS}

generate_key:generate_key.c
	${CC}  -D TEST_MAIN ${CFLAGS} -o generate_key_test generate_key.c  ${LDFLAGS}

clean:
	-rm main

