
export PKG_CONFIG_PATH='/usr/local/openssl/lib/pkgconfig'
export LD_LIBRARY_PATH='/usr/local/openssl/lib'

#gcc  `pkg-config  --cflags openssl` -I ../../openssl-1.1.1/crypto/include -I ../../openssl-1.1.1/include  \
#	-o main main.c ../crypto/sm2/sm2_crypt.c  `pkg-config  --libs openssl`  \
#	-L ../

#openssl version
#gcc  `pkg-config  --cflags openssl`  \
#	-o main main.c sm2_crypt.c   `pkg-config  --libs openssl`  
