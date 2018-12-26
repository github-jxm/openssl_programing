export PKG_CONFIG_PATH=/usr/local/openssl/lib/pkgconfig
#pkg-config --libs --cflags openssl
gcc  -o main  main.c `pkg-config --libs --cflags openssl` 

