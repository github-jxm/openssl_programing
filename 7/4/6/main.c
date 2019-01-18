#include <openssl/bio.h>
#include <openssl/ssl.h>

int     main()
{
	BIO*sbio, *out;
	int len;
	char tmpbuf[1024];
	SSL_CTX *ctx;
	SSL *ssl;

	SSLeay_add_ssl_algorithms();
	OpenSSL_add_all_algorithms();
	//ctx = SSL_CTX_new(SSLv3_client_method());
	ctx = SSL_CTX_new(SSLv23_client_method());
	sbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(sbio, &ssl);
	if(!ssl) {
		fprintf(stderr, "Can not locate SSL pointer\n");
		return 0;
	}
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	//BIO_set_conn_hostname(sbio, "mybank.icbc.com.cn:https");
	BIO_set_conn_hostname(sbio, "www.baidu.com:https");
	out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_printf(out,"链接中...\n");
	if(BIO_do_connect(sbio) <= 0) {
		fprintf(stderr, "Error connecting to server\n");
		return 0;
	}
	if(BIO_do_handshake(sbio) <= 0){
		fprintf(stderr, "Error establishing SSL connection\n");
		return 0;
	}
	BIO_puts(sbio, "GET / HTTP/1.0\n\n");
	for(;;)
	{
		len = BIO_read(sbio, tmpbuf, 1024);
		if(len <= 0) break;
		BIO_write(out, tmpbuf, len);
	}
	BIO_free_all(sbio);
	BIO_free(out);
	return 0;
}
 
/*
 * 本函数用ssl bio来链接mybank.icbc.com.cn的https服务,并请求首页文件。
 * 其中SSLeay_add_ssl_algorithms和OpenSSL_add_all_algorithms函数必不可少，
 * 否则不能找到ssl加密套件并且不能找到各种算法。
 */
