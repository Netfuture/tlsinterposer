#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <dlfcn.h>

#ifdef DEBUG
#define LOG(x)     fprintf(stderr, (x))
#define LOG2(x, y) fprintf(stderr, (x), (y))
#else
#define LOG(x)
#define LOG2(x, y)
#endif

static int interposer_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
	int (*orig_SSL_CTX_set_cipher_list)(SSL_CTX *, const char *);
	LOG("libtlsinterposer.so:interposer_SSL_CTX_set_cipher_list() starting\n");
	orig_SSL_CTX_set_cipher_list = dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
	if (orig_SSL_CTX_set_cipher_list == NULL) {
		fprintf(stderr, "libtlsinterposer.so:interposer_SSL_CTX_set_cipher_list() cannot find SSL_CTX_set_cipher_list()\n");
		return 0;
	}
	return (*orig_SSL_CTX_set_cipher_list)(ctx, str);
}

static int default_SSL_CTX_set_cipher_list(SSL_CTX *ctx)
{
	const char *ciphers = getenv("TLS_INTERPOSER_CIPHERS");
	if (ciphers == NULL) {
		// Qualys recommendation (I know the RC4 part could be simplified)
		// - https://community.qualys.com/blogs/securitylabs/2013/08/05/configuring-apache-nginx-and-openssl-for-forward-secrecy
		ciphers = "EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:EECDH+aRSA+RC4:EECDH:EDH+aRSA:RC4:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4";
	}
	LOG2("libtlsinterposer.so:default_SSL_CTX_set_cipher_list() using %s\n", ciphers);
	return interposer_SSL_CTX_set_cipher_list(ctx, ciphers);
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
	return default_SSL_CTX_set_cipher_list(ctx);
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
{
	SSL_CTX *(*orig_SSL_CTX_new)(const SSL_METHOD*);
	SSL_CTX *ctx;
	orig_SSL_CTX_new = dlsym(RTLD_NEXT, "SSL_CTX_new");
	if (orig_SSL_CTX_new == NULL) {
		fprintf(stderr, "libtlsinterposer.so:SSL_CTX_new() is NULL\n");
		return NULL;
	}
	ctx = (*orig_SSL_CTX_new)(method);
	if (ctx != NULL) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
		default_SSL_CTX_set_cipher_list(ctx);
		// Taken from Vincent Bernat
		// - http://vincent.bernat.im/en/blog/2011-ssl-perfect-forward-secrecy.html
		// - https://github.com/bumptech/stud/pull/61
#ifdef NID_X9_62_prime256v1
		EC_KEY *ecdh = NULL;
		ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		SSL_CTX_set_tmp_ecdh(ctx,ecdh);
		EC_KEY_free(ecdh);
		LOG("libtlsinterposer.so:ECDH Initialized with NIST P-256\n");
#endif
	}
	LOG2("libtlsinterposer.so:SSL_CTX_new returning %p\n", ctx);
	return ctx;
}
