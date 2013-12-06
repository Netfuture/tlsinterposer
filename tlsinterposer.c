/*
    TLS Interposer: An OpenSSL library interposer to get
	software to use more secure TLS protocol variants.

    Copyright (C) 2013 Marcel Waldvogel

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
    USA
*/
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <dlfcn.h>

#ifdef DEBUG
#define DEBUGLOG(x)     fprintf(stderr, (x))
#define DEBUGLOG2(x, y) fprintf(stderr, (x), (y))
#else
#define DEBUGLOG(x)
#define DEBUGLOG2(x, y)
#endif

static void *ssl_dlsym(const char *name)
{
	void *addr = dlsym(RTLD_NEXT, name);
	if (addr == NULL) {
		// Try again with a more specific name
		// Needed for ejabberd
		void *file = dlopen("libssl.so.1.0.0", RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
		if (file != NULL) {
			addr = dlsym(file, name);
			dlclose(file);
		}
	}
	return addr;
}

static int interposer_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
	int (*orig_SSL_CTX_set_cipher_list)(SSL_CTX *, const char *);
	DEBUGLOG("libtlsinterposer.so:interposer_SSL_CTX_set_cipher_list() starting\n");
	orig_SSL_CTX_set_cipher_list = ssl_dlsym("SSL_CTX_set_cipher_list");
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
		ciphers = "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS +RC4 RC4";
	}
	DEBUGLOG2("libtlsinterposer.so:default_SSL_CTX_set_cipher_list() using %s\n", ciphers);
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
	orig_SSL_CTX_new = ssl_dlsym("SSL_CTX_new");
	if (orig_SSL_CTX_new == NULL) {
		fprintf(stderr, "libtlsinterposer.so:SSL_CTX_new() is NULL\n");
		return NULL;
	}
	ctx = (*orig_SSL_CTX_new)(method);
	if (ctx != NULL) {
		long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE;
		if (getenv("TLS_INTERPOSER_NO_COMPRESSION") != NULL) options |= SSL_OP_NO_COMPRESSION;
		SSL_CTX_set_options(ctx, options);
		default_SSL_CTX_set_cipher_list(ctx);
		// Based on code by Vincent Bernat
		// - http://vincent.bernat.im/en/blog/2011-ssl-perfect-forward-secrecy.html
		// - https://github.com/bumptech/stud/pull/61
#ifdef NID_X9_62_prime256v1
		EC_KEY *ecdh;
		ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		SSL_CTX_set_tmp_ecdh(ctx, ecdh);
		EC_KEY_free(ecdh);
		DEBUGLOG("libtlsinterposer.so:ECDH Initialized with NIST P-256\n");
#endif
	}
	DEBUGLOG2("libtlsinterposer.so:SSL_CTX_new returning %p\n", ctx);
	return ctx;
}

// Based on Apache's bug #49559 by Kaspar Brand
// - https://issues.apache.org/bugzilla/show_bug.cgi?id=49559#c13
/*
 * Grab well-defined DH parameters from OpenSSL, see <openssl/bn.h>
 * (get_rfc*) for all available primes.
 */
#define make_get_dh(rfc,size,gen) \
static DH *get_dh##size(void) \
{ \
    DH *dh; \
    if (!(dh = DH_new())) { \
        return NULL; \
    } \
    dh->p = get_##rfc##_prime_##size(NULL); \
    BN_dec2bn(&dh->g, #gen); \
    if (!dh->p || !dh->g) { \
        DH_free(dh); \
        return NULL; \
    } \
    return dh; \
}

/*
 * Prepare DH parameters from 1024 to 4096 bits, in 1024-bit increments
 */
make_get_dh(rfc2409, 1024, 2)
make_get_dh(rfc3526, 2048, 2)
make_get_dh(rfc3526, 3072, 2)
make_get_dh(rfc3526, 4096, 2)

static DH *ssl_callback_TmpDH(SSL *ssl, int export, int keylen)
{
	EVP_PKEY *pkey = SSL_get_privatekey(ssl);
	int type = pkey ? EVP_PKEY_type(pkey->type) : EVP_PKEY_NONE;
	if ((type == EVP_PKEY_RSA) || (type == EVP_PKEY_DSA)) {
		keylen = EVP_PKEY_bits(pkey);
	}
	if (keylen >= 4096)
		return get_dh4096();
	else if (keylen >= 3072)
		return get_dh3072();
	else if (keylen >= 2048)
		return get_dh2048();
	else
		return get_dh1024();
}

void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx, DH *(*tmp_dh_callback)(SSL*ssl, int is_export, int keylength))
{
	void (*orig_SSL_CTX_set_tmp_dh_callback)(SSL_CTX *ctx, DH *(*tmp_dh_callback)(SSL*ssl, int is_export, int keylength));
	orig_SSL_CTX_set_tmp_dh_callback = ssl_dlsym("SSL_CTX_set_tmp_dh_callback");
	if (orig_SSL_CTX_set_tmp_dh_callback == NULL) {
		DEBUGLOG("libtlsinterposer.so:SSL_CTX_set_tmp_dh_callback() is NULL\n");
		return;
	}
	(*orig_SSL_CTX_set_tmp_dh_callback)(ctx, ssl_callback_TmpDH);
}

void SSL_set_tmp_dh_callback(SSL *ssl, DH *(*tmp_dh_callback)(SSL*ssl, int is_export, int keylength))
{
	void (*orig_SSL_set_tmp_dh_callback)(SSL *ssl, DH *(*tmp_dh_callback)(SSL*ssl, int is_export, int keylength));
	orig_SSL_set_tmp_dh_callback = ssl_dlsym("SSL_set_tmp_dh_callback");
	if (orig_SSL_set_tmp_dh_callback == NULL) {
		DEBUGLOG("libtlsinterposer.so:SSL_set_tmp_dh_callback() is NULL\n");
		return;
	}
	(*orig_SSL_set_tmp_dh_callback)(ssl, ssl_callback_TmpDH);
}
