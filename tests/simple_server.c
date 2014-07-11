// based on serv.cpp example from the openssl distribution

/* serv.cpp    -    Minimal ssleay server for Unix
     30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
     Simplified to be even more minimal
     12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


/* Make these what you want for cert & key files */
#define CERTF   "test-cert.pem"
#define KEYF    "test-cert.pem"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int verify_callback(int i, X509_STORE_CTX *ctx)
{
    (void)(i), (void)(ctx); // get rid of "unused param" warnings
    return 1;
}

int main (int argc, char *argv[])
{
    int err;
    int bytes;
    int listen_sd;
    int sd;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    socklen_t client_len;
    SSL_CTX* ctx;
    SSL*         ssl;
    X509*        client_cert;
    char*        str;
    char         buf [4096];
    const SSL_METHOD *meth;
    unsigned int nport;

    /* parse options */
    if (argc != 2) {
        fprintf(stderr, "usage: %s port_number\n", argv[0]);
        exit(255);
    }
    nport = strtoul(argv[1], &str, 0);
    if (*str != '\0' || nport >= 0xffff) {
        fprintf(stderr, "error parsing port number: %s\n", argv[1]);
        exit(255);
    }

    /* chdir to our directory, to load cert files properly if run from another dir */
    strncpy(buf, argv[0], sizeof(buf)); // copy since dirname may modify
    str = dirname(buf);
    err = chdir(str);
    CHK_ERR(err, "chdir");

    /* SSL preliminaries. We keep the certificate and key with the context. */

    SSL_load_error_strings();
    SSL_library_init();
    meth = SSLv23_server_method();
    ctx = SSL_CTX_new (meth);
    // an explicit setting to test for
    SSL_CTX_set_cipher_list(ctx, "AES128-SHA");
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr,"Private key does not match the certificate public key\n");
        exit(5);
    }

    /* ----------------------------------------------- */
    /* Prepare TCP socket for receiving connections */

    listen_sd = socket (AF_INET, SOCK_STREAM, 0);     CHK_ERR(listen_sd, "socket");
    err = 1;
    err = setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &err, sizeof(err));    CHK_ERR(err, "setsockopt");

    memset (&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family            = AF_INET;
    sa_serv.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    sa_serv.sin_port                = htons (nport);                    /* Server Port number */

    err = bind(listen_sd, (struct sockaddr*) &sa_serv,
             sizeof (sa_serv));                                     CHK_ERR(err, "bind");

    /* Receive a TCP connection. */

    err = listen (listen_sd, 5);                                        CHK_ERR(err, "listen");

    client_len = sizeof(sa_cli);
    sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
    CHK_ERR(sd, "accept");
    close (listen_sd);

    printf ("Connection from %lx, port %x\n",
        (long unsigned int)sa_cli.sin_addr.s_addr, sa_cli.sin_port);

    /* ----------------------------------------------- */
    /* TCP connection is ready. Do server side SSL. */

    ssl = SSL_new (ctx);                                                     CHK_NULL(ssl);
    SSL_set_fd (ssl, sd);
    SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_callback); /* ask for a cert */
    err = SSL_accept (ssl);                                                CHK_SSL(err);

    /* Get the cipher - opt */

    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

    /* Get client's certificate (note: beware of dynamic allocation) - opt */

    client_cert = SSL_get_peer_certificate (ssl);
    if (client_cert != NULL) {
        printf ("Client certificate:\n");

        str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
        CHK_NULL(str);
        printf ("\t subject: %s\n", str);
        err = SSL_write (ssl, "client cert: ", strlen("client cert: "));    CHK_SSL(err);
        err = SSL_write (ssl, str, strlen(str));    CHK_SSL(err);
        err = SSL_write (ssl, "\n", 1);        CHK_SSL(err);
        OPENSSL_free (str);

        str = X509_NAME_oneline (X509_get_issuer_name    (client_cert), 0, 0);
        CHK_NULL(str);
        printf ("\t issuer: %s\n", str);
        OPENSSL_free (str);

        /* We could do all sorts of certificate verification stuff here before
             deallocating the certificate. */

        X509_free (client_cert);
    } else
        printf ("Client does not have certificate.\n");

    /* DATA EXCHANGE - Receive message and send reply. */

    bytes = SSL_read (ssl, buf, sizeof(buf) - 1);                                     CHK_SSL(err);
    buf[bytes] = '\0';
    printf ("Got %d chars:'%s'\n", bytes, buf);

    err = SSL_write (ssl, "echo: ", strlen("echo: "));    CHK_SSL(err);
    err = SSL_write (ssl, buf, bytes);    CHK_SSL(err);

    /* Clean up. */

    close (sd);
    SSL_free (ssl);
    SSL_CTX_free (ctx);

    return 0;
}
/* EOF - serv.cpp */
