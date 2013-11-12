TLSinterposer
=============

OpenSSL library interposer to get software to use more secure TLS protocol variants.

Functionality
-------------
1. Disables SSLv2 and SSLv3 (broken), enables everything else (starting at OpenSSL 1.0.1 up to TLS 1.2)
2. Enables ECDHE algorithms
3. Disables all weak algorithms, including RC4

The cipher selection is according to Qualys SSLlabs recommendations and can be changed through the TLS_INTERPOSER_CIPERS environment variable.

Usage
-----
Start the process with LD_PRELOAD environment variable set to /path/to/libtlsinterposer.so . For example,

	env LD_PRELOAD=/usr/local/lib/libtlsinterposer.so apache2ctl start

enables Apache 2.2 to use the modern ciphers.
