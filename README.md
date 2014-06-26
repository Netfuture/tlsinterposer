TLS Interposer
==============

OpenSSL library interposer to get software to use more secure TLS protocol variants.

Functionality
-------------
1. Disables SSLv2 and SSLv3 (broken), enables everything else (starting at OpenSSL 1.0.1 up to TLS 1.2)
2. Enables ECDHE algorithms for forward secrecy
3. Disables all weak algorithms; by default including RC4 as a last resort compatibility mode

Environment Variables
---------------------
* `LD_PRELOAD`: Used by ld.so, should be set to /full/path/to/tlsinterposer.so
* `TLS_INTERPOSER_CIPHERS`: The ciphers to use, defaults to Qualys SSLlabs recommendations including RC4 as a last resort
* `TLS_INTERPOSER_OPTIONS`: Comma-separated list of options
  - `debug`: Be verbose on stderr
  - `ssllib=`: Full name of libssl.so.X.Y.Z, if not autodetected correctly
  - `-comp`: Disable compression
  - `-ecdhe`: Disable forward secrecy (ephemeral keys)
  - `-tlsv1`: Disable TLSv1, leaving TLSv1.1 and TLSv1.2, if supported
  - `+sslv3`: Reenable SSLv3 (advised against)
  - `+sslv2`: Reenable SSLv2 (strongly advised against)

Installation
------------
Download, make, make install.

Usage
-----
Start the process with LD_PRELOAD environment variable set to /path/to/libtlsinterposer.so . For example,

	env LD_PRELOAD=/usr/local/lib/libtlsinterposer.so apache2ctl start

enables Apache 2.2 to use the modern ciphers.

More information and documentation is available at https://netfuture.ch/tools/tls-interposer/
