# goldy

**goldy** is lightweight [DTLS](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)
proxy which allows adding DTLS encryption to UDP servers without modifying
their code.

goldy uses [mbed TLS](https://tls.mbed.org) to implement DTLS.

## Build

To build goldy from source:

    git clone .../goldy.git
    cd goldy
    make deps
    make

Use `make V=1` for a verbose build output and `make DEBUG=1` to enable debug
info (`-g3`).

## Help

    Usage: goldy [-hv] -l listen_host:port -b backend_host:port
                 -c cert_pem_file -k private_key_pem_file

    Options:
      -h, --help                 this help
      -v, --version              show version and exit
      -l, --listen=ADDR:PORT     listen for incoming DTLS on addr and port
      -b, --backend=ADDR:PORT    proxy UDP traffic to addr and port
      -c, --cert=FILE            TLS certificate PEM filename
      -k, --key=FILE             TLS private key PEM filename

## Tests

To compile the test client run the test suite:

    make test

## License

Copyright TODO

See the LICENSE file.
