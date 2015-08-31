# goldy

**goldy** is lightweight [DTLS](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)
proxy which allows adding DTLS encryption to UDP servers without modifying their code.

goldy uses [mbed TLS](https://tls.mbed.org) to implement DTLS.

## Build

To build goldy from source:

    git clone .../goldy.git
    cd goldy
    make deps
    make

## Tests

To compile the test client run the test suite:

    make test

## License

Copyright TODO

See the LICENSE file.
