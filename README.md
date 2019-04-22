# Goldy

**goldy** is lightweight [DTLS](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)
proxy which allows adding DTLS encryption (using [mbed TLS](https://tls.mbed.org) ) to UDP servers without modifying
their code.

[Goldy's homepage at IBM developerWorks](https://developer.ibm.com/open/goldy/).

[![Build Status](https://travis-ci.org/ibm-security-innovation/goldy.svg?branch=master)](https://travis-ci.org/ibm-security-innovation/goldy)
## Build

To build goldy from source:

    git clone .../goldy.git
    cd goldy
    make deps
    make

Use `make V=1` for a verbose build output and `make DEBUG=1` to enable debug
info (`-g3`).

## Help

    Usage: goldy [-hvd] [-g log_level] [-t seconds] -l listen_host:port
                 -b backend_host:port -c cert_pem_file -k private_key_pem_file

    Options:
      -h, --help                 this help
      -v, --version              show version and exit
      -d, --daemonize            run as a daemon
      -g, --log=LEVEL            log level DEBUG/INFO/ERROR
      -t, --timeout=SECONDS      Session timeout (seconds)
      -l, --listen=ADDR:PORT     listen for incoming DTLS on addr and UDP port
      -b, --backend=ADDR:PORT    proxy UDP traffic to addr and port
      -c, --cert=FILE            TLS certificate PEM filename
      -k, --key=FILE             TLS private key PEM filename

## Tests

The following command compiles the test client and server and then runs the
full-cycle test suite:

    make test

## Docker use

To build the Docker image:

	docker build . -t goldy:latest

The Docker image has an entrypoint script which makes easy to pass the certificate and key, without requiring the use of a volume. To do so, run:

    docker run -e LISTEN=:::5683 \
               -e BACKEND=<backend host:port> \
               -e KEY=<base64> \
               -e CERT=<base64> \
               -p 5683:5683 \
               <extra goldy arguments>

## License

Goldy is distributed under the [Apache License, version 2.0](LICENSE) .

(c) Copyright IBM Corp. 2015, 2016

Authors: Dov Murik, Shmulik Regev

Contributions are gladly welcome. Please see the requirement for [Developer Certificate of Origin](CONTRIBUTING.md) .

## Dependencies & 3rd Party

[mbedTLS](https://tls.mbed.org/) is used as the underlying DTLS implementation.

[libev](http://software.schmorp.de/pkg/libev.html) is used as an event library. It's BSD 2 clause license is used.

# Contribution

Contributions to the project are welcomed. It is required however to provide alongside the pull request one of the contribution forms (CLA) that are a part of the project. If the contributor is operating in his individual or personal capacity, then he/she is to use the [individual CLA](./CLA-Individual.txt); if operating in his/her role at a company or entity, then he/she must use the [corporate CLA](CLA-Corporate.txt).
