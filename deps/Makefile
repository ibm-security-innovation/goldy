download_deps: download_mbedtls

.PHONY: download_deps

build_deps: build_mbedtls

.PHONY: build_deps

download_mbedtls:
	curl -O https://tls.mbed.org/download/mbedtls-2.1.0-apache.tgz
	tar xzf mbedtls-2.1.0-apache.tgz
	rm -f mbedtls-2.1.0-apache.tgz

.PHONY: download_mbedtls

build_mbedtls:
	$(MAKE) -C mbedtls-2.1.0 lib

.PHONY: build_mbedtls

distclean:
	rm -rf mbedtls-2.1.0

.PHONY: distclean
