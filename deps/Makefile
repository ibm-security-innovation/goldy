download_deps: download_mbedtls

.PHONY: download_deps

build_deps: build_mbedtls

.PHONY: build_deps

download_mbedtls:
	curl -O https://tls.mbed.org/download/mbedtls-2.0.0-gpl.tgz
	tar xzf mbedtls-2.0.0-gpl.tgz
	rm -f mbedtls-2.0.0-gpl.tgz

.PHONY: download_mbedtls

build_mbedtls:
	$(MAKE) -C mbedtls-2.0.0 no_test

.PHONY: build_mbedtls

distclean:
	rm -rf mbedtls-2.0.0

.PHONY: distclean
