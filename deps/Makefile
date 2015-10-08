download_deps: download_mbedtls download_libev

.PHONY: download_deps

build_deps: build_mbedtls build_libev

.PHONY: build_deps

MBEDTLS_VER=2.1.0
download_mbedtls:
	curl -O https://tls.mbed.org/download/mbedtls-$(MBEDTLS_VER)-apache.tgz
	tar xzf mbedtls-$(MBEDTLS_VER)-apache.tgz
	rm -f mbedtls-$(MBEDTLS_VER)-apache.tgz

.PHONY: download_mbedtls

build_mbedtls:
	$(MAKE) -C mbedtls-$(MBEDTLS_VER) lib

LIBEV_VER=4.20
download_libev:
	curl -O http://dist.schmorp.de/libev/libev-$(LIBEV_VER).tar.gz
	tar xzf libev-$(LIBEV_VER).tar.gz
	rm -f libev-$(LIBEV_VER).tar.gz

.PHONY: download_libev

build_libev:
	cd libev-$(LIBEV_VER); ./configure; $(MAKE)

.PHONY: build_libev

distclean:
	rm -rf mbedtls-$(MBEDTLS_VER)
	rm -rf libev-$(LIBEV_VER)

.PHONY: distclean
