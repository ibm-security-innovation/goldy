include versions.mk

ifdef DEBUG
LIBEV_CFLAGS=-g3
endif

all: download_deps build_deps

download_deps: download_mbedtls download_libev

.PHONY: download_deps

build_deps: build_mbedtls build_libev

.PHONY: build_deps

download_mbedtls:
	@echo "Downloading mbedtls-$(MBEDTLS_VER) ..."
	@curl --fail -O https://tls.mbed.org/download/mbedtls-$(MBEDTLS_VER)-apache.tgz || \
		(echo "Error downloading mbedtls: Check the MBEDTLS_VER in deps/versions.mk and current version in https://tls.mbed.org/download" ; exit 1)
	tar xzf mbedtls-$(MBEDTLS_VER)-apache.tgz
	rm -f mbedtls-$(MBEDTLS_VER)-apache.tgz

.PHONY: download_mbedtls

build_mbedtls:
	$(MAKE) -C mbedtls-$(MBEDTLS_VER) lib

download_libev:
	@echo "Downloading libev-$(LIBEV_VER) ..."
	@curl --fail -O http://dist.schmorp.de/libev/libev-$(LIBEV_VER).tar.gz || \
		(echo "Error downloading libev: Check the LIBEV_VER in deps/versions.mk and current version in http://dist.schmorp.de/libev/" ; exit 1)
	tar xzf libev-$(LIBEV_VER).tar.gz
	rm -f libev-$(LIBEV_VER).tar.gz

.PHONY: download_libev

build_libev:
	cd libev-$(LIBEV_VER) && CFLAGS=$(LIBEV_CFLAGS) ./configure && $(MAKE)

.PHONY: build_libev

distclean:
	rm -rf mbedtls-$(MBEDTLS_VER)
	rm -rf libev-$(LIBEV_VER)

.PHONY: distclean
