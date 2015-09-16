MBEDTLS_INC_DIR ?= deps/mbedtls-2.1.0/include
MBEDTLS_LIB_DIR ?= deps/mbedtls-2.1.0/library

CFLAGS ?= -O2
WARNING_CFLAGS ?= -Wall -W -Wdeclaration-after-statement
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I$(MBEDTLS_INC_DIR) -D_FILE_OFFSET_BITS=64
MBEDTLS_LIBS = $(MBEDTLS_LIB_DIR)/libmbedtls.a $(MBEDTLS_LIB_DIR)/libmbedx509.a $(MBEDTLS_LIB_DIR)/libmbedcrypto.a
MBEDTLS_CONFIG_INC = $(MBEDTLS_INC_DIR)/mbedtls/config.h

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

COMPILE=$(QUIET_CC) $(CC) $(LOCAL_CFLAGS) $(CFLAGS)
LINK=$(QUIET_LINK) $(CC) $(LDFLAGS)

ifndef V
QUIET_CC   = @echo "  CC    $@" 1>&2;
QUIET_LINK = @echo "  LINK  $@" 1>&2;
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

APP = goldy
OBJS = goldy.o daemonize.o log.o

TEST_APP = test/dtls_test_client
TEST_OBJS = test/dtls_test_client.o

.PHONY: all clean distclean deps test

all: $(APP)

$(APP): $(OBJS) $(MBEDTLS_LIBS)
	$(LINK) -o $@ $^

$(TEST_APP): $(TEST_OBJS) $(MBEDTLS_LIBS)
	$(LINK) -o $@ $^

%.o: %.c $(MBEDTLS_CONFIG_INC)
	$(COMPILE) -o $@ -c $<

$(MBEDTLS_CONFIG_INC):
	@echo ""
	@echo "mbed TLS include files not found in $(MBEDTLS_INC_DIR); run:"
	@echo ""
	@echo "    make deps"
	@echo ""
	@echo "to download and build mbed TLS."
	@echo ""
	@false

clean:
	rm -f $(APP) $(OBJS) $(TEST_APP) $(TEST_OBJS)

distclean: clean
	$(MAKE) -C deps distclean

deps:
	$(MAKE) -C deps download_deps build_deps

test: $(TEST_APP) test/keys/test-proxy-key.pem test/keys/test-proxy-cert.pem
	test/run_test.sh

test/keys/test-proxy-key.pem:
	$(MBEDTLS_INC_DIR)/../programs/pkey/gen_key \
		type=ec ec_curve=secp256r1 format=pem filename=$@

test/keys/test-proxy-cert.pem: test/keys/test-proxy-key.pem
	$(MBEDTLS_INC_DIR)/../programs/x509/cert_write \
		issuer_name="CN=goldy.local, O=Dummy Ltd, C=US" \
		selfsign=1 issuer_key=$< output_file=$@
