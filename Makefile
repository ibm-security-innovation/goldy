MBEDTLS_INC_DIR ?= deps/mbedtls-2.1.2/include
MBEDTLS_LIB_DIR ?= deps/mbedtls-2.1.2/library
LIBEV_INC_DIR ?= deps/libev-4.20
LIBEV_LIB_DIR ?= deps/libev-4.20

CFLAGS ?= -g
WARNING_CFLAGS ?= -Wall -W -Wdeclaration-after-statement
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I$(MBEDTLS_INC_DIR) -I$(LIBEV_INC_DIR) -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -lm
MBEDTLS_LIBS = $(MBEDTLS_LIB_DIR)/libmbedtls.a $(MBEDTLS_LIB_DIR)/libmbedx509.a $(MBEDTLS_LIB_DIR)/libmbedcrypto.a
MBEDTLS_CONFIG_INC = $(MBEDTLS_INC_DIR)/mbedtls/config.h
LIBEV_LIBS = $(LIBEV_LIB_DIR)/.libs/libev.a

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

COMPILE=$(QUIET_CC) $(CC) $(LOCAL_CFLAGS) $(CFLAGS)
LINK=$(QUIET_LINK) $(CC) $(LOCAL_LDFLAGS) $(LDFLAGS)

ifndef V
QUIET_CC   = @echo "  CC    $@" 1>&2;
QUIET_LINK = @echo "  LINK  $@" 1>&2;
endif

INDENT_SETTINGS = -br -brf -brs -ce -cli2 -di1 -i2 -l100 -nbad -ncs -npcs -nprs \
		  -npsl -nut -T session_context -T global_context -T ev_io -T ev_timer
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	INDENT = gnuindent $(INDENT_SETTINGS)
else
	INDENT = indent $(INDENT_SETTINGS)
endif

APP = goldy
OBJS = goldy.o daemonize.o log.o

TEST_CLIENT = test/dtls_test_client
TEST_CLIENT_OBJS = test/dtls_test_client.o

TEST_SERVER = test/udp_test_server
TEST_SERVER_OBJS = test/udp_test_server.o

SRCS_C = $(OBJS:.o=.c) $(TEST_CLIENT_OBJS:.o=.c) $(TEST_SERVER_OBJS:.o=.c)
SRCS_H = $(OBJS:.o=.h)

.PHONY: all clean distclean deps test format

all: $(APP)

$(APP): $(OBJS) $(MBEDTLS_LIBS) $(LIBEV_LIBS)
	$(LINK) -o $@ $^

$(TEST_CLIENT): $(TEST_CLIENT_OBJS) $(MBEDTLS_LIBS)
	$(LINK) -o $@ $^

$(TEST_SERVER): $(TEST_SERVER_OBJS) $(LIBEV_LIBS)
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
	rm -f $(APP) $(OBJS) $(TEST_CLIENT) $(TEST_CLIENT_OBJS) $(TEST_SERVER) $(TEST_SERVER_OBJS)

distclean: clean
	$(MAKE) -C deps distclean

deps:
	$(MAKE) -C deps download_deps build_deps

test: $(TEST_CLIENT) $(TEST_SERVER) test/keys/test-proxy-key.pem test/keys/test-proxy-cert.pem
	test/run_test.sh

test/keys/test-proxy-key.pem:
	$(MBEDTLS_INC_DIR)/../programs/pkey/gen_key \
		type=ec ec_curve=secp256r1 format=pem filename=$@

test/keys/test-proxy-cert.pem: test/keys/test-proxy-key.pem
	$(MBEDTLS_INC_DIR)/../programs/x509/cert_write \
		issuer_name="CN=goldy.local, O=Dummy Ltd, C=US" \
		selfsign=1 issuer_key=$< output_file=$@

format:
	$(INDENT) $(SRCS_C) $(SRCS_H)
