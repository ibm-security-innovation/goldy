/*
 * dtls_test_client.c -
 */

#if defined(__linux__)
#define _XOPEN_SOURCE 700
#endif

#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"

#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define SSL_HANDSHAKE_TIMEOUT_MILLISECS 4000

#define DEBUG_LEVEL 0

static void plog(const char *format, ...) {
  va_list arglist;
  char line[1024];
  struct timeval tv;
  size_t len;

  gettimeofday(&tv, NULL);
  len = strftime(line, sizeof(line), "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
#if defined(__APPLE__) && defined(__MACH__)
  len += snprintf(line + len, sizeof(line) - len, ".%06d ", tv.tv_usec);
#else
  len += snprintf(line + len, sizeof(line) - len, ".%06lu ", tv.tv_usec);
#endif

  va_start(arglist, format);
  snprintf(line + len, sizeof(line), "dtls_test_client(PID=%d): %s\n", getpid(), format);
  vprintf(line, arglist);
  va_end(arglist);
  fflush(stdout);
}

static void log_mbedtls_debug_callback(void *ctx, int level, const char *file, int line,
                                       const char *str) {
  (void)ctx;
  plog("mbedtls_debug [%d] %s:%04d: %s", level, file, line, str);
}

static void print_usage(const char *argv0) {
  printf("Usage: %s -h host -p port [-n ssl_hostname] -s scenario\n", argv0);
  exit(1);
}

static long timeval_to_ms(struct timeval *tv) {
  return (long)tv->tv_sec * 1000 + (long)tv->tv_usec / 1000;
}

static long duration_ms(struct timeval *tv_end, struct timeval *tv_start) {
  return timeval_to_ms(tv_end) - timeval_to_ms(tv_start);
}

/* Return 1 if a equals to reverse(b) */
static int is_reverse(const char *a, const char *b) {
  size_t len = strlen(a);
  size_t i = 0;

  if (strlen(b) != len) {
    return 0;
  }

  for (i = 0; i < len; i++) {
    if (a[i] != b[len - 1 - i]) {
      return 0;
    }
  }
  return 1;
}

static int send_one_packet(const char *packet_body, mbedtls_ssl_context *ssl) {
  int ret, len;
  unsigned char buf[10000];

  plog("sending packet: '%s'", packet_body);

  len = strlen(packet_body);

  do {
    ret = mbedtls_ssl_write(ssl, (unsigned char *)packet_body, len);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret < 0) {
    plog("ERROR: mbedtls_ssl_write returned %d", ret);
    return ret;
  }

  len = ret;
  plog("%d bytes written: '%s'", len, packet_body);

  if (strncmp("noreply", packet_body, 7) == 0) {
    /* Outgoing packet begins with "noreply", so don't attempt to read a
     * response from the server. Just return successfully. */
    return 0;
  }

  plog("Read from server...");

  len = sizeof(buf) - 1;
  memset(buf, 0, sizeof(buf));

  do {
    ret = mbedtls_ssl_read(ssl, buf, len);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret <= 0) {
    switch (ret) {
      case MBEDTLS_ERR_SSL_TIMEOUT:
        plog("ERROR: timeout");
        return ret;

      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        plog("ERROR: connection was closed gracefully");
        return ret;

      default:
        plog("ERROR: mbedtls_ssl_read returned -0x%x", -ret);
        return ret;
    }
  }

  len = ret;
  plog("%d bytes read: '%s'", len, buf);

  if (is_reverse(packet_body, (char *)buf)) {
    return 0;                   /* Success */
  }
  return -1;
}

int run_scenario(const char *scenario, mbedtls_ssl_context *ssl) {
  int ret;
  int repeat = 1;
  const char *p = scenario;
  const char *start;
  char packet[10000];

  plog("Running scenario: '%s'", scenario);

  if (strncmp("repeat=", p, 7) == 0) {
    char *comma = strchr(p, ',');
    if (comma) {
      int packet_len = comma - p;
      memcpy(packet, p, packet_len);
      packet[packet_len] = '\0';
      repeat = atoi(packet + 7);
      p = comma + 1;
    }
  }

  start = p;

  for (; repeat > 0; repeat--) {
    plog("Scenario: %d repeats left", repeat);
    p = start;
    while (p) {
      char *comma = strchr(p, ',');
      if (comma) {
        int packet_len = comma - p;
        memcpy(packet, p, packet_len);
        packet[packet_len] = '\0';
        p = comma + 1;
      } else {
        strncpy(packet, p, sizeof(packet));
        p = NULL;
      }
      if (strncmp("sleep=", packet, 6) == 0) {
        long sleepms = atol(packet + 6);
        plog("Scenario: sleeping %ld milliseconds", sleepms);
        mbedtls_net_usleep(sleepms * 1000);
      } else {
        ret = send_one_packet(packet, ssl);
        if (ret != 0) {
          return ret;
        }
      }
    }
  }
  plog("Scenario successful!");
  return 0;
}

static int get_source_port(int fd) {
  union sockaddr_u {
    struct sockaddr_storage storage;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr sockaddr;
  } addr;
  socklen_t addrlen = sizeof(addr.storage);

  if (getsockname(fd, &addr.sockaddr, &addrlen) != 0) {
    return -1;
  }

  /* deal with both IPv4 and IPv6: */
  if (addr.storage.ss_family == AF_INET) {
    struct sockaddr_in *s_ip4 = &addr.in;
    return ntohs(s_ip4->sin_port);
  } else {
    struct sockaddr_in6 *s_ip6 = &addr.in6;
    return ntohs(s_ip6->sin6_port);
  }
  return -1;
}

int main(int argc, char *argv[]) {
  int ret, exitcode;
  mbedtls_net_context server_fd;
  uint32_t flags;
  char scenario[10000] = "";
  char server_host[100] = "";
  char server_port[6] = "";
  char server_ssl_hostname[100] = "";
  const char *pers = "dtls_client";
  int opt;
  struct timeval t0, t1;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  mbedtls_timing_delay_context timer;

  /* Parse command line */
  while ((opt = getopt(argc, argv, "h:n:p:s:")) != -1) {
    switch (opt) {
      case 'h':
        strncpy(server_host, optarg, sizeof(server_host));
        break;
      case 'n':
        strncpy(server_ssl_hostname, optarg, sizeof(server_ssl_hostname));
        break;
      case 'p':
        strncpy(server_port, optarg, sizeof(server_port));
        break;
      case 's':
        strncpy(scenario, optarg, sizeof(scenario));
        break;
      default:                 /* '?' */
        print_usage(argv[0]);
    }
  }

  if (!(scenario[0] && server_port[0] && server_host[0])) {
    print_usage(argv[0]);
  }

  if (!server_ssl_hostname[0]) {
    strncpy(server_ssl_hostname, server_host, sizeof(server_ssl_hostname));
  }
#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

  /*
   * 0. Initialize the RNG and the session data
   */
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  plog("Seeding the random number generator...");

  mbedtls_entropy_init(&entropy);
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *)pers, strlen(pers))) != 0) {
    plog("ERROR: failed! mbedtls_ctr_drbg_seed returned %d", ret);
    goto exit;
  }

  /*
   * 0. Load certificates
   */
  plog("Loading the CA root certificate ...");

  ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len);
  if (ret < 0) {
    plog("ERROR: failed! mbedtls_x509_crt_parse returned -0x%x", -ret);
    goto exit;
  }

  plog("Connecting to udp %s:%s (SSL hostname: %s)...",
       server_host, server_port, server_ssl_hostname);

  if ((ret = mbedtls_net_connect(&server_fd, server_host, server_port, MBEDTLS_NET_PROTO_UDP)) != 0) {
    plog("ERROR: failed! mbedtls_net_connect returned %d", ret);
    goto exit;
  }

  plog("The local client UDP source port is %d", get_source_port(server_fd.fd));

  plog("Setting up the DTLS structure...");

  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    plog("ERROR: failed! mbedtls_ssl_config_defaults returned %d", ret);
    goto exit;
  }

  /* OPTIONAL is usually a bad choice for security, but makes interop easier
   * in this simplified example, in which the ca chain is hardcoded.
   * Production code should set a proper ca chain and use REQUIRED. */
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, log_mbedtls_debug_callback, NULL);
  /* TODO timeouts */

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    plog("ERROR: failed! mbedtls_ssl_setup returned %d", ret);
    goto exit;
  }

  if ((ret = mbedtls_ssl_set_hostname(&ssl, server_ssl_hostname)) != 0) {
    plog("ERROR: failed! mbedtls_ssl_set_hostname returned %d", ret);
    goto exit;
  }

  mbedtls_ssl_set_bio(&ssl, &server_fd,
                      mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

  mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

  plog("Performing the SSL/TLS handshake...");

  gettimeofday(&t0, NULL);
  do {
    ret = mbedtls_ssl_handshake(&ssl);
    plog(" ... during SSL handshake, ret=%d (WANT_READ=%d, WANT_WRITE=%d, RECV_FAILED=%d",
         ret, MBEDTLS_ERR_SSL_WANT_READ, MBEDTLS_ERR_SSL_WANT_WRITE, MBEDTLS_ERR_NET_RECV_FAILED);
    gettimeofday(&t1, NULL);
  } while ((duration_ms(&t1, &t0) <= SSL_HANDSHAKE_TIMEOUT_MILLISECS) &&
           (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE));

  plog("handshake duration: %d milliseconds", duration_ms(&t1, &t0));
  if (duration_ms(&t1, &t0) > SSL_HANDSHAKE_TIMEOUT_MILLISECS) {
    plog("ERROR: long time to perform handshake: %d milliseconds", duration_ms(&t1, &t0));
    ret = MBEDTLS_ERR_SSL_TIMEOUT;
    goto exit;
  }

  if (ret != 0) {
    plog("ERROR: failed! mbedtls_ssl_handshake returned -0x%x", -ret);
    goto exit;
  }

  plog("Verifying peer X.509 certificate...");

  /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
   * handshake would not succeed if the peer's cert is bad.  Even if we used
   * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
  if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
    char vrfy_buf[512];
    mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "! ", flags);
    plog("Verification failed: %s", vrfy_buf);
  } else {
    plog("Certificates ok");
  }

  ret = run_scenario(scenario, &ssl);
  if (ret != 0) {
    goto exit;
  }

  plog("Closing the connection...");

  /* No error checking, the connection might be closed already */
  do {
    ret = mbedtls_ssl_close_notify(&ssl);
  } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  ret = 0;

exit:

#ifdef MBEDTLS_ERROR_C
  if (ret != 0) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    plog("ERROR: Last error was: %d - %s", ret, error_buf);
  }
#endif

  mbedtls_net_free(&server_fd);

  mbedtls_x509_crt_free(&cacert);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  exitcode = ret == 0 ? 0 : 1;
  plog("Done, exitcode=%d", exitcode);
  return exitcode;
}
