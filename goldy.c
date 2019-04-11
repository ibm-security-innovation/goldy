/*
 * goldy - DTLS proxy
 */

#if defined(__linux__)
#define _XOPEN_SOURCE 700
#endif

#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "ev.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <getopt.h>

#include "goldy.h"
#include "daemonize.h"
#include "log.h"
#include "utlist.h"

/* Raise this value to have more verbose logging from mbedtls functions */
#define MBEDTLS_DEBUG_LOGGING_LEVEL 0

/* Delete all the items in a singly-linked list */
#define LL_PURGE(head)                 \
  do {                                 \
    LDECLTYPE(head) _tmp;              \
    while (head) {                     \
      _tmp = (head);                   \
      (head) = (head)->next;           \
      free(_tmp);                      \
    }                                  \
  } while (0)

static void print_version() {
  printf("goldy %s\n", GOLDY_VERSION);
}

static void print_usage() {
  printf
    ("Usage: goldy [-hvd] [-g log_level] [-t seconds] -l listen_host:port\n"
     "             -b backend_host:port -c cert_pem_file -k private_key_pem_file\n"
     "\n"
     "Options:\n"
     "  -h, --help                 this help\n"
     "  -v, --version              show version and exit\n"
     "  -d, --daemonize            run as a daemon\n"
     "  -g, --log=LEVEL            log level DEBUG/INFO/ERROR\n"
     "  -t, --timeout=SECONDS      Session timeout (seconds)\n"
     "  -l, --listen=ADDR:PORT     listen for incoming DTLS on addr and UDP port\n"
     "  -b, --backend=ADDR:PORT    proxy UDP traffic to addr and port\n"
     "  -c, --cert=FILE            TLS certificate PEM filename\n"
     "  -k, --key=FILE             TLS private key PEM filename\n");
}

/** Parse command line arguments.
 *
 * Returns 1 if all OK or 0 if there's a problem.
 */
static int get_options(int argc, char **argv, struct instance *gi) {
  int opt;

  char *sep;

  static const char *short_options = "hvdb:g:l:c:k:t:";

  static struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"daemonize", no_argument, NULL, 'd'},
    {"backend", required_argument, NULL, 'b'},
    {"log", optional_argument, NULL, 'g'},
    {"listen", required_argument, NULL, 'l'},
    {"cert", required_argument, NULL, 'c'},
    {"key", required_argument, NULL, 'k'},
    {"timeout", optional_argument, NULL, 't'},
    {0, 0, 0, 0}
  };

  memset(gi, 0, sizeof(*gi));
  gi->session_timeout = DEFAULT_SESSION_TIMEOUT;

  while ((opt = getopt_long(argc, argv, short_options, long_options,
                            NULL)) != -1) {
    switch (opt) {
    case 'h':                /* -h, --help */
      print_usage();
      exit(0);
      break;
    case 'v':                /* -v, --version */
      print_version();
      exit(0);
      break;
    case 'd':                /* -d, --daemonize */
      gi->daemonize = 1;
      break;
    case 'b':                /* -b, --backend=S */
      sep = strchr(optarg, ':');
      if (!sep) {
        return 0;
      }
      *sep = '\0';
      gi->backend_host = optarg;
      gi->backend_port = sep + 1;
      break;
    case 'g':                /* -g, --log=S */
      if (strcmp(optarg, "DEBUG") == 0)
        log_stderr_open(LOG_DEBUG);
      else if (strcmp(optarg, "INFO") == 0)
        log_stderr_open(LOG_INFO);
      else if (strcmp(optarg, "ERROR") == 0)
        log_stderr_open(LOG_ERROR);
      break;
    case 'l':                /* -l, --listen=S */
      sep = strrchr(optarg, ':');
      if (!sep) {
        return 0;
      }

      *sep = '\0';
      gi->listen_host = optarg;
      gi->listen_port = sep + 1;
      break;
    case 'c':                /* -c, --cert=S */
      gi->cert_file = optarg;
      break;
    case 'k':                /* -k, --key=S */
      gi->private_key_file = optarg;
      break;
    case 't':                /* -t, --timeout=I */
      gi->session_timeout = atoi(optarg);
      break;
    default:                 /* '?' */
      return 0;
    }
  }

  if (!(gi->listen_host && gi->listen_port &&
        gi->backend_host && gi->backend_port &&
        gi->cert_file && gi->private_key_file)) {
    log_error("Mandatory param missing. Bye.\n");
    return 0;
  }
  return 1;
}

static int check_return_code(int ret, const char *label) {
#ifdef MBEDTLS_ERROR_C
  if (ret != 0) {
    char error_buf[100];

    mbedtls_strerror(ret, error_buf, 100);
    log_error("(%s) Last error was: %d - %s", label, ret, error_buf);
  }
#endif
  return ret;
}

typedef struct {
  const struct instance *options;
  mbedtls_ssl_cookie_ctx cookie_ctx;
  mbedtls_net_context listen_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_context cache;
#endif
} global_context;

static void global_cb(EV_P_ ev_io *w, int revents);

static int global_deinit(global_context *gc) {
  int ret = 0;

  mbedtls_net_free(&gc->listen_fd);

  mbedtls_x509_crt_free(&gc->srvcert);
  mbedtls_pk_free(&gc->pkey);
  mbedtls_ssl_config_free(&gc->conf);
  mbedtls_ssl_cookie_free(&gc->cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free(&gc->cache);
#endif
  mbedtls_ctr_drbg_free(&gc->ctr_drbg);
  mbedtls_entropy_free(&gc->entropy);

  return ret == 0 ? 0 : 1;
}

static int bind_listen_fd(global_context *gc) {
  int ret;

  ret =
    mbedtls_net_bind(&gc->listen_fd, gc->options->listen_host,
                     gc->options->listen_port, MBEDTLS_NET_PROTO_UDP);
  if (ret != 0) {
    log_error("Bind failed for host %s on UDP port %s", gc->options->listen_host, gc->options->listen_port);
    check_return_code(ret, "bind_listen_fd");
    return ret;
  }
  log_debug("Binded UDP %s:%s", gc->options->listen_host, gc->options->listen_port);
  mbedtls_net_set_nonblock(&gc->listen_fd);
  return 0;
}

static void log_mbedtls_debug_callback(void *ctx, int level, const char *file, int line,
                                       const char *str) {
  (void)ctx;
  log_debug("mbedtls_debug [%d] %s:%04d: %s", level, file, line, str);
}

static int global_init(const struct instance *gi, global_context *gc) {
  int ret;
#ifdef __APPLE__   // MacOS/X requires an additional call
  int one = 1;
#endif
  const char *pers = "goldy";

  memset(gc, 0, sizeof(*gc));
  gc->options = gi;
  mbedtls_ssl_config_init(&gc->conf);
  mbedtls_ssl_cookie_init(&gc->cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init(&gc->cache);
#endif
  mbedtls_x509_crt_init(&gc->srvcert);
  mbedtls_pk_init(&gc->pkey);
  mbedtls_entropy_init(&gc->entropy);
  mbedtls_ctr_drbg_init(&gc->ctr_drbg);

  log_info("Goldy %s starting up", GOLDY_VERSION);
  mbedtls_net_init(&gc->listen_fd);
  ret = bind_listen_fd(gc);
  if (ret != 0) {
    goto exit;
  }
#ifdef __APPLE__   // MacOS/X requires an additional call
  ret = setsockopt(gc->listen_fd.fd, SOL_SOCKET, SO_REUSEPORT, (char*)&one, sizeof(one));
  if (ret != 0) {
    goto exit;
  }
#endif

  ret = mbedtls_x509_crt_parse_file(&gc->srvcert, gi->cert_file);
  if (ret != 0) {
    log_error("mbedtls_x509_crt_parse returned %d", ret);
    goto exit;
  }
  log_debug("Loaded server certificate file");

  ret = mbedtls_pk_parse_keyfile(&gc->pkey, gi->private_key_file, NULL);
  if (ret != 0) {
    log_error("mbedtls_pk_parse_key returned %d", ret);
    goto exit;
  }
  log_debug("Loaded private key file");

  if ((ret = mbedtls_ctr_drbg_seed(&gc->ctr_drbg, mbedtls_entropy_func,
                                   &gc->entropy, (const unsigned char *)pers,
                                   strlen(pers))) != 0) {
    printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    goto exit;
  }
  log_debug("Seeded random number generator");

  if ((ret = mbedtls_ssl_config_defaults(&gc->conf,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    log_error("mbedtls_ssl_config_defaults returned %d", ret);
    goto exit;
  }

  mbedtls_ssl_conf_dbg(&gc->conf, log_mbedtls_debug_callback, NULL);
  mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LOGGING_LEVEL);
  mbedtls_ssl_conf_rng(&gc->conf, mbedtls_ctr_drbg_random, &gc->ctr_drbg);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache(&gc->conf, &gc->cache,
                                 mbedtls_ssl_cache_get,
                                 mbedtls_ssl_cache_set);
#endif

  mbedtls_ssl_conf_ca_chain(&gc->conf, gc->srvcert.next, NULL);
  if ((ret = mbedtls_ssl_conf_own_cert(&gc->conf, &gc->srvcert, &gc->pkey)) != 0) {
    log_error("mbedtls_ssl_conf_own_cert returned %d", ret);
    goto exit;
  }
  if ((ret = mbedtls_ssl_cookie_setup(&gc->cookie_ctx,
                                      mbedtls_ctr_drbg_random,
                                      &gc->ctr_drbg)) != 0) {
    log_error("mbedtls_ssl_cookie_setup returned %d", ret);
    goto exit;
  }
  mbedtls_ssl_conf_dtls_cookies(&gc->conf, mbedtls_ssl_cookie_write,
                                mbedtls_ssl_cookie_check, &gc->cookie_ctx);
  log_info("Proxy is ready, listening for connections on UDP %s:%s",
           gi->listen_host, gi->listen_port);

 exit:
  check_return_code(ret, "global_init - exit");

  if (ret != 0) {
    global_deinit(gc);
  }
  return ret == 0 ? 0 : 1;
}

#define PACKET_DATA_BUFFER_SIZE 4000
typedef struct packet_data {
  unsigned char payload[PACKET_DATA_BUFFER_SIZE];
  size_t length;
  struct packet_data *next;
} packet_data;

typedef enum {
  GOLDY_SESSION_STEP_HANDSHAKE = 0,
  GOLDY_SESSION_STEP_OPERATIONAL,
  GOLDY_SESSION_STEP_FLUSH_TO_BACKEND,
  GOLDY_SESSION_STEP_CLOSE_NOTIFY,
  GOLDY_SESSION_STEP_LAST,
} session_step;

typedef struct {
  const struct instance *options;
  mbedtls_net_context client_fd;
  mbedtls_net_context backend_fd;
  mbedtls_ssl_context ssl;
  mbedtls_timing_delay_context timer;
  unsigned char client_ip[39];
  char client_ip_str[INET6_ADDRSTRLEN];
  int client_port;
  size_t cliip_len;
  packet_data *from_client;
  packet_data *from_backend;
  ev_io client_rd_watcher;
  ev_io client_wr_watcher;
  ev_io backend_rd_watcher;
  ev_io backend_wr_watcher;
  ev_timer inactivity_timer;
  session_step step;
  ev_tstamp last_activity;
  int pending_free;
} session_context;

static void session_dispatch(EV_P_ ev_io *w, int revents);

static int session_init(const global_context *gc,
                        session_context *sc,
                        const mbedtls_net_context *client_fd,
                        unsigned char client_ip[39], size_t cliip_len,
                        const unsigned char* first_packet, size_t first_packet_len) {
  int ret;

  memset(sc, 0, sizeof(*sc));
  memcpy(&sc->client_fd, client_fd, sizeof(sc->client_fd));
  if (cliip_len > sizeof(sc->client_ip)) {
    log_error("session_init - client_ip size mismatch");
    return 1;
  }
  memcpy(&sc->client_ip, client_ip, cliip_len);
  sc->cliip_len = cliip_len;
  mbedtls_ssl_init(&sc->ssl);
  mbedtls_net_init(&sc->backend_fd);
  sc->step = GOLDY_SESSION_STEP_HANDSHAKE;
  sc->options = gc->options;

  if ((ret = mbedtls_ssl_setup(&sc->ssl, &gc->conf)) != 0) {
    check_return_code(ret, "session_init - mbedtls_ssl_steup");
    return 1;
  }
  mbedtls_ssl_set_timer_cb(&sc->ssl, &sc->timer,
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  /* We already read the first packet of the SSL session from the network in
   * the initial recvfrom() call on the listening fd. Here we copy the content
   * of that packet into the SSL incoming data buffer so it'll be consumed on
   * the next call to mbedtls_ssl_fetch_input(). */
  if (first_packet_len<MBEDTLS_SSL_BUFFER_LEN) {
    memcpy(sc->ssl.in_hdr, first_packet, first_packet_len);
    sc->ssl.in_left = first_packet_len;
  }

  return 0;
}

static void session_free(EV_P_ session_context *sc) {
  log_debug("session_free - sc=%x", sc);
  ev_io_stop(EV_A_ & sc->backend_rd_watcher);
  ev_io_stop(EV_A_ & sc->backend_wr_watcher);
  ev_io_stop(EV_A_ & sc->client_rd_watcher);
  ev_io_stop(EV_A_ & sc->client_wr_watcher);
  ev_timer_stop(EV_A_ & sc->inactivity_timer);

  mbedtls_net_free(&sc->backend_fd);
  mbedtls_net_free(&sc->client_fd);
  mbedtls_ssl_free(&sc->ssl);

  LL_PURGE(sc->from_client);
  LL_PURGE(sc->from_backend);

  log_info("(%s:%d) Session closed", sc->client_ip_str, sc->client_port);
  free(sc);
}

static void session_mark_activity(EV_P_ session_context *sc) {
  sc->last_activity = ev_now(EV_A);
  ev_timer_again(EV_A_ &sc->inactivity_timer);
}

static void session_inactivity_timer_handler(EV_P_ ev_timer *w, int revents) {
  session_context *sc = (session_context *)w->data;
  ev_tstamp now = ev_now(EV_A);

  (void)revents;
  log_debug("session_inactivity_timer_handler - sc=%x timeout: "
            "now=%.3f - last_activity=%.3f (duration=%.3f) > timeout=%d",
            sc, now, sc->last_activity, now - sc->last_activity,
            sc->options->session_timeout);
  log_info("(%s:%d) Session timeout", sc->client_ip_str, sc->client_port);
  session_free(EV_A_ sc);
}

static void session_start(session_context *sc, EV_P) {
  ev_io_init(&sc->client_rd_watcher, session_dispatch,
             sc->client_fd.fd, EV_READ);
  sc->client_rd_watcher.data = sc;

  ev_io_init(&sc->client_wr_watcher, session_dispatch,
             sc->client_fd.fd, EV_WRITE);
  sc->client_wr_watcher.data = sc;

  ev_timer_init(&sc->inactivity_timer, session_inactivity_timer_handler,
                0., (double)sc->options->session_timeout);
  sc->inactivity_timer.data = sc;

  ev_io_start(EV_A_ &sc->client_rd_watcher);
  session_mark_activity(EV_A_ sc);
}

static void acquire_peername(session_context *sc) {
  union sockaddr_u {
    struct sockaddr_storage storage;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr sockaddr;
  } addr;

  socklen_t addrlen = sizeof(addr.storage);

  getpeername(sc->client_fd.fd, &addr.sockaddr, &addrlen);

  /* deal with both IPv4 and IPv6: */
  if (addr.storage.ss_family == AF_INET) {
    struct sockaddr_in *s_ip4 = &addr.in;

    sc->client_port = ntohs(s_ip4->sin_port);
    inet_ntop(AF_INET, &s_ip4->sin_addr, sc->client_ip_str,
              sizeof(sc->client_ip_str));
  } else {
    struct sockaddr_in6 *s_ip6 = &addr.in6;

    sc->client_port = ntohs(s_ip6->sin6_port);
    inet_ntop(AF_INET6, &s_ip6->sin6_addr, sc->client_ip_str,
              sizeof(sc->client_ip_str));
  }

}

static void session_report_error(int ret, session_context *sc,
                                 const char *label) {
#ifdef MBEDTLS_ERROR_C
  char error_buf[100];

  mbedtls_strerror(ret, error_buf, sizeof(error_buf));
  log_error("(%s:%d) %s: %s (%d)", sc->client_ip_str, sc->client_port,
            label, error_buf, ret);
#endif
}

static int session_connected(session_context *sc) {
  int ret = 0;

  acquire_peername(sc);
  log_info("(%s:%d) Client connected", sc->client_ip_str, sc->client_port);
  /* For HelloVerifyRequest cookies */
  if ((ret = mbedtls_ssl_set_client_transport_id(&sc->ssl,
                                                 sc->client_ip,
                                                 sc->cliip_len)) == 0) {
    mbedtls_ssl_set_bio(&sc->ssl, &sc->client_fd, mbedtls_net_send,
                        mbedtls_net_recv, 0);
  } else {
    session_report_error(ret, sc, "session_connected");
  }
  return ret == 0 ? 0 : 1;
}

static void session_deferred_free(session_context *sc, const char *reason) {
  log_debug("session_deferred_free - %s %x %d", reason, sc, sc->client_fd.fd);
  sc->pending_free = 1;
}


static void session_deferred_free_after_error(session_context *sc, int ret,
                                              const char *label) {
  session_report_error(ret, sc, label);
  session_deferred_free(sc, label);
}

static int connect_to_backend(EV_P_ session_context *sc) {
  int ret;
  ret = mbedtls_net_connect(&sc->backend_fd,
                            sc->options->backend_host,
                            sc->options->backend_port,
                            MBEDTLS_NET_PROTO_UDP);
  if (ret != 0) {
    return 1;
  }
  mbedtls_net_set_nonblock(&sc->backend_fd);
  log_info("Created socket to backend UDP %s:%s",
           sc->options->backend_host, sc->options->backend_port);
  ev_io_init(&sc->backend_rd_watcher, session_dispatch, sc->backend_fd.fd,
             EV_READ);
  ev_io_init(&sc->backend_wr_watcher, session_dispatch, sc->backend_fd.fd,
             EV_WRITE);
  sc->backend_rd_watcher.data = sc;
  sc->backend_wr_watcher.data = sc;
  ev_io_start(EV_A_ &sc->backend_rd_watcher);
  return 0;
}

static void session_step_handshake(EV_P_ ev_io *w, int revents,
                                   session_context *sc) {
  int ret = mbedtls_ssl_handshake(&sc->ssl);

  (void)w;
  (void)revents;
  switch (ret) {
  case MBEDTLS_ERR_SSL_WANT_READ:
  case MBEDTLS_ERR_SSL_WANT_WRITE:
  case MBEDTLS_ERR_NET_RECV_FAILED:
    session_mark_activity(EV_A_ sc);
    return;

  case 0:
    log_debug("(%s:%d) DTLS handshake done", sc->client_ip_str,
              sc->client_port);
    session_mark_activity(EV_A_ sc);
    if (connect_to_backend(EV_A_ sc) != 0) {
      return session_deferred_free_after_error(sc, ret, "session_step_send_backend");
    }
    sc->step = GOLDY_SESSION_STEP_OPERATIONAL;
    return;

  case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
    log_debug("(%s:%d) DTLS handshake requested hello verification",
              sc->client_ip_str, sc->client_port);
    session_deferred_free(sc, "hello verification");
    return;

  default:
    return session_deferred_free_after_error(sc, ret, "session_cb - ssl handshake");
  }
}

static void session_receive_from_client(EV_P_ session_context *sc) {
  int ret;
  packet_data *pd;
  packet_data temp = { .length = sizeof(temp.payload) };

  ret = mbedtls_ssl_read(&sc->ssl, temp.payload, temp.length);
  switch (ret) {
  case MBEDTLS_ERR_SSL_WANT_READ:
  case MBEDTLS_ERR_SSL_WANT_WRITE:
  case MBEDTLS_ERR_NET_RECV_FAILED:
  case MBEDTLS_ERR_SSL_TIMEOUT:
    session_mark_activity(EV_A_ sc);
    return;

  case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
    log_info("(%s:%d) Client asked to close DTLS session",
             sc->client_ip_str, sc->client_port);
    ev_io_start(EV_A_ &sc->backend_wr_watcher);
    sc->step = GOLDY_SESSION_STEP_FLUSH_TO_BACKEND;
    return;

  default:
    if (ret < 0) {
      session_deferred_free_after_error(sc, ret, "session_receive_from_client - unknwon error");
      return;
    }
    /* ret is the number of plaintext bytes received */
    log_debug("(%s:%d) %d bytes read from DTLS socket",
            sc->client_ip_str, sc->client_port, ret);

    if (ret > PACKET_DATA_BUFFER_SIZE) {
      session_deferred_free_after_error(sc, 0, "session_receive_from_client - packet payload too big");
      return;
    }
    pd = calloc(1, sizeof(packet_data));
    memcpy(pd->payload, temp.payload, ret);
    pd->length = ret;
    pd->next = 0;
    LL_APPEND(sc->from_client, pd);
    session_mark_activity(EV_A_ sc);
    ev_io_start(EV_A_ &sc->backend_wr_watcher);
    return;
  }
}

static void session_send_to_backend(EV_P_ session_context *sc) {
  int ret;
  packet_data* head = sc->from_client;

  if (!head) {
    ev_io_stop(EV_A_ &sc->backend_wr_watcher);
    return;
  }

  ret = mbedtls_net_send(&sc->backend_fd, head->payload, head->length);

  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    session_mark_activity(EV_A_ sc);
    return;
  }
  if (ret < 0) {
    session_deferred_free_after_error(sc, ret, "session_send_to_backend");
    return;
  }
  log_debug("(%s:%d) %d bytes sent to backend server",
            sc->client_ip_str, sc->client_port, ret);
  if ((size_t)ret != head->length) {
    log_error("Sent only %d bytes out of %d", ret, head->length);
  }
  session_mark_activity(EV_A_ sc);
  LL_DELETE(sc->from_client, head);
  free(head);
  if (!sc->from_client) {
    ev_io_stop(EV_A_ &sc->backend_wr_watcher);
  }
  return;
}

static void session_receive_from_backend(EV_P_ session_context *sc) {
  int ret;
  packet_data *pd;
  packet_data temp = { .length = sizeof(temp.payload) };

  ret = mbedtls_net_recv(&sc->backend_fd, temp.payload, temp.length);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_NET_RECV_FAILED) {
    session_mark_activity(EV_A_ sc);
    return;
  }
  if (ret < 0) {
    session_deferred_free_after_error(sc, ret, "session_receive_from_backend");
    return;
  }
  /* ret is the number of bytes read from the backend server */
  log_debug("(%s:%d) %d bytes received from backend server",
            sc->client_ip_str, sc->client_port, ret);
  if (ret > PACKET_DATA_BUFFER_SIZE) {
    session_deferred_free_after_error(sc, 0, "session_receive_from_backend - packet payload too big");
    return;
  }
  pd = calloc(1, sizeof(packet_data));
  memcpy(pd->payload, temp.payload, ret);
  pd->length = ret;
  pd->next = 0;
  LL_APPEND(sc->from_backend, pd);
  session_mark_activity(EV_A_ sc);
  ev_io_start(EV_A_ &sc->client_wr_watcher);
}


static void session_send_to_client(EV_P_ session_context *sc) {
  int ret;
  packet_data* head = sc->from_backend;

  if (!head) {
    ev_io_stop(EV_A_ &sc->client_wr_watcher);
    return;
  }

  ret = mbedtls_ssl_write(&sc->ssl, head->payload, head->length);

  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ) {
    session_mark_activity(EV_A_ sc);
    return;
  }
  if (ret < 0) {
    session_deferred_free_after_error(sc, ret, "session_send_to_client - write error");
    return;
  }
  /* ret is the written len */
  log_debug("(%s:%d) %d bytes written to DTLS socket",
            sc->client_ip_str, sc->client_port, ret);
  if ((size_t)ret != head->length) {
    log_error("Sent only %d bytes out of %d", ret, head->length);
  }
  session_mark_activity(EV_A_ sc);
  LL_DELETE(sc->from_backend, head);
  free(head);
  if (!sc->from_backend) {
    ev_io_stop(EV_A_ &sc->client_wr_watcher);
  }
}

static void session_step_operational(EV_P_ ev_io *w, int revents, session_context *sc) {
  if ((w->fd == sc->client_fd.fd) && (revents & EV_READ)) {
    session_receive_from_client(EV_A_ sc);
  }
  if ((w->fd == sc->backend_fd.fd) && (revents & EV_WRITE)) {
    session_send_to_backend(EV_A_ sc);
  }
  if ((w->fd == sc->backend_fd.fd) && (revents & EV_READ)) {
    session_receive_from_backend(EV_A_ sc);
  }
  if ((w->fd == sc->client_fd.fd) && (revents & EV_WRITE)) {
    session_send_to_client(EV_A_ sc);
  }
}

static void session_step_flush_to_backend(EV_P_ ev_io *w, int revents,
                                          session_context *sc) {
  (void)w;
  if (sc->from_client) {
    if ((w->fd == sc->backend_fd.fd) && (revents & EV_WRITE)) {
      session_send_to_backend(EV_A_ sc);
    }
  } else {
    /* No more packets to send to backend */
    ev_io_stop(EV_A_ &sc->backend_wr_watcher);
    ev_io_start(EV_A_ &sc->client_wr_watcher);
    sc->step = GOLDY_SESSION_STEP_CLOSE_NOTIFY;
  }
}

static void session_step_close_notify(EV_P_ ev_io *w, int revents,
                                      session_context *sc) {
  int ret;

  (void)loop;
  (void)w;
  (void)revents;

  ret = mbedtls_ssl_close_notify(&sc->ssl);
  session_mark_activity(EV_A_ sc);
  if (ret==MBEDTLS_ERR_SSL_WANT_WRITE || ret==MBEDTLS_ERR_SSL_WANT_READ) {
    return;
  }
  session_deferred_free(sc, "close_notify");
}

typedef void (*session_step_cb) (EV_P_ ev_io *w, int revents,
                                           session_context *sc);

static session_step_cb session_callbacks[GOLDY_SESSION_STEP_LAST] = {
  session_step_handshake,
  session_step_operational,
  session_step_flush_to_backend,
  session_step_close_notify
};

static void session_dispatch(EV_P_ ev_io *w, int revents) {
  session_context *sc = (session_context *)w->data;
  /*
  static int count = 0;

  log_debug("(%s:%d) session_dispatch fds: %d,%d; w->fd: %d; revents:0x%02x; step:%d, count:%d",
            sc->client_ip_str, sc->client_port,
            sc->client_fd.fd,
            sc->backend_fd.fd,
            w->fd,
            revents,
            sc->step,
            count);
  count++;
  */
  session_callbacks[sc->step] (EV_A_ w, revents, sc);
  if (sc->pending_free) {
    /* time to kill the session */
    session_free(EV_A_ sc);
  }
}

static void start_listen_io(EV_P_ ev_io *w, global_context *gc) {
  log_debug("start_listen_io - %d", gc->listen_fd.fd);
  ev_io_init(w, global_cb, gc->listen_fd.fd, EV_READ);
  w->data = gc;
  ev_io_start(EV_A_ w);
}

static int connect_to_new_client(mbedtls_net_context* client_fd,
                                 const struct sockaddr_storage *client_addr,
                                 const socklen_t client_addr_size,
                                 const struct sockaddr_storage *local_addr,
                                 const socklen_t local_addr_size) {
  int ret = 0;
  int one = 1;

  mbedtls_net_init(client_fd);
  client_fd->fd = socket(client_addr->ss_family, SOCK_DGRAM, IPPROTO_UDP);
  if (client_fd->fd < 0) {
    log_error("socket() failed errno=%d", ret, errno);
    return 1;
  }

#ifdef __APPLE__   // MacOS/X requires an additional call
  ret = setsockopt(client_fd->fd, SOL_SOCKET, SO_REUSEPORT, (char*)&one, sizeof(one));
  if (ret != 0) {
    log_error("setsockopt(SO_REUSEPORT) failed ret=%d errno=%d", ret, errno);
    return 1;
  }
#endif
  ret = setsockopt(client_fd->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
  if (ret != 0) {
    log_error("setsockopt(SO_REUSEADDR) failed ret=%d errno=%d", ret, errno);
    return 1;
  }

  mbedtls_net_set_nonblock(client_fd);
  ret = bind(client_fd->fd, (struct sockaddr *)local_addr, local_addr_size);
  if (ret != 0) {
    log_error("bind() fd=%d failed ret=%d errno=%d", client_fd->fd, ret, errno);
    return 1;
  }

  ret = connect(client_fd->fd, (struct sockaddr *)client_addr, client_addr_size);
  if (ret != 0) {
    log_error("connect() failed ret=%d errno=%d", ret, errno);
    return 1;
  }

  log_debug("connect_to_new_client: connected on fd %d", client_fd->fd);
  return 0;
}

static void global_cb(EV_P_ ev_io *w, int revents) {
  global_context *gc = (global_context *)w->data;
  static int count = 0;
  int ret = 0;
  struct sockaddr_storage local_addr;
  socklen_t local_addr_size = sizeof(local_addr);

  log_debug("global_cb fds: %d,%d revents: 0x%02x count: %d", w->fd, gc->listen_fd.fd, revents, count);
  count++;

  ret = getsockname(gc->listen_fd.fd, (struct sockaddr *)&local_addr, &local_addr_size);
  if (ret < 0) {
    log_error("getsockname() failed errno=%d", ret, errno);
    return;
  }

  /* Read all the incoming packets waiting on listen_fd, and create a session for each one */
  for (;;) {
    mbedtls_net_context client_fd;
    session_context *sc;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size = sizeof(client_addr);
    unsigned char first_packet[MBEDTLS_SSL_MAX_CONTENT_LEN];
    size_t first_packet_len = 0;

    ret = recvfrom(gc->listen_fd.fd, first_packet, sizeof(first_packet), 0,
                   (struct sockaddr *)&client_addr, &client_addr_size);
    if (ret < 0) {
      int save_errno = errno;
      if ((save_errno == EAGAIN) || (save_errno == EWOULDBLOCK)) {
        /* We finished reading everything that was available so far */
        return;
      }
      log_error("recvfrom failed on listening socket (fd=%d), errno=%d", gc->listen_fd.fd,
                save_errno);
      return;
    } else if (ret == 0) {
      log_error("recvfrom() returned 0, this shouldn't happen");
      continue;
    }

    first_packet_len = ret;

    /* We have a new client! Connect the client_fd socket to that peer */
    ret = connect_to_new_client(&client_fd,
                                &client_addr, client_addr_size,
                                &local_addr, local_addr_size);
    if (ret != 0) {
      log_error("connect_to_new_client failed");
      continue;
    }

    sc = calloc(1, sizeof(session_context));

    session_init(gc, sc, &client_fd, (unsigned char *)&client_addr, client_addr_size,
                 first_packet, first_packet_len);

    if (session_connected(sc) != 0) {
      log_error("can't init client connection");
      free(sc);
      continue;
    }

    /* Start listening for network events on the new client fd */
    session_start(sc, EV_A);
    log_debug("global_cb - session_start - client_fd %d", sc->client_fd.fd);

    /* Trigger a simulated EV_READ event to cause the session callback to consume the fisrt
     * packet (which was already inserted into the SSL buffers in session_init()). */
    ev_feed_fd_event(EV_A_ sc->client_fd.fd, EV_READ);
  }
}

static int main_loop(global_context *gc) {
  ev_io global_watcher;
  struct ev_loop *loop = ev_default_loop(0);

  log_info("main_loop - start");
  start_listen_io(EV_A_ &global_watcher, gc);
  ev_loop(EV_A_ 0);

  log_info("main_loop - exit");
  return 0;
}

int main(int argc, char **argv) {
  struct instance gi;
  global_context gc;

  int ret = 0;

  log_stderr_open(LOG_INFO);

  if (!get_options(argc, argv, &gi)) {
    print_usage();
    exit(1);
  }
  if (gi.daemonize) {
    daemonize(NULL, GOLDY_DAEMON_USER);
  }
  if ((ret = global_init(&gi, &gc)) != 0) {
    printf("global initialization failed\n");
    goto exit;
  }
  main_loop(&gc);

 exit:
  check_return_code(ret, "main - exit");
  global_deinit(&gc);
  return ret == 0 ? 0 : 1;
}
