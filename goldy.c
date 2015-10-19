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
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "ev.h"

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


static void print_version() {
  printf("goldy %s\n", GOLDY_VERSION);
}

static void print_usage() {
  printf
  ("Usage: goldy [-hvd] -g log_level -l listen_host:port -b backend_host:port\n"
   "             -c cert_pem_file -k private_key_pem_file\n" "\n"
   "Options:\n" "  -h, --help                 this help\n"
   "  -v, --version              show version and exit\n"
   "  -d, --daemonize            run as a daemon\n"
   "  -g, --log=log level        log level DEBUG/INFO/ERROR\n"
   "  -l, --listen=ADDR:PORT     listen for incoming DTLS on addr and UDP port\n"
   "  -b, --backend=ADDR:PORT    proxy UDP traffic to addr and port\n"
   "  -c, --cert=FILE            TLS certificate PEM filename\n"
   "  -k, --key=FILE             TLS private key PEM filename\n");
}

/*
 * Parse command line arguments.
 *
 * Returns 1 if all OK or 0 if there's a problem.
 */
static int get_options(int argc, char **argv, struct instance *gi) {
  int opt;
  char *sep;
  static const char *short_options = "hvdb:g:l:c:k:";
  static struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"daemonize", no_argument, NULL, 'd'},
    {"backend", required_argument, NULL, 'b'},
    {"log", optional_argument, NULL, 'g'},
    {"listen", required_argument, NULL, 'l'},
    {"cert", required_argument, NULL, 'c'},
    {"key", required_argument, NULL, 'k'},
    {0, 0, 0, 0}
  };

  memset(gi, 0, sizeof(*gi));

  while ((opt=getopt_long(argc, argv, short_options, long_options,
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
        sep = strchr(optarg, ':');
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

typedef enum {
  GOLDY_GLOBAL_STEP_ACCEPT = 0
} global_step;

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
  int step;
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

static int global_init(const struct instance *gi, global_context *gc) {
  int ret;
  const char *pers = "goldy";

  memset(gc, 0, sizeof(*gc));
  gc->options = gi;
  mbedtls_net_init(&gc->listen_fd);
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

  ret = mbedtls_x509_crt_parse_file(&gc->srvcert, gi->cert_file);
  if (ret != 0) {
    printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n",
           ret);
    goto exit;
  }
  log_debug("Loaded server certificate file");

  ret = mbedtls_pk_parse_keyfile(&gc->pkey, gi->private_key_file, NULL);
  if (ret != 0) {
    printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
    goto exit;
  }
  log_debug("Loaded private key file");

  if ((ret=mbedtls_net_bind(&gc->listen_fd, gi->listen_host, gi->listen_port,
                            MBEDTLS_NET_PROTO_UDP)) != 0) {
    printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
    goto exit;
  }
  log_debug("Binded UDP %s:%s", gi->listen_host, gi->listen_port);
  mbedtls_net_set_nonblock(&gc->listen_fd);
  if ((ret=mbedtls_ctr_drbg_seed(&gc->ctr_drbg, mbedtls_entropy_func,
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
    mbedtls_printf
      (" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n",
       ret);
    goto exit;
  }
  mbedtls_ssl_conf_rng(&gc->conf, mbedtls_ctr_drbg_random,
                       &gc->ctr_drbg);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache(&gc->conf, &gc->cache,
                                 mbedtls_ssl_cache_get,
                                 mbedtls_ssl_cache_set);
#endif

  mbedtls_ssl_conf_ca_chain(&gc->conf, gc->srvcert.next, NULL);
  if ((ret=mbedtls_ssl_conf_own_cert(&gc->conf, &gc->srvcert,
                                     &gc->pkey)) != 0) {
    printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n",
           ret);
    goto exit;
  }
  if ((ret = mbedtls_ssl_cookie_setup(&gc->cookie_ctx,
                                      mbedtls_ctr_drbg_random,
                                      &gc->ctr_drbg)) != 0) {
    printf(" failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n",
           ret);
    goto exit;
  }
  mbedtls_ssl_conf_dtls_cookies(&gc->conf, mbedtls_ssl_cookie_write,
                                mbedtls_ssl_cookie_check,
                                &gc->cookie_ctx);
  log_info("Proxy is ready, listening for connections on UDP %s:%s",
           gi->listen_host, gi->listen_port);

exit:
  check_return_code(ret, "global_init - exit");

  if (ret != 0) {
    global_deinit(gc);
  }
  return ret == 0 ? 0 : 1;
}

typedef enum {
  GOLDY_SESSION_STEP_HANDSHAKE = 0,
  GOLDY_SESSION_STEP_READ,
  GOLDY_SESSION_STEP_SEND_BACKEND,
  GOLDY_SESSION_STEP_RECEIVE_BACKEND,
  GOLDY_SESSION_STEP_WRITE,
  GOLDY_SESSION_STEP_CLOSE_NOTIFY,
  GOLDY_SESSION_STEP_LAST,
} session_step;

typedef struct {
  const struct instance *options;
  mbedtls_net_context client_fd;
  mbedtls_net_context backend_fd;
  mbedtls_ssl_context ssl;
  mbedtls_timing_delay_context timer;
  unsigned char client_ip[16];
  char client_ip_str[INET6_ADDRSTRLEN];
  int client_port;
  size_t cliip_len;
  unsigned char buf[4096];
  size_t len;
  ev_io session_watcher;
  ev_io backend_watcher;
  session_step step;
} session_context;

static void session_dispatch(EV_P_ ev_io *w, int revents);

static int session_deinit(session_context *sc) {
  mbedtls_net_free(&sc->backend_fd);
  mbedtls_net_free(&sc->client_fd);
  mbedtls_ssl_free(&sc->ssl);
  return 0;
}

static int session_init(const global_context *gc,
                            session_context *sc,
                            const mbedtls_net_context *client_fd,
                            unsigned char client_ip[16], size_t cliip_len) {
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
    printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
    goto exit;
  }
  mbedtls_ssl_set_timer_cb(&sc->ssl, &sc->timer,
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

exit:
  check_return_code(ret, "session_init - exit");
  if (ret != 0) {
    session_deinit(sc);
  }
  return ret == 0 ? 0 : 1;
}

static void session_start(session_context *sc, EV_P) {
  ev_io_init(&sc->session_watcher, session_dispatch,
             sc->client_fd.fd, EV_NONE | EV_READ | EV_WRITE);
  sc->session_watcher.data = sc;
  ev_io_start(loop, &sc->session_watcher);
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
  log_info("(%s:%d) Received connection", sc->client_ip_str,
           sc->client_port);
  mbedtls_net_set_nonblock(&sc->client_fd);
  /* For HelloVerifyRequest cookies */
  if ((ret = mbedtls_ssl_set_client_transport_id(&sc->ssl,
                                                 sc->client_ip,
                                                 sc->cliip_len)) == 0) {
    mbedtls_ssl_set_bio(&sc->ssl, &sc->client_fd, mbedtls_net_send,
                        mbedtls_net_recv, mbedtls_net_recv_timeout);
  } else {
    session_report_error(ret, sc, "session_connected");
  }
  return ret == 0 ? 0 : 1;
}

static void session_destruct(int revents, void *arg) {
  session_context *sc = (session_context *) arg;

  (void)revents;
  log_debug("(%s:%d) session_destruct %x", sc->client_ip_str,
            sc->client_port, sc);
  session_deinit(sc);
  free(sc);
}

static void session_defer_destruct(EV_P_ ev_io *w,
                                       session_context *sc) {
  ev_once(loop, -1, 0, 0, session_destruct, sc);
  ev_io_stop(loop, w);
}

static void session_reset(int revents, void *arg) {
  /*
   *the name is misleading - net_free actually shutdown/close the socket but
   *doesn'tfree any resources, hence it can be called repeatedly, even
   *without net_init (which actually does nothing other than set the fd to
   *-1.
   */
  session_context *sc = (session_context *) arg;

  (void)revents;
  log_debug("(%s:%d) session_reset %x", sc->client_ip_str,
            sc->client_port, sc);
  mbedtls_net_free(&sc->client_fd);
  mbedtls_ssl_session_reset(&sc->ssl);
}


static void session_defer_reset(EV_P_ ev_io *w,
                                    session_context *sc) {
  ev_once(loop, -1, 0, 0, session_reset, sc);
  ev_io_stop(loop, w);
}



static void session_step_handshake(EV_P_ ev_io *w,
                                       session_context *sc) {
  int ret = mbedtls_ssl_handshake(&sc->ssl);

  switch (ret) {
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
      return;

    case 0:
      log_debug("(%s:%d) DTLS handshake done", sc->client_ip_str,
                sc->client_port);
      sc->step = GOLDY_SESSION_STEP_READ;
      return;

    case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
      log_debug("(%s:%d) DTLS handshake requested hello verification",
                sc->client_ip_str, sc->client_port);
      return session_defer_reset(loop, w, sc);

    default:
      session_report_error(ret, sc, "session_cb - ssl handshake");
      return session_defer_destruct(loop, w, sc);
  }
}

static void session_step_read(EV_P_ ev_io *w, session_context *sc) {
  int ret;

  sc->len = sizeof(sc->buf) - 1;
  memset(sc->buf, 0, sizeof(sc->buf));

  ret = mbedtls_ssl_read(&sc->ssl, sc->buf, sc->len);
  switch (ret) {
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
      return;

    case MBEDTLS_ERR_SSL_TIMEOUT:
      session_report_error(ret, sc, "session_cb - timeout");
      return session_defer_destruct(loop, w, sc);

    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      session_report_error(ret, sc,
                              "session_cb - gracefully closed");
      sc->step = GOLDY_SESSION_STEP_CLOSE_NOTIFY;
      return;

    default:
      if (ret < 0) {
        session_report_error(ret, sc,
                                "session_cb - unknwon error");
        return session_defer_destruct(loop, w, sc);
      } else {
        sc->len = ret;
        log_debug("(%s:%d) %d bytes read from DTLS socket",
                  sc->client_ip_str, sc->client_port, ret);
        ret = mbedtls_net_connect(&sc->backend_fd,
                                  sc->options->backend_host,
                                  sc->options->backend_port,
                                  MBEDTLS_NET_PROTO_UDP);
        if (ret != 0) {
          session_report_error(ret, sc, "session_step_send_backend");
          return session_defer_destruct(loop, w, sc);
        }
        mbedtls_net_set_nonblock(&sc->backend_fd);
        log_info("Created socket to backend UDP %s:%s",sc->options->backend_host, sc->options->backend_port);
        ev_io_init(&sc->backend_watcher, session_dispatch,
                   sc->backend_fd.fd, EV_READ | EV_WRITE);
        sc->backend_watcher.data = sc;
        ev_io_start(loop,&sc->backend_watcher);

        sc->step = GOLDY_SESSION_STEP_SEND_BACKEND;
        return;
      }
  }
}

static void session_step_send_backend(EV_P_ ev_io *w,session_context *sc) {
  int ret = mbedtls_net_send(&sc->backend_fd, sc->buf, sc->len);
  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return;
  }
  if (ret < 0) {
    session_report_error(ret, sc, "session_step_send_backend");
    return session_defer_destruct(loop, w, sc);
  }
  log_debug("(%s:%d) %d bytes sent to backend server",
            sc->client_ip_str, sc->client_port, ret);
  sc->step = GOLDY_SESSION_STEP_RECEIVE_BACKEND;
  return;
}

static void session_step_receive_backend(EV_P_ ev_io *w,
                                             session_context *sc) {
  int ret;

  sc->len = sizeof(sc->buf) - 1;
  memset(sc->buf, 0, sizeof(sc->buf));
  ret = mbedtls_net_recv(&sc->backend_fd, sc->buf, sc->len);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
    return;
  }
  if (ret < 0) {
    session_report_error(ret, sc, "session_step_send_backend");
    return session_defer_destruct(loop, w, sc);
  }
  log_debug("(%s:%d) %d bytes received from backend server",
            sc->client_ip_str, sc->client_port, ret);
  sc->len = ret;
  ev_io_stop(loop,&sc->backend_watcher);
  sc->step = GOLDY_SESSION_STEP_WRITE;
}


static void session_step_write(EV_P_ ev_io *w,
                                   session_context *sc) {
  int ret = mbedtls_ssl_write(&sc->ssl, sc->buf, sc->len);

  switch (ret) {
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
      return;

    default:
      if (ret < 0) {
        session_report_error(ret, sc,
                                "session_cb - write error");
        return session_defer_destruct(loop, w, sc);
      }
      /* ret is the written len */
      log_debug("(%s:%d) %d bytes written to DTLS socket",
                sc->client_ip_str, sc->client_port, ret);
      sc->step = GOLDY_SESSION_STEP_CLOSE_NOTIFY;
      return;
  }

}

static void session_step_close_notify(EV_P_ ev_io *w,
                                          session_context *sc) {
  int ret = mbedtls_ssl_close_notify(&sc->ssl);

  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return;
  }
  session_defer_destruct(loop, w, sc);
}

typedef void (*session_step_cb) (EV_P_ ev_io *w,
                                  session_context *sc);

static session_step_cb session_callbacks[GOLDY_SESSION_STEP_LAST] = {
  session_step_handshake,
  session_step_read,
  session_step_send_backend,
  session_step_receive_backend,
  session_step_write,
  session_step_close_notify,
};

static void session_dispatch(EV_P_ ev_io *w, int revents) {
  session_context *sc = (session_context *) w->data;

  log_debug("session_dispatch events:%x step:%d", revents, sc->step);
  session_callbacks[sc->step] (loop, w, sc);
}

static void bind_listen_fd(EV_P_ ev_io *w, global_context *gc) {
  ev_io_init(w, global_cb, gc->listen_fd.fd,
             EV_NONE | EV_READ | EV_WRITE);
  w->data = gc;
  ev_io_start(loop, w);
}

static void global_cb(EV_P_ ev_io *w, int revents) {
  global_context *gc = (global_context *) w->data;
  int ret = 0;

  (void)revents;
  if (gc->step == GOLDY_GLOBAL_STEP_ACCEPT) {
    mbedtls_net_context client_fd;
    unsigned char client_ip[16];
    size_t cliip_len;

    mbedtls_net_init(&client_fd);
    if ((ret = mbedtls_net_accept(&gc->listen_fd, &client_fd,
                                  client_ip, sizeof(client_ip),
                                  &cliip_len)) != 0) {
      return;
    }
    session_context *sc = malloc(sizeof(session_context));

    session_init(gc, sc, &client_fd, client_ip, cliip_len);

    if (session_connected(sc) != 0) {
      log_error("can't init client connection");
      free(sc);
      return;
    }
    /*
     *mbedtls_net_accept replaces the listening sock :) So we need to bind
     *it again to libev
     */
    ev_io_stop(loop, w);
    bind_listen_fd(loop, w, gc);
    mbedtls_net_set_nonblock(&gc->listen_fd);
    session_start(sc,loop);
   return;
  }
}


static int main_loop(global_context *gc) {
  struct ev_loop *loop = ev_default_loop(0);
  ev_io global_watcher;


  log_info("main_loop - start");
  bind_listen_fd(loop, &global_watcher, gc);
  ev_loop(loop, 0);

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
