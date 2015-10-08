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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>

#include "goldy.h"
#include "daemonize.h"
#include "log.h"

static int connect_to_udp_backend(const char *backend_host, const char* backend_port) {
  struct addrinfo hints;
  struct addrinfo *result;
  struct addrinfo *rp;
  int ret, sfd;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  ret = getaddrinfo(backend_host, backend_port, &hints, &result);
  if (ret != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
    exit(EXIT_FAILURE);
  }

  for (rp = result; rp; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1) {
      continue;
    }

    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
      break; /* Success */
    }

    close(sfd);
  }

  freeaddrinfo(result);

  if (!rp) {
    printf("failed: could not connect to UDP backend\n");
    return -1;
  }

  return sfd;
}

static void print_version() {
  printf("goldy %s\n", GOLDY_VERSION);
}

static void print_usage() {
  printf("Usage: goldy [-hvd] -l listen_host:port -b backend_host:port\n"
         "             -c cert_pem_file -k private_key_pem_file\n"
         "\n"
         "Options:\n"
         "  -h, --help                 this help\n"
         "  -v, --version              show version and exit\n"
         "  -d, --daemonize            run as a daemon\n"
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
  char* sep;
  static const char* short_options = "hvdb:l:c:k:";
  static struct option long_options[] = {
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'v'},
    {"daemonize", no_argument,       NULL, 'd'},
    {"backend", required_argument, NULL, 'b'},
    {"listen",  required_argument, NULL, 'l'},
    {"cert",    required_argument, NULL, 'c'},
    {"key",     required_argument, NULL, 'k'},
    {0, 0, 0, 0}
  };

  memset(gi, 0, sizeof(*gi));

  while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
    switch (opt) {
    case 'h': /* -h, --help */
      print_usage();
      exit(0);
      break;
    case 'v': /* -v, --version */
      print_version();
      exit(0);
      break;
    case 'd': /* -d, --daemonize */
      gi->daemonize = 1;
      break;
    case 'b': /* -b, --backend=S */
      sep = strchr(optarg, ':');
      if (!sep) {
        return 0;
      }
      *sep = '\0';
      gi->backend_host = optarg;
      gi->backend_port = sep + 1;
      break;
    case 'l': /* -l, --listen=S */
      sep = strchr(optarg, ':');
      if (!sep) {
        return 0;
      }
      *sep = '\0';
      gi->listen_host = optarg;
      gi->listen_port = sep + 1;
      break;
    case 'c': /* -c, --cert=S */
      gi->cert_file = optarg;
      break;
    case 'k': /* -k, --key=S */
      gi->private_key_file = optarg;
      break;
    default: /* '?' */
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

static void check_return_code(int ret,const char* label) {
#ifdef MBEDTLS_ERROR_C
  if( ret != 0 )
    {
      char error_buf[100];
      mbedtls_strerror( ret, error_buf, 100 );
      log_error("(%s) Last error was: %d - %s", label, ret, error_buf);
    }
#endif
}

typedef struct {
  int backend_fd;
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

static int global_deinit(global_context *gc) {
  int ret = 0;

  if (gc->backend_fd > 0) {
    shutdown(gc->backend_fd, SHUT_RDWR);
    close(gc->backend_fd);
  }

  mbedtls_net_free( &gc->listen_fd );

  mbedtls_x509_crt_free( &gc->srvcert );
  mbedtls_pk_free( &gc->pkey );
  mbedtls_ssl_config_free( &gc->conf );
  mbedtls_ssl_cookie_free( &gc->cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free( &gc->cache );
#endif
  mbedtls_ctr_drbg_free( &gc->ctr_drbg );
  mbedtls_entropy_free( &gc->entropy );

  return ret == 0 ? 0 : 1;
}

static int global_init(const struct instance *gi, global_context *gc) {
  int ret;
  const char *pers = "goldy";

  memset(gc, 0, sizeof(*gc));
  mbedtls_net_init( &gc->listen_fd );
  mbedtls_ssl_config_init( &gc->conf );
  mbedtls_ssl_cookie_init( &gc->cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init( &gc->cache );
#endif
  mbedtls_x509_crt_init( &gc->srvcert );
  mbedtls_pk_init( &gc->pkey );
  mbedtls_entropy_init( &gc->entropy );
  mbedtls_ctr_drbg_init( &gc->ctr_drbg );

  log_info("Goldy %s starting up", GOLDY_VERSION);

  ret = mbedtls_x509_crt_parse_file(&gc->srvcert, gi->cert_file);
  if( ret != 0 )
    {
      printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
      goto exit;
    }
  log_debug("Loaded server certificate file");

  ret = mbedtls_pk_parse_keyfile(&gc->pkey, gi->private_key_file, NULL);
  if( ret != 0 )
    {
      printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
      goto exit;
    }
  log_debug("Loaded private key file");

  if( ( ret = mbedtls_net_bind( &gc->listen_fd, gi->listen_host, gi->listen_port, MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
      goto exit;
    }
  log_debug("Binded UDP %s:%s", gi->listen_host, gi->listen_port);

  gc->backend_fd = connect_to_udp_backend(gi->backend_host, gi->backend_port);
  log_debug("Created socket to backend UDP %s:%s", gi->backend_host, gi->backend_port);

  if( ( ret = mbedtls_ctr_drbg_seed( &gc->ctr_drbg, mbedtls_entropy_func, &gc->entropy,
                                     (const unsigned char *) pers,
                                     strlen( pers ) ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
      goto exit;
    }
  log_debug("Seeded random number generator");

  if( ( ret = mbedtls_ssl_config_defaults( &gc->conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
      mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
      goto exit;
    }

  mbedtls_ssl_conf_rng( &gc->conf, mbedtls_ctr_drbg_random, &gc->ctr_drbg );

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache( &gc->conf, &gc->cache,
                                  mbedtls_ssl_cache_get,
                                  mbedtls_ssl_cache_set );
#endif

  mbedtls_ssl_conf_ca_chain( &gc->conf, gc->srvcert.next, NULL );
  if( ( ret = mbedtls_ssl_conf_own_cert( &gc->conf, &gc->srvcert, &gc->pkey ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
      goto exit;
    }

  if( ( ret = mbedtls_ssl_cookie_setup( &gc->cookie_ctx,
                                        mbedtls_ctr_drbg_random, &gc->ctr_drbg ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret );
      goto exit;
    }

  mbedtls_ssl_conf_dtls_cookies( &gc->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                 &gc->cookie_ctx );
  log_info("Proxy is ready, listening for connections on UDP %s:%s", gi->listen_host, gi->listen_port);

 exit:
  check_return_code(ret,"global_init - exit");

  global_deinit(gc);
  return ret == 0 ? 0 : 1;
}

typedef struct {
  mbedtls_net_context client_fd;
  mbedtls_ssl_context ssl;
  mbedtls_timing_delay_context timer;
  unsigned char client_ip[16];
  char client_ip_str[INET6_ADDRSTRLEN];
  int client_port;
  size_t cliip_len;

} per_client_context;


static int per_client_deinit(per_client_context *pcc) {
  mbedtls_net_free( &pcc->client_fd );
  mbedtls_ssl_free( &pcc->ssl );
  return 0;
}

static void per_client_reset(per_client_context *pcc) {
  mbedtls_net_free( &pcc->client_fd );
  mbedtls_ssl_session_reset( &pcc->ssl );
}

static int per_client_init(const global_context *gc,per_client_context *pcc) {
  int ret;
  memset(pcc, 0, sizeof(*pcc));
  mbedtls_net_init( &pcc->client_fd );
  mbedtls_ssl_init( &pcc->ssl );

  if( ( ret = mbedtls_ssl_setup( &pcc->ssl, &gc->conf ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
      goto exit;
    }

  mbedtls_ssl_set_timer_cb( &pcc->ssl, &pcc->timer, mbedtls_timing_set_delay,
                            mbedtls_timing_get_delay );


 exit:
  check_return_code(ret,"per_client_init - exit");
  per_client_deinit(pcc);
  return ret == 0 ? 0 : 1;
}

static int main_loop(const struct instance *gi,global_context *gc,per_client_context *pcc) {
  int ret = 0, len;
  unsigned char buf[10000];

 start:
  check_return_code(ret,"main_loop - start");
  per_client_reset(pcc);

  if( ( ret = mbedtls_net_accept( &gc->listen_fd, &pcc->client_fd,
                                  pcc->client_ip, sizeof( pcc->client_ip ), &pcc->cliip_len ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
      goto exit;
    }

  {
    union sockaddr_u {
      struct sockaddr_storage storage;
      struct sockaddr_in in;
      struct sockaddr_in6 in6;
      struct sockaddr sockaddr;
    } addr;
    socklen_t addrlen = sizeof(addr.storage);

    getpeername(pcc->client_fd.fd, &addr.sockaddr, &addrlen);

    /* deal with both IPv4 and IPv6: */
    if (addr.storage.ss_family == AF_INET) {
      struct sockaddr_in *s_ip4 = &addr.in;
      pcc->client_port = ntohs(s_ip4->sin_port);
      inet_ntop(AF_INET, &s_ip4->sin_addr, pcc->client_ip_str, sizeof(pcc->client_ip_str));
    } else {
      struct sockaddr_in6 *s_ip6 = &addr.in6;
      pcc->client_port = ntohs(s_ip6->sin6_port);
      inet_ntop(AF_INET6, &s_ip6->sin6_addr, pcc->client_ip_str, sizeof(pcc->client_ip_str));
    }

    log_info("(%s:%d) Received connection", pcc->client_ip_str, pcc->client_port);
  }

  /* For HelloVerifyRequest cookies */
  if( ( ret = mbedtls_ssl_set_client_transport_id( &pcc->ssl,
                                                   pcc->client_ip, pcc->cliip_len ) ) != 0 )
    {
      printf( " failed\n  ! "
              "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret );
      goto exit;
    }

  mbedtls_ssl_set_bio( &pcc->ssl, &pcc->client_fd,
                       mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );

  do ret = mbedtls_ssl_handshake( &pcc->ssl );
  while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE );

  if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
      log_debug("(%s:%d) DTLS handshake requested hello verification", pcc->client_ip_str, pcc->client_port);
      ret = 0;
      goto start;
    }
  else if( ret != 0 )
    {
      char error_buf[100];
      mbedtls_strerror(ret, error_buf, sizeof(error_buf));
      log_error("(%s:%d) DTLS handshake failed: %s (%d)", pcc->client_ip_str, pcc->client_port, error_buf, ret);
      goto start;
    }

  log_debug("(%s:%d) DTLS handshake done", pcc->client_ip_str, pcc->client_port);

  len = sizeof( buf ) - 1;
  memset( buf, 0, sizeof( buf ) );

  do ret = mbedtls_ssl_read( &pcc->ssl, buf, len );
  while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE );

  if( ret <= 0 )
    {
      switch( ret )
        {
        case MBEDTLS_ERR_SSL_TIMEOUT:
          printf( " timeout\n\n" );
          goto start;

        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
          printf( " connection was closed gracefully\n" );
          ret = 0;
          goto close_notify;

        default:
          printf( " mbedtls_ssl_read returned -0x%x\n\n", -ret );
          goto start;
        }
    }

  len = ret;
  log_debug("(%s:%d) %d bytes read from DTLS socket", pcc->client_ip_str, pcc->client_port, len);

  ret = send(gc->backend_fd, buf, len, 0);
  log_debug("(%s:%d) %d bytes sent to backend server (%s:%s)", pcc->client_ip_str, pcc->client_port, ret,
            gi->backend_host, gi->backend_port);

  /* Wait for response */
  len = sizeof(buf) - 1;
  memset(buf, 0, sizeof(buf));
  ret = recv(gc->backend_fd, buf, len, 0);
  log_debug("(%s:%d) %d bytes received from backend server", pcc->client_ip_str, pcc->client_port, ret);

  len = ret;
  do ret = mbedtls_ssl_write( &pcc->ssl, buf, len );
  while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE );

  if( ret < 0 )
    {
      printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
      goto exit;
    }

  len = ret;
  log_debug("(%s:%d) %d bytes written to DTLS socket", pcc->client_ip_str, pcc->client_port, len);

 close_notify:

  /* No error checking, the connection might be closed already */
  do ret = mbedtls_ssl_close_notify( &pcc->ssl );
  while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
  ret = 0;

  /* TODO: We might receive a close-notify packet from the client at this
   * point; we'd want to swallow it so it doesn't look like a new connection
   * in accept() above. */

  log_debug("(%s:%d) Connection closed", pcc->client_ip_str, pcc->client_port, len);

  goto start;

 exit:
  check_return_code(ret,"main_loop - exit");
  return ret == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
  struct instance gi;
  global_context gc;
  per_client_context pcc;
  int ret = 0;

  log_stderr_open(LOG_INFO);

  if (!get_options(argc, argv, &gi)) {
    print_usage();
    exit(1);
  }

  if ( gi.daemonize ) {
    daemonize(NULL,GOLDY_DAEMON_USER);
  }

  if ( (ret = global_init(&gi,&gc)) != 0 )
    {
      printf("global initialization failed\n");
      goto exit;
    }

  per_client_init(&gc,&pcc);

  main_loop(&gi,&gc,&pcc);

 exit:
  check_return_code(ret,"main - exit");
  global_deinit(&gc);
  return ret == 0 ? 0 : 1;
}
