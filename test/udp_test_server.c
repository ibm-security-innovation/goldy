#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "ev.h"

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
  snprintf(line + len, sizeof(line), "udp_test_server(PID=%d): %s\n", getpid(), format);
  vprintf(line, arglist);
  va_end(arglist);
  fflush(stdout);
}

static void reverse_in_place(char *buf, int len) {
  int i;
  for (i = 0; i < len / 2; i++) {
    char tmp = buf[i];
    buf[i] = buf[len - i - 1];
    buf[len - i - 1] = tmp;
  }
}

typedef struct {
  int fd;
  struct sockaddr_in peer_addr;
  int client_port;
  char client_ip_str[100];
  char buf[10000];
  ssize_t recv_len;
  ev_timer send_response_timer;
} session_context;

static void send_response_callback(EV_P_ ev_timer *w, int revents) {
  session_context *session;
  ssize_t sent_len;

  (void)loop;
  assert(revents & EV_TIMER);
  session = w->data;

  reverse_in_place(session->buf, session->recv_len);
  sent_len = sendto(session->fd, session->buf, session->recv_len, 0,
                    (struct sockaddr *)&session->peer_addr, sizeof(session->peer_addr));
  if (sent_len < 0) {
    plog("ERROR in sendto() - returned %d", sent_len);
  } else if (sent_len != session->recv_len) {
    plog("ERROR in sendto() - sent only %d out of %d bytes", sent_len, session->recv_len);
  } else {
    plog("Sent to   %s:%d - '%s'", session->client_ip_str, session->client_port, session->buf);
  }

  ev_timer_stop(loop, w);
  free(session);
  /* Must not use 'w' here because it points to the freed memory */
}

static int is_buffer_noreply(const char *buf) {
  return (strncmp("noreply", buf, 7) == 0);
}

static ev_tstamp get_delay_ms_from_buffer(const char *buf) {
  long delay_ms;

  if (strncmp("serverdelay=", buf, 12) != 0) {
    return 0.0;
  }
  delay_ms = atol(buf + 12);
  if (delay_ms < 0) {
    return 0.0;
  }
  return (ev_tstamp) delay_ms / 1000.0;
}

static void handle_udp_packet(EV_P_ ev_io *w, int revents) {
  char buf[10000];
  struct sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  ssize_t recv_len;
  int client_port;
  char client_ip_str[100];
  session_context *session;
  ev_tstamp response_delay;

  assert(revents & EV_READ);
  recv_len = recvfrom(w->fd, buf, sizeof(buf) - 1, 0,
                      (struct sockaddr *)&peer_addr, &peer_addr_len);
  if (recv_len < 0) {
    plog("Weird! handle_udp_packet called but recvfrom() failed (returned %d)", recv_len);
    return;
  }
  buf[recv_len] = '\0';

  client_port = ntohs(peer_addr.sin_port);
  inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip_str, sizeof(client_ip_str));
  plog("Recv from %s:%d - '%s'", client_ip_str, client_port, buf);

  if (is_buffer_noreply(buf)) {
    /* The client's packet started with "noreply", so we're not preparing a
     * session and scheduling a response. */
    return;
  }

  session = calloc(1, sizeof(session_context));
  session->fd = w->fd;
  memcpy(&session->peer_addr, &peer_addr, sizeof(session->peer_addr));
  session->client_port = client_port;
  strncpy(session->client_ip_str, client_ip_str, sizeof(session->client_ip_str));
  memcpy(session->buf, buf, recv_len + 1);
  session->recv_len = recv_len;

  response_delay = get_delay_ms_from_buffer(buf);

  ev_timer_init(&session->send_response_timer, send_response_callback, response_delay, 0.0);
  session->send_response_timer.data = session;
  ev_timer_start(loop, &session->send_response_timer);
}

static void print_usage(const char *argv0) {
  printf("Usage: %s -p port\n", argv0);
  exit(1);
}

int main(int argc, char *argv[]) {
  int port = -1;
  struct sockaddr_in bind_addr;
  int bind_fd, opt;
  struct ev_loop *loop;
  ev_io w;

  while ((opt = getopt(argc, argv, "p:")) != -1) {
    switch (opt) {
      case 'p':                /* -p PORT */
        port = atoi(optarg);
        break;
      default:                 /* '?' */
        print_usage(argv[0]);
    }
  }

  if (port < 0) {
    print_usage(argv[0]);
  }

  bind_fd = socket(PF_INET, SOCK_DGRAM, 0);
  bzero(&bind_addr, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(port);
  bind_addr.sin_addr.s_addr = INADDR_ANY;       /* TODO: listen on localhost */
  if (bind(bind_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
    perror("bind");
  }

  fcntl(bind_fd, F_SETFL, fcntl(bind_fd, F_GETFL) | O_NONBLOCK);

  plog("Listening for UDP on port %d...", port);

  loop = ev_default_loop(0);
  ev_io_init(&w, handle_udp_packet, bind_fd, EV_READ);
  ev_io_start(loop, &w);
  ev_loop(loop, 0);

  /* Not reachable */
  close(bind_fd);
  return EXIT_SUCCESS;
}
