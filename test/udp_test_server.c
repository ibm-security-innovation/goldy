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

static void handle_udp_packet(EV_P_ ev_io *w, int revents) {
  char buf[10000];
  struct sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  ssize_t recv_len, sent_len;
  int client_port;
  char client_ip_str[100];

  (void)loop;                   /* unused */

  assert(revents & EV_READ);
  recv_len =
    recvfrom(w->fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&peer_addr, &peer_addr_len);
  if (recv_len < 0) {
    plog("Weird! handle_udp_packet called but recvfrom() failed (returned %d)", recv_len);
    return;
  }
  buf[recv_len] = '\0';

  client_port = ntohs(peer_addr.sin_port);
  inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip_str, sizeof(client_ip_str));
  plog("Recv from %s:%d - '%s'", client_ip_str, client_port, buf);

  reverse_in_place(buf, recv_len);
  sent_len = sendto(w->fd, buf, recv_len, 0, (struct sockaddr *)&peer_addr, peer_addr_len);
  if (sent_len < 0) {
    plog("ERROR in sendto() - returned %d", sent_len);
  } else if (sent_len != recv_len) {
    plog("ERROR in sendto() - sent only %d out of %d bytes", sent_len, recv_len);
  } else {
    plog("Sent to   %s:%d - '%s'", client_ip_str, client_port, buf);
  }
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
