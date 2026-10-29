/* Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics.c
 * @brief Metrics subsystem.
 **/

#define METRICS_PRIVATE

#include "orconfig.h"

#include "core/or/or.h"

#include "lib/encoding/confline.h"
#include "lib/evloop/compat_libevent.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/metrics/metrics_store.h"
#include "lib/net/resolve.h"
#include "lib/net/socket.h"
#include "lib/string/printf.h"
#include "lib/net/nettypes.h"
#include "lib/net/address.h"

#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/or/connection_or.h"
#include "core/or/connection_st.h"
#include "core/or/policies.h"
#include "core/or/port_cfg_st.h"
#include "core/proto/proto_http.h"

#include "feature/dircommon/directory.h"
#include "feature/metrics/metrics.h"

#include "app/config/config.h"
#include "app/main/subsysmgr.h"

#ifdef _WIN32
#define tor_poll(f, n, t) ((n) ? WSAPoll((f), (n), (t)) : (Sleep(t), 0))
#define TOR_SHUT_RD SD_RECEIVE
#else
#include <poll.h>
#define tor_poll(f, n, t) poll((f), (n), (t))
#define TOR_SHUT_RD SHUT_RD
#endif

/** Metrics format driver set by the MetricsPort option. */
static metrics_format_t the_format = METRICS_FORMAT_PROMETHEUS;

/** Return true iff the given peer address is allowed by our MetricsPortPolicy
 * option that is is in that list. */
static bool
metrics_request_allowed(const tor_addr_t *peer_addr)
{
  tor_assert(peer_addr);

  return metrics_policy_permits_address(peer_addr);
}

/** Helper: Return a newly allocated buffer holding the whole MetricsPort HTTP
 * response: headers followed by the output of all subsystems. */
static buf_t *
metrics_get_http_response(void)
{
  char date[RFC1123_TIME_LEN+1];
  buf_t *data = metrics_get_output(the_format);
  const size_t data_len = buf_datalen(data);
  buf_t *buf = buf_new_with_capacity(128 + data_len);

  format_rfc1123_time(date, approx_time());
  buf_add_printf(buf, "HTTP/1.0 200 OK\r\nDate: %s\r\n", date);
  buf_add_printf(buf, "Content-Type: text/plain; charset=utf-8\r\n");
  buf_add_printf(buf, "Content-Length: %" TOR_PRIuSZ "\r\n", data_len);
  buf_add_string(buf, "\r\n");
  buf_move_all(buf, data);

  buf_free(data);
  return buf;
}

/** Helper: Return NULL if <b>headers</b> starts with a GET /metrics request,
 * else the HTTP error response to send back. */
static const char *
metrics_check_http_request(const char *headers)
{
  char *command = NULL, *url = NULL;
  const char *errmsg = NULL;

  if (parse_http_command(headers, &command, &url) < 0) {
    errmsg = "HTTP/1.0 400 Bad Request\r\n\r\n";
  } else if (strcmp(command, "GET")) {
    errmsg = "HTTP/1.0 405 Method Not Allowed\r\n\r\n";
  } else if (strcmp(url, "/metrics")) {
    errmsg = "HTTP/1.0 404 Not Found\r\n\r\n";
  }

  tor_free(command);
  tor_free(url);
  return errmsg;
}

/** Return newly allocated buffer containing the output of all subsystems
 * having metrics.
 *
 * This is used to output the content on the MetricsPort. */
buf_t *
metrics_get_output(const metrics_format_t fmt)
{
  buf_t *data = buf_new();

  /* Go over all subsystems that exposes a metrics store. */
  for (unsigned i = 0; i < n_tor_subsystems; ++i) {
    const smartlist_t *stores;
    const subsys_fns_t *sys = tor_subsystems[i];

    /* Skip unsupported subsystems. */
    if (!sys->supported) {
      continue;
    }

    if (sys->get_metrics && (stores = sys->get_metrics())) {
      SMARTLIST_FOREACH_BEGIN(stores, const metrics_store_t *, store) {
        metrics_store_get_output(fmt, store, data);
      } SMARTLIST_FOREACH_END(store);
    }
  }

  return data;
}

/** Process what is in the inbuf of this connection of type metrics.
 *
 * Return 0 on success else -1 on error for which the connection is marked for
 * close. */
int
metrics_connection_process_inbuf(connection_t *conn)
{
  int ret = -1;
  char *headers = NULL;
  const char *errmsg = NULL;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_METRICS);

  if (!metrics_request_allowed(&conn->addr)) {
    /* Close connection. Don't bother returning anything if you are not
     * allowed by being on the policy list. */
    errmsg = NULL;
    goto err;
  }

  const int http_status =
    connection_fetch_from_buf_http(conn, &headers, 1024, NULL, NULL, 1024, 0);
  if (http_status < 0) {
    errmsg = "HTTP/1.0 400 Bad Request\r\n\r\n";
    goto err;
  } else if (http_status == 0) {
    /* no HTTP request yet. */
    ret = 0;
    goto done;
  }

  errmsg = metrics_check_http_request(headers);
  if (errmsg) {
    goto err;
  }

  buf_t *data = metrics_get_http_response();
  connection_buf_add_buf(conn, data);
  buf_free(data);

  ret = 0;
  goto done;

 err:
  if (errmsg) {
    log_info(LD_EDGE, "HTTP metrics error: saying %s", escaped(errmsg));
    connection_buf_add(errmsg, strlen(errmsg), conn);
  }
  connection_mark_and_flush(conn);

 done:
  tor_free(headers);

  return ret;
}

/** Seconds that a MetricsPort worker client has to complete its request. */
#define METRICS_WORKER_TIMEOUT 10

/** Mutex protecting worker_* state shared between main and worker threads. */
static tor_mutex_t *worker_mutex = NULL;
/** Active MetricsPort listener socket, or TOR_INVALID_SOCKET. */
static tor_socket_t worker_listener = TOR_INVALID_SOCKET;
/** Latest metrics_get_http_response() snapshot and its byte length. */
static char *worker_response = NULL;
static size_t worker_response_len = 0;
/** True while the MetricsPort worker thread is running. */
static bool worker_running = false;
/** Main-loop event refreshing worker_response once per second. */
static mainloop_event_t *worker_ev = NULL;

/** Wait up to 1s for <b>events</b> on <b>s</b> with worker_mutex released.
 * Return 1 if ready, 0 on timeout/EINTR, or -1 on error/hangup. */
static int
worker_wait(tor_socket_t s, short events)
{
  struct pollfd pfd = { .fd = s, .events = events };
  tor_mutex_release(worker_mutex);
  const int r = tor_poll(&pfd, SOCKET_OK(s) ? 1 : 0,
                         SOCKET_OK(s) ? 200 : 1000);
  const int e = r < 0 ? tor_socket_errno(-1) : 0;
  tor_mutex_acquire(worker_mutex);
  if (r < 0)
    return ERRNO_IS_EINTR(e) ? 0 : -1;
  if (r > 0 && (pfd.revents & events))
    return 1;
  return (r > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) ? -1 : 0;
}

/** Accept one client on <b>listener</b> and serve worker_response.
 * Called with worker_mutex held. */
static void
metrics_worker_serve(tor_socket_t listener)
{
  struct sockaddr_storage ss = {0};
  socklen_t ss_len = sizeof(ss);
  tor_addr_t addr;
  char req[1024], *out = NULL;
  const char *errmsg = NULL;
  size_t len = 0, out_len = 0;
  const time_t deadline = time(NULL) + METRICS_WORKER_TIMEOUT;

  const tor_socket_t s = tor_accept_socket_nonblocking_unlimited(
      listener, (struct sockaddr *)&ss, &ss_len);
  if (!SOCKET_OK(s)) {
    if (ERRNO_IS_RESOURCE_LIMIT(tor_socket_errno(listener)))
      worker_wait(TOR_INVALID_SOCKET, 0);
    return;
  }
  if (tor_addr_from_sockaddr(&addr, (struct sockaddr *)&ss, NULL) < 0 ||
      !metrics_request_allowed(&addr)) {
    goto done;
  }

  while (!tor_memstr(req, len, "\r\n\r\n")) {
    if (len == sizeof(req) - 1) {
      errmsg = "HTTP/1.0 400 Bad Request\r\n\r\n";
      break;
    }
    int w = (time(NULL) < deadline && listener == worker_listener) ?
            worker_wait(s, POLLIN) : -1;
    if (w <= 0) {
      if (w < 0)
        goto done;
      continue;
    }
    ssize_t n = tor_socket_recv(s, req + len, sizeof(req) - 1 - len, 0);
    int e = n < 0 ? tor_socket_errno(s) : 0;
    if (n < 0 && (ERRNO_IS_EAGAIN(e) || ERRNO_IS_EINTR(e)))
      continue;
    if (n <= 0)
      goto done;
    len += (size_t)n;
  }
  req[len] = '\0';

  if (!errmsg)
    errmsg = metrics_check_http_request(req);
  if (!errmsg && !worker_response)
    goto done;
  out_len = errmsg ? strlen(errmsg) : worker_response_len;
  out = tor_memdup(errmsg ? errmsg : worker_response, out_len);
  for (len = 0; len < out_len; ) {
    int w = (time(NULL) < deadline && listener == worker_listener) ?
            worker_wait(s, POLLOUT) : -1;
    if (w <= 0) {
      if (w < 0)
        break;
      continue;
    }
    ssize_t n = tor_socket_send(s, out + len, out_len - len, 0);
    int e = n < 0 ? tor_socket_errno(s) : 0;
    if (n < 0 && !(ERRNO_IS_EAGAIN(e) || ERRNO_IS_EINTR(e)))
      break;
    if (n > 0)
      len += (size_t)n;
  }

 done:
  for (int i = 0; out && i < 4 &&
       tor_socket_recv(s, req, sizeof(req), 0) == (ssize_t)sizeof(req); ++i) {
  }
  tor_free(out);
  tor_close_socket(s);
}

/** Worker thread loop: serve clients while worker_listener is open. */
static void
metrics_worker_main(void *arg)
{
  (void) arg;
  tor_mutex_acquire(worker_mutex);
  while (SOCKET_OK(worker_listener)) {
    const tor_socket_t listener = worker_listener;
    if (worker_wait(listener, POLLIN) > 0 && listener == worker_listener &&
        worker_response) {
      metrics_worker_serve(listener);
    }
  }
  worker_running = false;
  tor_mutex_release(worker_mutex);
}

/** Main-thread callback: refresh worker_response and spawn the worker thread
 * once privilege drop and sandbox initialization have completed. */
STATIC void
metrics_worker_refresh(mainloop_event_t *ev, void *arg)
{
  static const struct timeval one_second = { 1, 0 };
  (void) arg;
  if (!SOCKET_OK(worker_listener))
    return;
  buf_t *buf = metrics_get_http_response();
  size_t len;
  char *response = buf_extract(buf, &len);
  buf_free(buf);

  tor_mutex_acquire(worker_mutex);
  tor_free(worker_response);
  worker_response = response;
  worker_response_len = len;
  if (!worker_running)
    worker_running = (spawn_func(metrics_worker_main, NULL) == 0);
  bool ok = worker_running;
  tor_mutex_release(worker_mutex);

  if (!ok) {
    log_warn(LD_BUG, "Unable to start MetricsPort worker; using main loop.");
    connection_t *c = connection_get_by_type(CONN_TYPE_METRICS_LISTENER);
    if (c)
      connection_start_reading(c);
    worker_listener = TOR_INVALID_SOCKET;
    tor_free(worker_response);
    mainloop_event_free(worker_ev);
    return;
  }
  if (ev)
    mainloop_event_schedule(ev, &one_second);
}

/** Hand the MetricsPort listener <b>conn</b> to the worker thread. */
void
metrics_configure_listener(connection_t *conn)
{
  tor_assert(conn);
  if (!worker_mutex)
    worker_mutex = tor_mutex_new_nonrecursive();
  tor_mutex_acquire(worker_mutex);
  worker_listener = conn->s;
  tor_mutex_release(worker_mutex);
  if (!worker_ev)
    worker_ev = mainloop_event_new(metrics_worker_refresh, NULL);
  mainloop_event_activate(worker_ev);
}

/** Stop serving <b>conn</b> (or any listener if NULL) on the worker thread. */
void
metrics_close_listener(const connection_t *conn)
{
  if (!worker_mutex || (conn && conn->type != CONN_TYPE_METRICS_LISTENER))
    return;
  bool clear = false;
  tor_mutex_acquire(worker_mutex);
  const tor_socket_t s = conn ? conn->s : worker_listener;
  if (SOCKET_OK(s))
    shutdown(s, TOR_SHUT_RD);
  if (!conn || s == worker_listener) {
    worker_listener = TOR_INVALID_SOCKET;
    tor_free(worker_response);
    worker_response_len = 0;
    clear = true;
  }
  tor_mutex_release(worker_mutex);
  if (clear)
    mainloop_event_free(worker_ev);
}

/** Parse metrics ports from options. On success, add the port to the ports
 * list and return 0. On failure, set err_msg_out to a newly allocated string
 * describing the problem and return -1. */
int
metrics_parse_ports(or_options_t *options, smartlist_t *ports,
                    char **err_msg_out)
{
  int num_elems, ok = 0, ret = -1;
  const char *addrport_str = NULL, *fmt_str = NULL;
  smartlist_t *elems = NULL;
  port_cfg_t *cfg = NULL;

  tor_assert(options);
  tor_assert(ports);

  /* No metrics port to configure, just move on . */
  if (!options->MetricsPort_lines) {
    return 0;
  }

  elems = smartlist_new();

  /* Split between the protocol and the address/port. */
  num_elems = smartlist_split_string(elems,
                                     options->MetricsPort_lines->value, " ",
                                     SPLIT_SKIP_SPACE | SPLIT_IGNORE_BLANK, 2);
  if (num_elems < 1) {
    *err_msg_out = tor_strdup("MetricsPort is missing port.");
    goto end;
  }

  addrport_str = smartlist_get(elems, 0);
  if (num_elems >= 2) {
    /* Parse the format if any. */
    fmt_str = smartlist_get(elems, 1);
    if (!strcasecmp(fmt_str, "prometheus")) {
      the_format = METRICS_FORMAT_PROMETHEUS;
    } else {
      tor_asprintf(err_msg_out, "MetricsPort unknown format: %s", fmt_str);
      goto end;
    }
  }

  /* Port configuration with default address. */
  cfg = port_cfg_new(0);
  cfg->type = CONN_TYPE_METRICS_LISTENER;

  /* Parse the port first. Then an address if any can be found. */
  cfg->port = (int) tor_parse_long(addrport_str, 10, 0, 65535, &ok, NULL);
  if (ok) {
    tor_addr_parse(&cfg->addr, "127.0.0.1");
  } else {
    /* We probably have a host:port situation */
    if (tor_addr_port_lookup(addrport_str, &cfg->addr,
                             (uint16_t *) &cfg->port) < 0) {
      *err_msg_out = tor_strdup("MetricsPort address/port failed to parse or "
                                "resolve.");
      goto end;
    }
  }
  /* Add it to the ports list. */
  smartlist_add(ports, cfg);

  /* It is set. MetricsPort doesn't support the NoListen options or such that
   * would prevent from being a real listener port. */
  options->MetricsPort_set = 1;

  /* Success. */
  ret = 0;

 end:
  if (ret != 0) {
    port_cfg_free(cfg);
  }
  SMARTLIST_FOREACH(elems, char *, e, tor_free(e));
  smartlist_free(elems);
  return ret;
}

/** Called when conn has gotten its socket closed. */
int
metrics_connection_reached_eof(connection_t *conn)
{
  tor_assert(conn);

  log_info(LD_EDGE, "Metrics connection reached EOF. Closing.");
  connection_mark_for_close(conn);
  return 0;
}

/** Called when conn has no more bytes left on its outbuf. Return 0 indicating
 * success. */
int
metrics_connection_finished_flushing(connection_t *conn)
{
  tor_assert(conn);
  return 0;
}

/** Initialize the subsystem. */
void
metrics_init(void)
{
}

/** Cleanup and free any global memory of this subsystem. */
void
metrics_cleanup(void)
{
  metrics_close_listener(NULL);
}
