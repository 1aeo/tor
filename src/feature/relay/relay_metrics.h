/* Copyright (c) 2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_metrics.h
 * @brief Header for feature/relay/relay_metrics.c
 **/

#ifndef TOR_FEATURE_RELAY_RELAY_METRICS_H
#define TOR_FEATURE_RELAY_RELAY_METRICS_H

#include "lib/container/smartlist.h"
#include "lib/metrics/metrics_common.h"

/** Metrics key for each reported metrics. This key is also used as an index in
 * the base_metrics array. */
typedef enum {
  /** Number of OOM invocation. */
  RELAY_METRICS_NUM_OOM_BYTES,
  /** Number of onionskines handled. */
  RELAY_METRICS_NUM_ONIONSKINS,
  /** Number of sockets. */
  RELAY_METRICS_NUM_SOCKETS,
  /** Number of global connection rate limit. */
  RELAY_METRICS_NUM_GLOBAL_RW_LIMIT,
  /** Number of DNS queries. */
  RELAY_METRICS_NUM_DNS,
  /** Number of DNS query errors. */
  RELAY_METRICS_NUM_DNS_ERRORS,
  /** Number of TCP exhaustion reached. */
  RELAY_METRICS_NUM_TCP_EXHAUSTION,
  /** Connections counters (always going up). */
  RELAY_METRICS_CONN_COUNTERS,
  /** Connections gauges. */
  RELAY_METRICS_CONN_GAUGES,
  /** Number of streams. */
  RELAY_METRICS_NUM_STREAMS,
  /** Congestion control counters. */
  RELAY_METRICS_CC_COUNTERS,
  /** Congestion control gauges. */
  RELAY_METRICS_CC_GAUGES,
  /** Denial of Service defenses subsystem. */
  RELAY_METRICS_NUM_DOS,
  /** Denial of Service defenses subsystem. */
  RELAY_METRICS_NUM_TRAFFIC,
  /** Relay flags. */
  RELAY_METRICS_RELAY_FLAGS,
  /** Numer of circuits. */
  RELAY_METRICS_NUM_CIRCUITS,
  /** Timestamp at which the current online keys will expire. */
  RELAY_METRICS_SIGNING_CERT_EXPIRY,
  /** Number of times we received an EST_REND cell */
  RELAY_METRICS_NUM_EST_REND,
  /** Number of times we received an EST_INTRO cell */
  RELAY_METRICS_NUM_EST_INTRO,
  /** Number of times we received an INTRO1 cell */
  RELAY_METRICS_NUM_INTRO1_CELLS,
  /** Number of times we received a REND1 cell */
  RELAY_METRICS_NUM_REND1_CELLS,
  /** Number of circuit closed by receiving a DESTROY cell. */
  RELAY_METRICS_CIRC_DESTROY_CELL,
  /** Number of circuits closed due to protocol violation. */
  RELAY_METRICS_CIRC_PROTO_VIOLATION,
  /** Number of drop cell seen. */
  RELAY_METRICS_CIRC_DROP_CELL,
  /** Onion service descriptor fetches, by outcome. */
  RELAY_METRICS_NUM_HSDIR_GET,
  /** Onion service descriptor uploads, by outcome. */
  RELAY_METRICS_NUM_HSDIR_POST,
  /** Tunneled directory requests, by type. */
  RELAY_METRICS_NUM_BEGINDIR_REQUESTS,
  /** Tunneled directory responses handed to their stream, by type. */
  RELAY_METRICS_NUM_BEGINDIR_RESPONSES,
  /** Open tunneled directory server connections, by state. */
  RELAY_METRICS_BEGINDIR_CONNS,
} relay_metrics_key_t;

/** The metadata of a relay metric. */
typedef struct relay_metrics_entry_t {
  /* Metric key used as a static array index. */
  relay_metrics_key_t key;
  /* Metric type. */
  metrics_type_t type;
  /* Metrics output name. */
  const char *name;
  /* Metrics output help comment. */
  const char *help;
  /* Update value function. */
  void (*fill_fn)(void);
} relay_metrics_entry_t;

/* Init. */
void relay_metrics_init(void);
void relay_metrics_free(void);

/* Accessors. */
const smartlist_t *relay_metrics_get_stores(void);

typedef enum {
  EST_INTRO_SUCCESS,
  EST_INTRO_MALFORMED,
  EST_INTRO_UNSUITABLE_CIRCUIT,
  EST_INTRO_CIRCUIT_DEAD,

  EST_INTRO_ACTION_COUNT
} est_intro_action_t;

void relay_increment_est_intro_action(est_intro_action_t);

typedef enum {
  EST_REND_SUCCESS,
  EST_REND_UNSUITABLE_CIRCUIT,
  EST_REND_SINGLE_HOP,
  EST_REND_MALFORMED,
  EST_REND_DUPLICATE_COOKIE,
  EST_REND_CIRCUIT_DEAD,

  EST_REND_ACTION_COUNT
} est_rend_action_t;

void relay_increment_est_rend_action(est_rend_action_t);

typedef enum {
  INTRO1_SUCCESS,
  INTRO1_CIRCUIT_DEAD,
  INTRO1_MALFORMED,
  INTRO1_UNKNOWN_SERVICE,
  INTRO1_RATE_LIMITED,
  INTRO1_CIRCUIT_REUSED,
  INTRO1_SINGLE_HOP,

  INTRO1_ACTION_COUNT
} intro1_action_t;

void relay_increment_intro1_action(intro1_action_t);

typedef enum {
  REND1_SUCCESS,
  REND1_UNSUITABLE_CIRCUIT,
  REND1_MALFORMED,
  REND1_UNKNOWN_COOKIE,
  REND1_CIRCUIT_DEAD,

  REND1_ACTION_COUNT
} rend1_action_t;

void relay_increment_rend1_action(rend1_action_t);

/** Outcome of an onion service descriptor fetch (GET /tor/hs/3/). */
typedef enum {
  /** Found in our cache and queued: 200. */
  HSDIR_GET_SUCCESS,
  /** Not in our cache, or not a valid blinded key: 404. */
  HSDIR_GET_NOT_FOUND,
  /** Not over an anonymous circuit, because the previous hop never
   * authenticated (see connection_dir_is_anonymous()): 503. */
  HSDIR_GET_SINGLE_HOP,
  /** Refused, closing the circuit without an answer: the second HSDir
   * request on its circuit, or one HSDirRefuseUnknownPrevHop refused. */
  HSDIR_GET_REFUSED,

  HSDIR_GET_ACTION_COUNT
} hsdir_get_action_t;

void relay_increment_hsdir_get_action(hsdir_get_action_t);

/** Outcome of an onion service descriptor upload (POST /tor/hs/). */
typedef enum {
  /** Stored: 200. */
  HSDIR_POST_SUCCESS,
  /** Unsupported version or command in the URL: 400. */
  HSDIR_POST_BAD_URL,
  /** Descriptor didn't parse or validate: 400. */
  HSDIR_POST_INVALID,
  /** Valid descriptor, but its revision counter is not greater than the one
   * we have cached: 400. This happens without any fault when several
   * instances publish for the same onion address. */
  HSDIR_POST_NOT_NEWER,
  /** Not over an anonymous circuit, because the previous hop never
   * authenticated (see connection_dir_is_anonymous()): 503. */
  HSDIR_POST_SINGLE_HOP,
  /** Refused, closing the circuit without an answer: the second HSDir
   * request on its circuit, or one HSDirRefuseUnknownPrevHop refused. */
  HSDIR_POST_REFUSED,

  HSDIR_POST_ACTION_COUNT
} hsdir_post_action_t;

void relay_increment_hsdir_post_action(hsdir_post_action_t);

/** What a tunneled (BEGIN_DIR) directory request asked for. */
typedef enum {
  /** GET /tor/hs/3/: an onion service descriptor fetch. */
  DIR_REQUEST_HS_GET,
  /** POST /tor/hs/: an onion service descriptor upload. */
  DIR_REQUEST_HS_POST,
  /** GET /tor/status-vote/current/consensus: a consensus. */
  DIR_REQUEST_CONSENSUS,
  /** GET /tor/micro/d/: microdescriptors. */
  DIR_REQUEST_MICRODESC,
  /** GET /tor/server/ or /tor/extra/: relay descriptors. */
  DIR_REQUEST_DESCRIPTOR,
  /** Any other GET that parsed, including those we answer with 404. */
  DIR_REQUEST_OTHER_GET,
  /** Any other POST, including every POST to a relay that isn't public. */
  DIR_REQUEST_OTHER_POST,
  /** A request that didn't parse, was too large or had an unknown method, or
   * the start of one when the connection timed out. */
  DIR_REQUEST_UNPARSED,
  /** Nothing at all before the stream or the connection closed. */
  DIR_REQUEST_NO_REQUEST,
  /** A request, or the start of one, that we didn't read because its stream
   * or circuit was already closing. */
  DIR_REQUEST_CIRCUIT_DEAD,

  DIR_REQUEST_TYPE_COUNT
} dir_request_type_t;

struct dir_connection_t;
void relay_note_dir_request(struct dir_connection_t *conn,
                            dir_request_type_t type);
void relay_note_dir_response(const struct dir_connection_t *conn);

#endif /* !defined(TOR_FEATURE_RELAY_RELAY_METRICS_H) */
