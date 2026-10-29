/* Copyright (c) 2016-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_cache.c
 * \brief Test hidden service caches.
 */

#define CONNECTION_PRIVATE
#define DIRCACHE_PRIVATE
#define DIRCLIENT_PRIVATE
#define HS_CACHE_PRIVATE
#define CHANNEL_OBJECT_PRIVATE
#define CIRCUITLIST_PRIVATE

#include "app/config/config.h"
#include "app/config/or_options_st.h"
#include "trunnel/ed25519_cert.h"
#include "feature/hs/hs_cache.h"
#include "feature/dircache/dircache.h"
#include "feature/dirclient/dirclient.h"
#include "feature/dircommon/directory.h"
#include "feature/hs/hs_ident.h"
#include "feature/nodelist/networkstatus.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/proto/proto_http.h"
#include "core/or/circuitlist.h"
#include "core/or/connection_edge.h"
#include "core/or/channel.h"
#include "core/or/dos.h"
#include "feature/relay/relay_metrics.h"
#include "lib/metrics/metrics_store_entry.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/metrics/metrics_store.h"

#include "core/or/edge_connection_st.h"
#include "core/or/dos_options_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/or_connection_st.h"
#include "feature/dircommon/dir_connection_st.h"
#include "feature/nodelist/networkstatus_st.h"
#include "feature/nodelist/routerstatus_st.h"

#include "test/fakechans.h"
#include "test/hs_test_helpers.h"
#include "test/log_test_helpers.h"
#include "test/opts_test_helpers.h"
#include "test/test_helpers.h"
#include "test/test.h"

/* Static variable used to encoded the HSDir query. */
static char query_b64[256];

/* Build an HSDir query using a ed25519 public key. */
static const char *
helper_get_hsdir_query(const hs_descriptor_t *desc)
{
  ed25519_public_to_base64(query_b64, &desc->plaintext_data.blinded_pubkey);
  return query_b64;
}

static void
init_test(void)
{
  /* Always needed. Initialize the subsystem. */
  hs_cache_init();
}

static int
mock_channel_get_addr_if_possible(const channel_t *chan, tor_addr_t *addr_out)
{
  (void) chan;
  (void) addr_out;
  return 0;
}

/* Issue a request on a new stream, then close that stream. Keep the circuit
 * alive so the next request tests its lifetime allowance, not concurrency.
 * Return the HTTP status, or 0 if no response was written. */
static int
hsdir_request_on_circuit(or_circuit_t *circ, const char *headers,
                         const char *body)
{
  int status = -1;
  char *response = NULL;
  size_t response_len;
  dir_connection_t *conn = dir_connection_new(AF_INET);
  edge_connection_t *edge = edge_connection_new(CONN_TYPE_EXIT, AF_INET);

  tor_addr_from_ipv4h(&conn->base_.addr, 0x7f000001);
  conn->base_.address = tor_strdup("127.0.0.1");
  connection_link_connections(TO_CONN(conn), TO_CONN(edge));
  edge->on_circuit = circ ? TO_CIRCUIT(circ) : NULL;

  if (body) {
    tt_int_op(directory_handle_command_post(conn, headers, body, strlen(body)),
              OP_EQ, 0);
  } else {
    tt_int_op(directory_handle_command_get(conn, headers, NULL, 0), OP_EQ, 0);
  }
  response = buf_get_contents(TO_CONN(conn)->outbuf, &response_len);
  tt_assert(response);
  if (response_len == 0) {
    /* No response was written. */
    status = 0;
    goto done;
  }
  tt_int_op(parse_http_response(response, &status, NULL, NULL, NULL),
            OP_EQ, 0);

 done:
  tor_free(response);
  connection_free_minimal(TO_CONN(edge));
  connection_free_minimal(TO_CONN(conn));
  return status;
}

/* Fetches and uploads share one allowance, independent of descriptor key,
 * stream lifetime, or whether we are a directory authority. */
static void
test_hsdir_request_limit(void *arg)
{
  const char *mode = arg;
  const bool post_first = !strcmp(mode, "post");
  const char *post_headers = "POST /tor/hs/3/publish HTTP/1.0\r\n\r\n";
  const char *missing_get = GET("/tor/hs/3/"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  char *get_headers = NULL, *encoded = NULL;
  hs_descriptor_t *desc = NULL;
  ed25519_keypair_t signing_kp;
  channel_t chan = {0};
  or_circuit_t *circ = NULL, *fresh = NULL, *missing = NULL, *invalid = NULL;
  or_circuit_t *client = NULL;
  or_options_t *options = get_options_mutable();
  buf_t *metrics = buf_new();
  char *metrics_output = NULL;
  size_t metrics_len;

  init_test();
  options->ORPort_set = 1;
  options->BridgeRelay = 0;
  options->AuthoritativeDir = !strcmp(mode, "authority");
  options->V3AuthoritativeDir = options->AuthoritativeDir;
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  /* Closing a circuit looks up the fake channel's address. */
  MOCK(channel_get_addr_if_possible, mock_channel_get_addr_if_possible);

  circ = or_circuit_new(0, NULL);
  fresh = or_circuit_new(0, NULL);
  missing = or_circuit_new(0, NULL);
  invalid = or_circuit_new(0, NULL);
  client = or_circuit_new(0, NULL);
  circ->p_chan = fresh->p_chan = missing->p_chan = invalid->p_chan =
    client->p_chan = &chan;
  /* Closing a circuit checks its invariants, which need a valid purpose. */
  circ->base_.purpose = fresh->base_.purpose = missing->base_.purpose =
    invalid->base_.purpose = client->base_.purpose = CIRCUIT_PURPOSE_OR;

  tt_int_op(ed25519_keypair_generate(&signing_kp, 0), OP_EQ, 0);
  desc = hs_helper_build_hs_desc_with_ip(&signing_kp);
  tt_assert(desc);
  tt_int_op(hs_desc_encode_descriptor(desc, &signing_kp, NULL, &encoded),
            OP_EQ, 0);
  tor_asprintf(&get_headers, GET("/tor/hs/3/%s"),
               helper_get_hsdir_query(desc));

  /* Ordinary directory requests do not consume the allowance. */
  tt_int_op(hsdir_request_on_circuit(circ, GET("/tor/robots.txt"), NULL),
            OP_EQ, 200);
  tt_int_op(circ->already_received_hsdir_request, OP_EQ, 0);

  if (post_first) {
    tt_int_op(hsdir_request_on_circuit(circ, post_headers, encoded),
              OP_EQ, 200);
  } else {
    tt_int_op(hs_cache_store_as_dir(encoded), OP_EQ, 0);
    tt_int_op(hsdir_request_on_circuit(circ, get_headers, NULL), OP_EQ, 200);
  }
  tt_int_op(circ->already_received_hsdir_request, OP_EQ, 1);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 0);
  /* A second HSDir request is rejected and closes the circuit. */
  if (post_first) {
    tt_int_op(hsdir_request_on_circuit(circ, get_headers, NULL), OP_EQ, 0);
  } else {
    tt_int_op(hsdir_request_on_circuit(circ, post_headers, encoded), OP_EQ, 0);
  }
  tt_assert(TO_CIRCUIT(circ)->marked_for_close);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 1);

  /* Queued requests on a closing or detached circuit get no HTTP response,
   * and do not count as additional lifetime-limit rejections. */
  tt_int_op(hsdir_request_on_circuit(circ, get_headers, NULL), OP_EQ, 0);
  tt_int_op(hsdir_request_on_circuit(circ, post_headers, encoded), OP_EQ, 0);
  tt_int_op(hsdir_request_on_circuit(NULL, get_headers, NULL), OP_EQ, 0);
  tt_int_op(hsdir_request_on_circuit(NULL, post_headers, encoded), OP_EQ, 0);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 1);

  /* The allowance is per circuit, not per channel or blinded key. */
  tt_int_op(hsdir_request_on_circuit(fresh, get_headers, NULL), OP_EQ, 200);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 1);

  /* Missing descriptors and malformed uploads also consume the allowance. */
  tt_int_op(hsdir_request_on_circuit(missing, missing_get, NULL), OP_EQ, 404);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 1);
  tt_int_op(hsdir_request_on_circuit(missing, get_headers, NULL), OP_EQ, 0);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 2);
  tt_int_op(hsdir_request_on_circuit(invalid, post_headers, ""), OP_EQ, 400);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 2);
  tt_int_op(hsdir_request_on_circuit(invalid, get_headers, NULL), OP_EQ, 0);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 3);

  /* Unauthenticated clients/bridges still cannot fetch or upload at all. */
  channel_mark_client(&chan);
  tt_int_op(hsdir_request_on_circuit(client, get_headers, NULL), OP_EQ, 503);
  tt_int_op(hsdir_request_on_circuit(client, post_headers, encoded),
            OP_EQ, 503);
  tt_int_op(client->already_received_hsdir_request, OP_EQ, 0);
  tt_int_op(hsdir_request_on_circuit(client, GET("/tor/robots.txt"), NULL),
            OP_EQ, 200);
  tt_u64_op(dos_get_num_begindir_hsdir_rejected(), OP_EQ, 3);

  /* HSDir rejections are reported independently of the BEGIN_DIR defenses. */
  tt_u64_op(dos_get_num_begindir_rejected(), OP_EQ, 0);
  tt_u64_op(dos_get_num_begindir_rate_rejected(), OP_EQ, 0);
  setup_capture_of_logs(LOG_NOTICE);
  dos_log_heartbeat();
  expect_log_msg_containing("3 BEGIN_DIR HSDir requests rejected");

  const smartlist_t *stores = relay_metrics_get_stores();
  tt_int_op(smartlist_len(stores), OP_EQ, 1);
  metrics_store_get_output(METRICS_FORMAT_PROMETHEUS,
                           smartlist_get(stores, 0), metrics);
  metrics_output = buf_get_contents(metrics, &metrics_len);
  tt_assert(metrics_output);
  tt_assert(strstr(metrics_output,
                  "tor_relay_dos_total{"
                  "type=\"begindir_hsdir_rejected\"} 3\n"));

 done:
  teardown_capture_of_logs();
  buf_free(metrics);
  tor_free(metrics_output);
  UNMOCK(connection_write_to_buf_impl_);
  UNMOCK(channel_get_addr_if_possible);
  or_circuit_t *circs[] = { circ, fresh, missing, invalid, client };
  for (unsigned i = 0; i < ARRAY_LENGTH(circs); ++i) {
    if (circs[i]) {
      circs[i]->p_chan = NULL;
      circuit_free_(TO_CIRCUIT(circs[i]));
    }
  }
  hs_descriptor_free(desc);
  tor_free(encoded);
  tor_free(get_headers);
  hs_cache_free_all();
}

static void
test_directory(void *arg)
{
  int ret;
  size_t oom_size;
  char *desc1_str = NULL;
  const char *desc_out;
  ed25519_keypair_t signing_kp1;
  hs_descriptor_t *desc1 = NULL;

  (void) arg;

  init_test();
  /* Generate a valid descriptor with normal values. */
  ret = ed25519_keypair_generate(&signing_kp1, 0);
  tt_int_op(ret, OP_EQ, 0);
  desc1 = hs_helper_build_hs_desc_with_ip(&signing_kp1);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, NULL, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);

  /* Very first basic test, should be able to be stored, survive a
   * clean, found with a lookup and then cleaned by our OOM. */
  {
    ret = hs_cache_store_as_dir(desc1_str);
    tt_int_op(ret, OP_EQ, 0);
    /* Re-add, it should fail since we already have it. */
    ret = hs_cache_store_as_dir(desc1_str);
    tt_int_op(ret, OP_EQ, -2);
    /* Try to clean now which should be fine, there is at worst few seconds
     * between the store and this call. */
    hs_cache_clean_as_dir(time(NULL));
    /* We should find it in our cache. */
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    tt_str_op(desc_out, OP_EQ, desc1_str);
    /* Tell our OOM to run and to at least remove a byte which will result in
     * removing the descriptor from our cache. */
    oom_size = hs_cache_handle_oom(1);
    tt_int_op(oom_size, OP_GE, 1);
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Store two descriptors and remove the expiring one only. */
  {
    ed25519_keypair_t signing_kp_zero;
    ret = ed25519_keypair_generate(&signing_kp_zero, 0);
    tt_int_op(ret, OP_EQ, 0);
    hs_descriptor_t *desc_zero_lifetime;
    desc_zero_lifetime = hs_helper_build_hs_desc_with_ip(&signing_kp_zero);
    tt_assert(desc_zero_lifetime);
    desc_zero_lifetime->plaintext_data.revision_counter = 1;
    desc_zero_lifetime->plaintext_data.lifetime_sec = 0;
    char *desc_zero_lifetime_str;
    ret = hs_desc_encode_descriptor(desc_zero_lifetime, &signing_kp_zero,
                                    NULL, &desc_zero_lifetime_str);
    tt_int_op(ret, OP_EQ, 0);

    ret = hs_cache_store_as_dir(desc1_str);
    tt_int_op(ret, OP_EQ, 0);
    ret = hs_cache_store_as_dir(desc_zero_lifetime_str);
    tt_int_op(ret, OP_EQ, 0);
    /* This one should clear out our zero lifetime desc. */
    hs_cache_clean_as_dir(time(NULL));
    /* We should find desc1 in our cache. */
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    tt_str_op(desc_out, OP_EQ, desc1_str);
    /* We should NOT find our zero lifetime desc in our cache. */
    ret = hs_cache_lookup_as_dir(3,
                                 helper_get_hsdir_query(desc_zero_lifetime),
                                 NULL);
    tt_int_op(ret, OP_EQ, 0);
    /* Cleanup our entire cache. */
    oom_size = hs_cache_handle_oom(1);
    tt_int_op(oom_size, OP_GE, 1);
    hs_descriptor_free(desc_zero_lifetime);
    tor_free(desc_zero_lifetime_str);
  }

  /* Throw junk at it. */
  {
    ret = hs_cache_store_as_dir("blah");
    tt_int_op(ret, OP_EQ, -1);
    /* Poor attempt at tricking the decoding. */
    ret = hs_cache_store_as_dir("hs-descriptor 3\nJUNK");
    tt_int_op(ret, OP_EQ, -1);
    /* Undecodable base64 query. */
    ret = hs_cache_lookup_as_dir(3, "blah", NULL);
    tt_int_op(ret, OP_EQ, -1);
    /* Decodable base64 query but wrong ed25519 size. */
    ret = hs_cache_lookup_as_dir(3, "dW5pY29ybg==", NULL);
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Test descriptor replacement with revision counter. */
  {
    char *new_desc_str;

    /* Add a descriptor. */
    ret = hs_cache_store_as_dir(desc1_str);
    tt_int_op(ret, OP_EQ, 0);
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    /* Bump revision counter. */
    desc1->plaintext_data.revision_counter++;
    ret = hs_desc_encode_descriptor(desc1, &signing_kp1, NULL, &new_desc_str);
    tt_int_op(ret, OP_EQ, 0);
    ret = hs_cache_store_as_dir(new_desc_str);
    tt_int_op(ret, OP_EQ, 0);
    /* Look it up, it should have been replaced. */
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    tt_str_op(desc_out, OP_EQ, new_desc_str);
    tor_free(new_desc_str);
  }

 done:
  hs_descriptor_free(desc1);
  tor_free(desc1_str);
}

static void
test_clean_as_dir(void *arg)
{
  size_t ret;
  char *desc1_str = NULL;
  time_t now = time(NULL);
  hs_descriptor_t *desc1 = NULL;
  ed25519_keypair_t signing_kp1;

  (void) arg;

  init_test();

  /* Generate a valid descriptor with values. */
  ret = ed25519_keypair_generate(&signing_kp1, 0);
  tt_int_op(ret, OP_EQ, 0);
  desc1 = hs_helper_build_hs_desc_with_ip(&signing_kp1);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, NULL, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);
  ret = hs_cache_store_as_dir(desc1_str);
  tt_int_op(ret, OP_EQ, 0);

  /* With the lifetime being 3 hours, a cleanup shouldn't remove it. */
  ret = cache_clean_v3_as_dir(now, 0);
  tt_int_op(ret, OP_EQ, 0);
  /* Should be present after clean up. */
  ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
  tt_int_op(ret, OP_EQ, 1);
  /* Set a cutoff 100 seconds in the past. It should not remove the entry
   * since the entry is still recent enough. */
  ret = cache_clean_v3_as_dir(now, now - 100);
  tt_int_op(ret, OP_EQ, 0);
  /* Should be present after clean up. */
  ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
  tt_int_op(ret, OP_EQ, 1);
  /* Set a cutoff of 100 seconds in the future. It should remove the entry
   * that we've just added since it's not too old for the cutoff. */
  ret = cache_clean_v3_as_dir(now, now + 100);
  tt_int_op(ret, OP_GT, 0);
  /* Shouldn't be present after clean up. */
  ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  hs_descriptor_free(desc1);
  tor_free(desc1_str);
}

static void
test_clean_oom_as_dir(void *arg)
{
  size_t ret;
  char *desc1_str = NULL, *desc2_str = NULL;
  hs_descriptor_t *desc1 = NULL, *desc2 = NULL;
  ed25519_keypair_t signing_kp1, signing_kp2;

  (void) arg;

  init_test();

  /* Generate two valid descriptors. */
  ret = ed25519_keypair_generate(&signing_kp1, 0);
  tt_int_op(ret, OP_EQ, 0);
  ret = ed25519_keypair_generate(&signing_kp2, 0);
  tt_int_op(ret, OP_EQ, 0);
  desc1 = hs_helper_build_hs_desc_with_ip(&signing_kp1);
  tt_assert(desc1);
  desc2 = hs_helper_build_hs_desc_with_ip(&signing_kp2);
  tt_assert(desc2);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, NULL, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);
  ret = hs_cache_store_as_dir(desc1_str);
  tt_int_op(ret, OP_EQ, 0);
  ret = hs_desc_encode_descriptor(desc2, &signing_kp2, NULL, &desc2_str);
  tt_int_op(ret, OP_EQ, 0);
  ret = hs_cache_store_as_dir(desc2_str);
  tt_int_op(ret, OP_EQ, 0);

  /* Set the downloaded count to 42 for the second one. */
  dir_set_downloaded(&desc2->plaintext_data.blinded_pubkey, 42);
  const hs_cache_dir_descriptor_t *entry =
    lookup_v3_desc_as_dir(desc2->plaintext_data.blinded_pubkey.pubkey);
  tt_u64_op(entry->n_downloaded, OP_EQ, 42);

  /* Spin the OOM cleanup for only 1 descriptor (very low amount of bytes). We
   * expect desc1 to be cleaned up because its downloaded counter is 0. */
  size_t removed = hs_cache_handle_oom(1);
  tt_size_op(removed, OP_GT, 0);

  /* Desc1 is gone. */
  entry = lookup_v3_desc_as_dir(desc1->plaintext_data.blinded_pubkey.pubkey);
  tt_assert(!entry);
  /* Desc2 is still there. */
  entry = lookup_v3_desc_as_dir(desc2->plaintext_data.blinded_pubkey.pubkey);
  tt_assert(entry);

 done:
  hs_descriptor_free(desc1);
  hs_descriptor_free(desc2);
  tor_free(desc1_str);
  tor_free(desc2_str);
}

/* Test helper: Fetch an HS descriptor from an HSDir (for the hidden service
   with <b>blinded_key</b>. Return the received descriptor string. */
static char *
helper_fetch_desc_from_hsdir(const ed25519_public_key_t *blinded_key)
{
  int retval;

  char *received_desc = NULL;
  char *hsdir_query_str = NULL;

  /* The dir conn we are going to simulate */
  dir_connection_t *conn = NULL;
  edge_connection_t *edge_conn = NULL;
  or_circuit_t *or_circ = NULL;

  /* First extract the blinded public key that we are going to use in our
     query, and then build the actual query string. */
  {
    char hsdir_cache_key[ED25519_BASE64_LEN+1];

    ed25519_public_to_base64(hsdir_cache_key, blinded_key);
    tor_asprintf(&hsdir_query_str, GET("/tor/hs/3/%s"), hsdir_cache_key);
  }

  /* Simulate an HTTP GET request to the HSDir */
  conn = dir_connection_new(AF_INET);
  tt_assert(conn);
  TO_CONN(conn)->linked = 1; /* Signal that it is encrypted. */
  tor_addr_from_ipv4h(&conn->base_.addr, 0x7f000001);

  /* Pretend this conn is anonymous. */
  edge_conn = edge_connection_new(CONN_TYPE_EXIT, AF_INET);
  TO_CONN(conn)->linked_conn = TO_CONN(edge_conn);
  or_circ = or_circuit_new(0, NULL);
  or_circ->p_chan = tor_malloc_zero(sizeof(channel_t));
  edge_conn->on_circuit = TO_CIRCUIT(or_circ);

  retval = directory_handle_command_get(conn, hsdir_query_str,
                                        NULL, 0);
  tt_int_op(retval, OP_EQ, 0);

  /* Read the descriptor that the HSDir just served us */
  {
    char *headers = NULL;
    size_t body_used = 0;

    fetch_from_buf_http(TO_CONN(conn)->outbuf, &headers, MAX_HEADERS_SIZE,
                        &received_desc, &body_used, HS_DESC_MAX_LEN, 0);
    tor_free(headers);
  }

 done:
  tor_free(hsdir_query_str);
  if (conn) {
    tor_free(or_circ->p_chan);
    connection_free_minimal(TO_CONN(conn)->linked_conn);
    connection_free_minimal(TO_CONN(conn));
  }

  return received_desc;
}

/* Return the value of <b>name</b>{<b>key</b>="<b>value</b>"} in the relay
 * metrics store. If there is no such entry, fail the test and return -1. */
static int64_t
get_metric(const char *name, const char *key, const char *value)
{
  const smartlist_t *entries =
    metrics_store_get_all(smartlist_get(relay_metrics_get_stores(), 0), name);
  const metrics_store_entry_t *entry =
    metrics_store_find_entry_with_label(entries,
                                        metrics_format_label(key, value));
  if (!entry)
    TT_FAIL(("no series %s{%s=\"%s\"}", name, key, value));
  return entry ? metrics_store_entry_get_value(entry) : -1;
}
#define GET_METRIC(action) \
  get_metric(METRICS_NAME(relay_hsdir_fetch_total), "action", (action))
#define POST_METRIC(action) \
  get_metric(METRICS_NAME(relay_hsdir_upload_total), "action", (action))
#define DOS_METRIC(type) \
  get_metric(METRICS_NAME(relay_dos_total), "type", (type))
/* tor_relay_begindir_request_total{type} */
#define REQ_SUM(type) \
  get_metric(METRICS_NAME(relay_begindir_request_total), "type", (type))

/* Return a new OR circuit whose previous hop is <b>chan</b>. */
static or_circuit_t *
new_or_circ(channel_t *chan)
{
  or_circuit_t *circ = or_circuit_new(0, NULL);

  circ->p_chan = chan;
  /* Closing a circuit checks its invariants, which need a valid purpose. */
  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_OR;
  return circ;
}

/* As hsdir_request_on_circuit(), on a new OR circuit whose previous hop is
 * <b>chan</b>. */
static int
hsdir_request_on_new_circ(channel_t *chan, const char *req, const char *body)
{
  return hsdir_request_on_circuit(new_or_circ(chan), req, body);
}

/* HSDirs count descriptor fetches and uploads by outcome. */
static void
test_hsdir_get_post_metrics(void *arg)
{
  channel_t *chan = new_fake_channel();
  ed25519_keypair_t signing_kp;
  hs_descriptor_t *desc = NULL;
  dir_connection_t *dirport;
  or_circuit_t *circs[2];
  char *desc_str = NULL, *get = NULL;
  const char *post = "POST /tor/hs/3/publish HTTP/1.0\r\n\r\n";
  const char *get_actions[] = { "success", "not_found", "single_hop",
                                "refused" };
  const char *post_actions[] = { "success", "not_newer", "invalid", "bad_url",
                                 "single_hop", "refused" };
  (void) arg;

  init_test();
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  get_options_mutable()->ORPort_set = 1; /* Accept descriptor uploads. */
  tt_int_op(ed25519_keypair_generate(&signing_kp, 0), OP_EQ, 0);
  desc = hs_helper_build_hs_desc_with_ip(&signing_kp);
  tt_int_op(hs_desc_encode_descriptor(desc, &signing_kp, NULL, &desc_str),
            OP_EQ, 0);
  tor_asprintf(&get, GET("/tor/hs/3/%s"), helper_get_hsdir_query(desc));

  hsdir_request_on_new_circ(chan, get, NULL); /* Not uploaded yet. */
  /* The second request on a circuit is refused, and closes the circuit. */
  for (size_t i = 0; i < ARRAY_LENGTH(circs); i++)
    circs[i] = new_or_circ(chan);
  tt_int_op(hsdir_request_on_circuit(circs[0], post, desc_str), OP_EQ, 200);
  tt_int_op(hsdir_request_on_circuit(circs[0], get, NULL), OP_EQ, 0);
  hsdir_request_on_new_circ(chan, post, desc_str); /* Same revision. */
  tt_i64_op(POST_METRIC("not_newer"), OP_EQ, 1);
  hsdir_request_on_new_circ(chan, post, "hs-descriptor 3\nJUNK");
  hsdir_request_on_new_circ(chan,
                            "POST /tor/hs/2/publish HTTP/1.0\r\n\r\n",
                            desc_str);
  tt_int_op(hsdir_request_on_circuit(circs[1], get, NULL), OP_EQ, 200);
  tt_int_op(hsdir_request_on_circuit(circs[1], post, desc_str), OP_EQ, 0);
  chan->is_client = 1; /* A one-hop client is refused. */
  hsdir_request_on_new_circ(chan, get, NULL);
  hsdir_request_on_new_circ(chan, post, desc_str);

  /* Requests on the DirPort (not tunneled) aren't counted. */
  dirport = dir_connection_new(AF_INET);
  tor_addr_from_ipv4h(&TO_CONN(dirport)->addr, 0x7f000001);
  directory_handle_command_get(dirport, get, NULL, 0);
  directory_handle_command_post(dirport, post, desc_str, strlen(desc_str));
  connection_free_minimal(TO_CONN(dirport));

  /* Exactly one request of each outcome, each also counted by type. */
  for (size_t i = 0; i < ARRAY_LENGTH(get_actions); i++)
    tt_i64_op(GET_METRIC(get_actions[i]), OP_EQ, 1);
  for (size_t i = 0; i < ARRAY_LENGTH(post_actions); i++)
    tt_i64_op(POST_METRIC(post_actions[i]), OP_EQ, 1);
  tt_i64_op(REQ_SUM("hs_get"), OP_EQ, 4);
  tt_i64_op(REQ_SUM("hs_post"), OP_EQ, 6);

 done:
  UNMOCK(connection_write_to_buf_impl_);
  circuit_free_all();
  free_fake_channel(chan);
  hs_descriptor_free(desc);
  tor_free(desc_str);
  tor_free(get);
}

/* Publish a descriptor to the HSDir, then fetch it. Check that the received
   descriptor matches the published one. */
static void
test_upload_and_download_hs_desc(void *arg)
{
  int retval;
  hs_descriptor_t *published_desc = NULL;

  char *published_desc_str = NULL;
  char *received_desc_str = NULL;

  (void) arg;

  /* Initialize HSDir cache subsystem */
  init_test();

  /* Test a descriptor not found in the directory cache. */
  {
    ed25519_public_key_t blinded_key;
    memset(&blinded_key.pubkey, 'A', sizeof(blinded_key.pubkey));
    received_desc_str = helper_fetch_desc_from_hsdir(&blinded_key);
    tt_int_op(strlen(received_desc_str), OP_EQ, 0);
    tor_free(received_desc_str);
  }

  /* Generate a valid descriptor with normal values. */
  {
    ed25519_keypair_t signing_kp;
    retval = ed25519_keypair_generate(&signing_kp, 0);
    tt_int_op(retval, OP_EQ, 0);
    published_desc = hs_helper_build_hs_desc_with_ip(&signing_kp);
    tt_assert(published_desc);
    retval = hs_desc_encode_descriptor(published_desc, &signing_kp,
                                       NULL, &published_desc_str);
    tt_int_op(retval, OP_EQ, 0);
  }

  /* Publish descriptor to the HSDir */
  {
    retval = handle_post_hs_descriptor("/tor/hs/3/publish",published_desc_str);
    tt_int_op(retval, OP_EQ, 200);
  }

  /* Simulate a fetch of the previously published descriptor */
  {
    const ed25519_public_key_t *blinded_key;
    blinded_key = &published_desc->plaintext_data.blinded_pubkey;
    received_desc_str = helper_fetch_desc_from_hsdir(blinded_key);
  }

  /* Verify we received the exact same descriptor we published earlier */
  tt_str_op(received_desc_str, OP_EQ, published_desc_str);
  tor_free(received_desc_str);

  /* With a valid descriptor in the directory cache, try again an invalid. */
  {
    ed25519_public_key_t blinded_key;
    memset(&blinded_key.pubkey, 'A', sizeof(blinded_key.pubkey));
    received_desc_str = helper_fetch_desc_from_hsdir(&blinded_key);
    tt_int_op(strlen(received_desc_str), OP_EQ, 0);
  }

 done:
  tor_free(received_desc_str);
  tor_free(published_desc_str);
  hs_descriptor_free(published_desc);
}

/* Test that HSDirs reject outdated descriptors based on their revision
 * counter. Also test that HSDirs correctly replace old descriptors with newer
 * descriptors. */
static void
test_hsdir_revision_counter_check(void *arg)
{
  int retval;

  ed25519_keypair_t signing_kp;

  hs_descriptor_t *published_desc = NULL;
  char *published_desc_str = NULL;

  hs_subcredential_t subcredential;
  char *received_desc_str = NULL;
  hs_descriptor_t *received_desc = NULL;

  (void) arg;

  /* Initialize HSDir cache subsystem */
  init_test();

  /* Generate a valid descriptor with normal values. */
  {
    retval = ed25519_keypair_generate(&signing_kp, 0);
    tt_int_op(retval, OP_EQ, 0);
    published_desc = hs_helper_build_hs_desc_with_ip(&signing_kp);
    tt_assert(published_desc);
    retval = hs_desc_encode_descriptor(published_desc, &signing_kp,
                                       NULL, &published_desc_str);
    tt_int_op(retval, OP_EQ, 0);
  }

  /* Publish descriptor to the HSDir */
  {
    retval = handle_post_hs_descriptor("/tor/hs/3/publish",published_desc_str);
    tt_int_op(retval, OP_EQ, 200);
  }

  /* Try publishing again with the same revision counter: Should fail. */
  {
    retval = handle_post_hs_descriptor("/tor/hs/3/publish",published_desc_str);
    tt_int_op(retval, OP_EQ, 400);
  }

  /* Fetch the published descriptor and validate the revision counter. */
  {
    const ed25519_public_key_t *blinded_key;

    blinded_key = &published_desc->plaintext_data.blinded_pubkey;
    hs_get_subcredential(&signing_kp.pubkey, blinded_key, &subcredential);
    received_desc_str = helper_fetch_desc_from_hsdir(blinded_key);

    retval = hs_desc_decode_descriptor(received_desc_str,
                                       &subcredential, NULL, &received_desc);
    tt_int_op(retval, OP_EQ, HS_DESC_DECODE_OK);
    tt_assert(received_desc);

    /* Check that the revision counter is correct */
    tt_u64_op(received_desc->plaintext_data.revision_counter, OP_EQ, 42);

    hs_descriptor_free(received_desc);
    received_desc = NULL;
    tor_free(received_desc_str);
  }

  /* Increment the revision counter and try again. Should work. */
  {
    published_desc->plaintext_data.revision_counter = 1313;
    tor_free(published_desc_str);
    retval = hs_desc_encode_descriptor(published_desc, &signing_kp,
                                       NULL, &published_desc_str);
    tt_int_op(retval, OP_EQ, 0);

    retval = handle_post_hs_descriptor("/tor/hs/3/publish",published_desc_str);
    tt_int_op(retval, OP_EQ, 200);
  }

  /* Again, fetch the published descriptor and perform the revision counter
     validation. The revision counter must have changed. */
  {
    const ed25519_public_key_t *blinded_key;

    blinded_key = &published_desc->plaintext_data.blinded_pubkey;
    received_desc_str = helper_fetch_desc_from_hsdir(blinded_key);

    retval = hs_desc_decode_descriptor(received_desc_str,
                                       &subcredential, NULL, &received_desc);
    tt_int_op(retval, OP_EQ, HS_DESC_DECODE_OK);
    tt_assert(received_desc);

    /* Check that the revision counter is the latest */
    tt_u64_op(received_desc->plaintext_data.revision_counter, OP_EQ, 1313);
  }

 done:
  hs_descriptor_free(published_desc);
  hs_descriptor_free(received_desc);
  tor_free(received_desc_str);
  tor_free(published_desc_str);
}

static networkstatus_t mock_ns;

static networkstatus_t *
mock_networkstatus_get_reasonably_live_consensus(time_t now, int flavor)
{
  (void) now;
  (void) flavor;
  return &mock_ns;
}

/** Test that we can store HS descriptors in the client HS cache. */
static void
test_client_cache(void *arg)
{
  int retval;
  ed25519_keypair_t signing_kp;
  hs_descriptor_t *published_desc = NULL;
  char *published_desc_str = NULL;
  hs_subcredential_t wanted_subcredential;
  response_handler_args_t *args = NULL;
  dir_connection_t *conn = NULL;

  (void) arg;

  /* Initialize HSDir cache subsystem */
  init_test();

  MOCK(networkstatus_get_reasonably_live_consensus,
       mock_networkstatus_get_reasonably_live_consensus);

  /* Set consensus time */
  parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC",
                           &mock_ns.valid_after);
  parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC",
                           &mock_ns.fresh_until);
  parse_rfc1123_time("Sat, 26 Oct 1985 16:00:00 UTC",
                           &mock_ns.valid_until);

  /* Generate a valid descriptor with normal values. */
  {
    retval = ed25519_keypair_generate(&signing_kp, 0);
    tt_int_op(retval, OP_EQ, 0);
    published_desc = hs_helper_build_hs_desc_with_ip(&signing_kp);
    tt_assert(published_desc);
    retval = hs_desc_encode_descriptor(published_desc, &signing_kp,
                                       NULL, &published_desc_str);
    tt_int_op(retval, OP_EQ, 0);
    memcpy(&wanted_subcredential, &published_desc->subcredential,
           sizeof(hs_subcredential_t));
    tt_assert(!fast_mem_is_zero((char*)wanted_subcredential.subcred,
                                DIGEST256_LEN));
  }

  /* Test handle_response_fetch_hsdesc_v3() */
  {
    args = tor_malloc_zero(sizeof(response_handler_args_t));
    args->status_code = 200;
    args->reason = NULL;
    args->body = published_desc_str;
    args->body_len = strlen(published_desc_str);

    conn = tor_malloc_zero(sizeof(dir_connection_t));
    conn->hs_ident = tor_malloc_zero(sizeof(hs_ident_dir_conn_t));
    ed25519_pubkey_copy(&conn->hs_ident->identity_pk, &signing_kp.pubkey);
  }

  /* store the descriptor! */
  retval = handle_response_fetch_hsdesc_v3(conn, args);
  tt_int_op(retval, == , 0);

  /* Progress time a bit and attempt to clean cache: our desc should not be
   * cleaned since we still in the same TP. */
  {
    parse_rfc1123_time("Sat, 27 Oct 1985 02:00:00 UTC",
                       &mock_ns.valid_after);
    parse_rfc1123_time("Sat, 27 Oct 1985 03:00:00 UTC",
                       &mock_ns.fresh_until);
    parse_rfc1123_time("Sat, 27 Oct 1985 05:00:00 UTC",
                       &mock_ns.valid_until);

    /* fetch the descriptor and make sure it's there */
    const hs_descriptor_t *cached_desc = NULL;
    cached_desc = hs_cache_lookup_as_client(&signing_kp.pubkey);
    tt_assert(cached_desc);
    tt_mem_op(cached_desc->subcredential.subcred,
              OP_EQ, wanted_subcredential.subcred,
              SUBCRED_LEN);
  }

  /* Progress time to next TP and check that desc was cleaned */
  {
    parse_rfc1123_time("Sat, 27 Oct 1985 12:00:00 UTC",
                       &mock_ns.valid_after);
    parse_rfc1123_time("Sat, 27 Oct 1985 13:00:00 UTC",
                       &mock_ns.fresh_until);
    parse_rfc1123_time("Sat, 27 Oct 1985 15:00:00 UTC",
                       &mock_ns.valid_until);

    const hs_descriptor_t *cached_desc = NULL;
    cached_desc = hs_cache_lookup_as_client(&signing_kp.pubkey);
    tt_assert(!cached_desc);
  }

 done:
  tor_free(args);
  hs_descriptor_free(published_desc);
  tor_free(published_desc_str);
  if (conn) {
    tor_free(conn->hs_ident);
    tor_free(conn);
  }
}

/** Test that we can store HS descriptors in the client HS cache. */
static void
test_client_cache_decrypt(void *arg)
{
  int ret;
  char *desc_encoded = NULL;
  uint8_t descriptor_cookie[HS_DESC_DESCRIPTOR_COOKIE_LEN];
  curve25519_keypair_t client_kp;
  ed25519_keypair_t service_kp;
  hs_descriptor_t *desc = NULL;
  const hs_descriptor_t *search_desc;
  const char *search_desc_encoded;

  (void) arg;

  /* Initialize HSDir cache subsystem */
  hs_init();

  MOCK(networkstatus_get_reasonably_live_consensus,
       mock_networkstatus_get_reasonably_live_consensus);

  /* Set consensus time */
  parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC",
                     &mock_ns.valid_after);
  parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC",
                     &mock_ns.fresh_until);
  parse_rfc1123_time("Sat, 26 Oct 1985 16:00:00 UTC",
                     &mock_ns.valid_until);

  /* Generate a valid descriptor with normal values. */
  {
    ret = ed25519_keypair_generate(&service_kp, 0);
    tt_int_op(ret, OP_EQ, 0);
    ret = curve25519_keypair_generate(&client_kp, 0);
    tt_int_op(ret, OP_EQ, 0);
    crypto_rand((char *) descriptor_cookie, sizeof(descriptor_cookie));

    desc = hs_helper_build_hs_desc_with_client_auth(descriptor_cookie,
                                                    &client_kp.pubkey,
                                                    &service_kp);
    tt_assert(desc);
    ret = hs_desc_encode_descriptor(desc, &service_kp, descriptor_cookie,
                                    &desc_encoded);
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Put it in the cache. Should not be decrypted since the client
   * authorization creds were not added to the global map. */
  ret = hs_cache_store_as_client(desc_encoded, &service_kp.pubkey);
  tt_int_op(ret, OP_EQ, HS_DESC_DECODE_NEED_CLIENT_AUTH);

  /* We should not be able to decrypt anything. */
  ret = hs_cache_client_new_auth_parse(&service_kp.pubkey);
  tt_int_op(ret, OP_EQ, false);

  /* Add client auth to global map. */
  hs_helper_add_client_auth(&service_kp.pubkey, &client_kp.seckey);

  /* We should not be able to decrypt anything. */
  ret = hs_cache_client_new_auth_parse(&service_kp.pubkey);
  tt_int_op(ret, OP_EQ, true);

  /* Lookup the cache to make sure it is usable and there. */
  search_desc = hs_cache_lookup_as_client(&service_kp.pubkey);
  tt_assert(search_desc);
  search_desc_encoded = hs_cache_lookup_encoded_as_client(&service_kp.pubkey);
  tt_mem_op(search_desc_encoded, OP_EQ, desc_encoded, strlen(desc_encoded));

 done:
  hs_descriptor_free(desc);
  tor_free(desc_encoded);

  hs_free_all();

  UNMOCK(networkstatus_get_reasonably_live_consensus);
}

static void
test_client_cache_remove(void *arg)
{
  int ret;
  ed25519_keypair_t service_kp;
  hs_descriptor_t *desc1 = NULL;

  (void) arg;

  hs_init();

  MOCK(networkstatus_get_reasonably_live_consensus,
       mock_networkstatus_get_reasonably_live_consensus);

  /* Set consensus time. Lookup will not return the entry if it has expired
   * and it is checked against the consensus valid_after time. */
  parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC",
                     &mock_ns.valid_after);
  parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC",
                     &mock_ns.fresh_until);
  parse_rfc1123_time("Sat, 26 Oct 1985 16:00:00 UTC",
                     &mock_ns.valid_until);

  /* Generate service keypair */
  tt_int_op(0, OP_EQ, ed25519_keypair_generate(&service_kp, 0));

  /* Build a descriptor and cache it. */
  {
    char *encoded;
    desc1 = hs_helper_build_hs_desc_with_ip(&service_kp);
    tt_assert(desc1);
    ret = hs_desc_encode_descriptor(desc1, &service_kp, NULL, &encoded);
    tt_int_op(ret, OP_EQ, 0);
    tt_assert(encoded);

    /* Store it */
    ret = hs_cache_store_as_client(encoded, &service_kp.pubkey);
    tt_int_op(ret, OP_EQ, HS_DESC_DECODE_OK);
    tor_free(encoded);
    tt_assert(hs_cache_lookup_as_client(&service_kp.pubkey));
  }

  /* Remove the cached entry. */
  hs_cache_remove_as_client(&service_kp.pubkey);
  tt_assert(!hs_cache_lookup_as_client(&service_kp.pubkey));

 done:
  hs_descriptor_free(desc1);
  hs_free_all();

  UNMOCK(networkstatus_get_reasonably_live_consensus);
}

static void
hsdir_mock_mark_for_close(connection_t *conn, int line, const char *file)
{
  (void) line;
  (void) file;
  conn->marked_for_close = 1;
}

/* An HSDir counts a descriptor as downloaded only once its whole response has
 * left the dir connection's outbuf (connection_dir_finished_flushing()), not
 * when the connection closes. A connection closed before then (for example an
 * END or DESTROY processed before the exit edge read the response, or an edge
 * already stopped on an empty package window or a blocked channel) earns no
 * credit; a normal flush earns exactly one. This does not prove the client
 * received the descriptor. */
static void
test_downloaded_counter_as_dir(void *arg)
{
  char *desc_str = NULL;
  hs_descriptor_t *desc = NULL;
  ed25519_keypair_t signing_kp;
  dir_connection_t *conns[3] = { NULL, NULL, NULL };
  const hs_cache_dir_descriptor_t *entry;
  (void) arg;

  init_test();
  MOCK(connection_mark_for_close_internal_, hsdir_mock_mark_for_close);

  tt_int_op(ed25519_keypair_generate(&signing_kp, 0), OP_EQ, 0);
  desc = hs_helper_build_hs_desc_with_ip(&signing_kp);
  tt_int_op(hs_desc_encode_descriptor(desc, &signing_kp, NULL, &desc_str),
            OP_EQ, 0);
  tt_int_op(hs_cache_store_as_dir(desc_str), OP_EQ, 0);
  entry = lookup_v3_desc_as_dir(desc->plaintext_data.blinded_pubkey.pubkey);
  tt_assert(entry);

  /* Two server-side connections that each served this descriptor, and one
   * that served something else. */
  for (int i = 0; i < 3; i++) {
    conns[i] = dir_connection_new(AF_INET);
    TO_CONN(conns[i])->purpose = DIR_PURPOSE_SERVER;
    TO_CONN(conns[i])->state = DIR_CONN_STATE_SERVER_WRITING;
    if (i < 2)
      conns[i]->hs_ident =
        hs_ident_server_dir_conn_new(&desc->plaintext_data.blinded_pubkey);
  }

  /* Blocked output / early abort: closed before the response was ever written
   * out (finished_flushing never ran). No credit. */
  connection_mark_for_close(TO_CONN(conns[0]));
  connection_dir_about_to_close(conns[0]);
  tt_u64_op(entry->n_downloaded, OP_EQ, 0);

  /* Normal flush: the whole response is written out, then the connection
   * closes. Exactly one credit, and about_to_close does not add a second. */
  tt_int_op(connection_dir_finished_flushing(conns[1]), OP_EQ, 0);
  tt_assert(TO_CONN(conns[1])->marked_for_close);
  connection_dir_about_to_close(conns[1]);
  tt_u64_op(entry->n_downloaded, OP_EQ, 1);
  /* A response with no descriptor finishes flushing and closes normally,
   * without a credit. */
  tt_int_op(connection_dir_finished_flushing(conns[2]), OP_EQ, 0);
  tt_assert(TO_CONN(conns[2])->marked_for_close);
  tt_u64_op(entry->n_downloaded, OP_EQ, 1);

 done:
  UNMOCK(connection_mark_for_close_internal_);
  for (int i = 0; i < 3; i++)
    connection_free_minimal(TO_CONN(conns[i]));
  hs_descriptor_free(desc);
  tor_free(desc_str);
}

#define DIR_RESPONSE_METRIC(type) \
  get_metric(METRICS_NAME(relay_begindir_response_total), "type", (type))

/* Make a tunneled directory server connection waiting for a request, with
 * <b>input</b> (if any) on its inbuf. */
static dir_connection_t *
new_waiting_dir_conn(const char *input)
{
  dir_connection_t *conn = dir_connection_new(AF_INET);

  TO_CONN(conn)->purpose = DIR_PURPOSE_SERVER;
  TO_CONN(conn)->state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;
  TO_CONN(conn)->linked = 1;
  tor_addr_from_ipv4h(&TO_CONN(conn)->addr, 0x7f000001);
  if (input)
    buf_add(TO_CONN(conn)->inbuf, input, strlen(input));
  return conn;
}

/* Link <b>conn</b>, from new_waiting_dir_conn(), to a new stream on a new
 * circuit: directory_handle_command() drops a request on a stream that is
 * gone or closing without reading it. Return the stream. */
static edge_connection_t *
open_waiting_stream(dir_connection_t *conn)
{
  edge_connection_t *edge = edge_connection_new(CONN_TYPE_EXIT, AF_INET);

  connection_link_connections(TO_CONN(conn), TO_CONN(edge));
  edge->on_circuit = TO_CIRCUIT(or_circuit_new(0, NULL));
  return edge;
}

/* Close <b>conn</b>, from new_waiting_dir_conn(), then free it and its
 * <b>stream</b>, if any. */
static void
close_waiting_dir_conn(dir_connection_t *conn, edge_connection_t *stream)
{
  connection_dir_about_to_close(conn);
  connection_free_minimal(TO_CONN(conn));
  if (stream)
    connection_free_minimal(TO_CONN(stream));
}

/* Tunneled directory requests are counted once, by what they asked for, and
 * responses once they are handed to their stream; direct (DirPort)
 * connections are not counted. */
static void
test_dir_request_response_metrics(void *arg)
{
  channel_t *chan = new_fake_channel();
  dir_connection_t *conn = dir_connection_new(AF_INET), *dirport = NULL;
  dir_connection_t *waiting;
  edge_connection_t *stream;
  ed25519_public_key_t pk;
  (void) arg;

  init_test();
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  MOCK(connection_mark_for_close_internal_, hsdir_mock_mark_for_close);
  get_options_mutable()->ORPort_set = 1; /* Accept directory posts. */

  hsdir_request_on_new_circ(chan, "POST /tor/ HTTP/1.0\r\n\r\n", "x");
  hsdir_request_on_new_circ(chan, "GET\r\n\r\n", NULL);
  hsdir_request_on_new_circ(chan, "POST\r\n\r\n", "x");
  /* The same requests on a DirPort connection aren't counted. */
  dirport = dir_connection_new(AF_INET);
  tor_addr_from_ipv4h(&TO_CONN(dirport)->addr, 0x7f000001);
  directory_handle_command_post(dirport, "POST /tor/ HTTP/1.0\r\n\r\n",
                                "x", 1);
  directory_handle_command_get(dirport, "GET\r\n\r\n", NULL, 0);
  directory_handle_command_post(dirport, "POST\r\n\r\n", "x", 1);
  tt_int_op(dirport->request_type, OP_EQ, 0);
  tt_i64_op(REQ_SUM("other_post"), OP_EQ, 1);
  tt_i64_op(REQ_SUM("unparsed"), OP_EQ, 2);

  /* An unknown method is counted when we refuse it, and only then: its
   * request is already off the inbuf when the connection closes. */
  waiting = new_waiting_dir_conn("PUT /tor/ HTTP/1.0\r\n\r\n");
  stream = open_waiting_stream(waiting);
  tt_int_op(directory_handle_command(waiting), OP_EQ, -1);
  tt_i64_op(REQ_SUM("unparsed"), OP_EQ, 3);
  close_waiting_dir_conn(waiting, stream);
  /* What a stream whose circuit is closing sent is dropped unread: a
   * request as circuit_dead, nothing at all as no_request. */
  for (int i = 0; i < 2; i++) {
    waiting = new_waiting_dir_conn(i ? NULL : GET("/tor/"));
    stream = open_waiting_stream(waiting);
    stream->on_circuit->marked_for_close = 1;
    tt_int_op(directory_handle_command(waiting), OP_EQ, -1);
    close_waiting_dir_conn(waiting, stream);
    tt_i64_op(REQ_SUM(i ? "no_request" : "circuit_dead"), OP_EQ, 1);
  }
  /* Closed with part of a request, or with nothing at all; a directory
   * client connection isn't counted. */
  close_waiting_dir_conn(new_waiting_dir_conn("GET /tor/"), NULL);
  tt_i64_op(REQ_SUM("unparsed"), OP_EQ, 4);
  close_waiting_dir_conn(new_waiting_dir_conn(NULL), NULL);
  tt_i64_op(REQ_SUM("no_request"), OP_EQ, 2);
  waiting = new_waiting_dir_conn(NULL);
  TO_CONN(waiting)->purpose = DIR_PURPOSE_FETCH_CONSENSUS;
  TO_CONN(waiting)->state = DIR_CONN_STATE_CLIENT_FINISHED;
  close_waiting_dir_conn(waiting, NULL);
  tt_i64_op(REQ_SUM("unparsed"), OP_EQ, 4);
  /* A bridge answers a POST with a 503 before reading its URL. */
  get_options_mutable()->BridgeRelay = 1;
  waiting = new_waiting_dir_conn(NULL);
  directory_handle_command_post(waiting,
                                "POST /tor/hs/3/publish HTTP/1.0\r\n\r\n",
                                "x", 1);
  close_waiting_dir_conn(waiting, NULL);
  get_options_mutable()->BridgeRelay = 0;
  tt_i64_op(REQ_SUM("other_post"), OP_EQ, 2);
  tt_i64_op(REQ_SUM("no_request"), OP_EQ, 2);

  /* A response is counted once it has been handed to its stream, and only
   * if tunneled. */
  TO_CONN(conn)->purpose = DIR_PURPOSE_SERVER;
  TO_CONN(conn)->state = DIR_CONN_STATE_SERVER_WRITING;
  tt_int_op(connection_dir_finished_flushing(conn), OP_EQ, 0);
  tt_i64_op(DIR_RESPONSE_METRIC("other"), OP_EQ, 0);
  TO_CONN(conn)->linked = 1;
  TO_CONN(conn)->marked_for_close = 0;
  tt_int_op(connection_dir_finished_flushing(conn), OP_EQ, 0);
  tt_i64_op(DIR_RESPONSE_METRIC("other"), OP_EQ, 1);
  memset(&pk, 0, sizeof(pk));
  conn->hs_ident = hs_ident_server_dir_conn_new(&pk);
  TO_CONN(conn)->marked_for_close = 0;
  tt_int_op(connection_dir_finished_flushing(conn), OP_EQ, 0);
  tt_i64_op(DIR_RESPONSE_METRIC("hs_descriptor"), OP_EQ, 1);
  tt_i64_op(DIR_RESPONSE_METRIC("other"), OP_EQ, 1);

 done:
  UNMOCK(connection_write_to_buf_impl_);
  UNMOCK(connection_mark_for_close_internal_);
  circuit_free_all();
  connection_free_minimal(TO_CONN(conn));
  if (dirport)
    connection_free_minimal(TO_CONN(dirport));
  free_fake_channel(chan);
}

/* Each GET that url_table matches is counted by the type of its entry, and
 * any other as other_get. */
static void
test_dir_request_url_table_types(void *arg)
{
  channel_t *chan = new_fake_channel();
  const struct {
    const char *url;
    const char *type;
  } reqs[] = {
    { "/tor/status-vote/current/consensus", "consensus" },
    { "/tor/micro/d/zz", "microdesc" },
    { "/tor/server/fp/zz", "descriptor" },
    { "/tor/extra/fp/zz", "descriptor" },
    { "/tor/hs/3/zz", "hs_get" },
    { "/tor/", "other_get" },
    { "/tor/status-vote/current/zz", "other_get" },
    { "/tor/status-vote/next/bandwidth", "other_get" },
    { "/tor/status-vote/next/zz", "other_get" },
    { "/tor/keys/zz", "other_get" },
    { "/tor/robots.txt", "other_get" },
    { "/tor/networkstatus-bridges", "other_get" },
    { "/tor/nothing-here", "other_get" },
  };
  char *req = NULL;
  (void) arg;

  init_test();
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  for (size_t i = 0; i < ARRAY_LENGTH(reqs); i++) {
    const int64_t n0 = REQ_SUM(reqs[i].type);
    tor_asprintf(&req, GET("%s"), reqs[i].url);
    hsdir_request_on_new_circ(chan, req, NULL);
    tor_free(req);
    tt_i64_op(REQ_SUM(reqs[i].type), OP_EQ, n0 + 1);
  }

 done:
  UNMOCK(connection_write_to_buf_impl_);
  tor_free(req);
  circuit_free_all();
  free_fake_channel(chan);
}

#define DIR_CONN_GAUGE(state) \
  get_metric(METRICS_NAME(relay_begindir_connections), "state", (state))

/* The tunneled directory server connection gauge puts each open BEGIN_DIR
 * stream in exactly one state, and ignores direct and closing connections. */
static void
test_dir_server_conns_gauge(void *arg)
{
  const char *states[] = { "command_wait", "writing_hs_descriptor",
                           "writing_other", "draining" };
  const int64_t added[ARRAY_LENGTH(states)] = { 1, 1, 1, 2 };
  connection_t *conns[7];
  ed25519_public_key_t pk;
  (void) arg;

  memset(&pk, 0, sizeof(pk));
  for (size_t i = 0; i < 5; i++) {
    conns[i] = TO_CONN(dir_connection_new(AF_INET));
    conns[i]->purpose = DIR_PURPOSE_SERVER;
    conns[i]->linked = 1;
  }
  conns[0]->state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;
  conns[1]->state = DIR_CONN_STATE_SERVER_WRITING;
  TO_DIR_CONN(conns[1])->hs_ident = hs_ident_server_dir_conn_new(&pk);
  conns[2]->state = DIR_CONN_STATE_SERVER_WRITING;
  conns[3]->state = DIR_CONN_STATE_SERVER_WRITING;
  conns[3]->linked = 0; /* Direct, not tunneled. */
  conns[4]->state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;
  conns[4]->marked_for_close = 1;
  /* Streams whose directory connection is gone, or closing. */
  conns[5] = TO_CONN(edge_connection_new(CONN_TYPE_EXIT, AF_INET));
  conns[6] = TO_CONN(edge_connection_new(CONN_TYPE_EXIT, AF_INET));
  conns[5]->linked = conns[6]->linked = 1;
  conns[6]->linked_conn = conns[4];

  for (size_t i = 0; i < ARRAY_LENGTH(conns); i++) {
    conns[i]->conn_array_index = smartlist_len(get_connection_array());
    smartlist_add(get_connection_array(), conns[i]);
  }
  for (size_t i = 0; i < ARRAY_LENGTH(states); i++)
    tt_i64_op(DIR_CONN_GAUGE(states[i]), OP_EQ, added[i]);

 done:
  conns[6]->linked_conn = NULL;
  for (size_t i = 0; i < ARRAY_LENGTH(conns); i++) {
    if (conns[i]->conn_array_index >= 0)
      connection_remove(conns[i]);
    connection_free_minimal(conns[i]);
  }
}

static networkstatus_t *mock_hsdir_ns;
static networkstatus_t *
mock_hsdir_get_latest_consensus(void)
{
  return mock_hsdir_ns;
}

/* HSDirs count the anonymous onion service directory requests whose
 * previous hop is not a known relay. */
static void
test_hsdir_prev_hop_counter(void *arg)
{
  channel_t *chan = new_fake_channel();
  routerstatus_t known_rs;
  or_circuit_t *circ;
  const char *post = "POST /tor/hs/3/publish HTTP/1.0\r\n\r\n";
  (void) arg;

  init_test();
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  get_options_mutable()->ORPort_set = 1; /* Accept descriptor uploads. */

  /* The zeroed previous hop identity is not a known relay. A second request
   * on a circuit isn't counted: tor refuses it first. */
  circ = new_or_circ(chan);
  tt_int_op(hsdir_request_on_circuit(circ, post, "x"), OP_EQ, 400);
  tt_int_op(hsdir_request_on_circuit(circ, post, "x"), OP_EQ, 0);
  circ = new_or_circ(chan);
  tt_int_op(hsdir_request_on_circuit(circ, GET("/tor/hs/3/x"), NULL),
            OP_EQ, 404);
  tt_int_op(hsdir_request_on_circuit(circ, GET("/tor/hs/3/x"), NULL),
            OP_EQ, 0);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_UNKNOWN_PREV_HOP), OP_EQ, 2);
  tt_i64_op(DOS_METRIC("hsdir_unknown_prev_hop"), OP_EQ, 2);

  /* Single-hop requests are refused, and not counted here. */
  chan->is_client = 1;
  hsdir_request_on_new_circ(chan, GET("/tor/hs/3/x"), NULL);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_UNKNOWN_PREV_HOP), OP_EQ, 2);
  chan->is_client = 0;

  /* A previous hop in our consensus is known. */
  memset(&known_rs, 0, sizeof(known_rs)); /* Matches the zeroed identity. */
  mock_hsdir_ns = tor_malloc_zero(sizeof(networkstatus_t));
  mock_hsdir_ns->routerstatus_list = smartlist_new();
  smartlist_add(mock_hsdir_ns->routerstatus_list, &known_rs);
  MOCK(networkstatus_get_latest_consensus, mock_hsdir_get_latest_consensus);
  hsdir_request_on_new_circ(chan, GET("/tor/hs/3/x"), NULL);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_UNKNOWN_PREV_HOP), OP_EQ, 2);

 done:
  UNMOCK(connection_write_to_buf_impl_);
  UNMOCK(networkstatus_get_latest_consensus);
  if (mock_hsdir_ns) {
    smartlist_free(mock_hsdir_ns->routerstatus_list);
    tor_free(mock_hsdir_ns);
  }
  circuit_free_all();
  free_fake_channel(chan);
}

/* HSDirRefuseUnknownPrevHop only refuses when the torrc, or else the
 * consensus, enables it, and only on public relays. Requests are counted
 * either way, and refused ones as "refused". */
static void
test_hsdir_prev_hop_defense(void *arg)
{
  channel_t *chan = new_fake_channel();
  routerstatus_t known_rs;
  dos_options_t *dos_opts;
  or_circuit_t *circ;
  const char *get = GET("/tor/hs/3/x");
  const char *post = "POST /tor/hs/3/publish HTTP/1.0\r\n\r\n";
  (void) arg;

  init_test();
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  mock_hsdir_ns = tor_malloc_zero(sizeof(networkstatus_t));
  mock_hsdir_ns->net_params = smartlist_new();
  mock_hsdir_ns->routerstatus_list = smartlist_new();
  MOCK(networkstatus_get_latest_consensus, mock_hsdir_get_latest_consensus);
  get_options_mutable()->ORPort_set = 1;
  dos_opts = get_dos_options(get_options_mutable());
  memset(&known_rs, 0, sizeof(known_rs)); /* Matches the zeroed identity. */

  /* By default, a request from an unknown relay is served. */
  circ = new_or_circ(chan);
  tt_int_op(hsdir_request_on_circuit(circ, get, NULL), OP_EQ, 404);

  /* The consensus can refuse unknown previous hops, but not known ones, by
   * closing the circuit without an answer, after tor's limit of one request
   * per circuit. */
  smartlist_add_strdup(mock_hsdir_ns->net_params,
                       "HSDirRefuseUnknownPrevHop=1");
  tt_int_op(hsdir_request_on_circuit(circ, get, NULL), OP_EQ, 0);
  circ = new_or_circ(chan);
  tt_int_op(hsdir_request_on_circuit(circ, get, NULL), OP_EQ, 0);
  tt_assert(TO_CIRCUIT(circ)->marked_for_close);
  tt_int_op(hsdir_request_on_new_circ(chan, post, "x"), OP_EQ, 0);
  smartlist_add(mock_hsdir_ns->routerstatus_list, &known_rs);
  tt_int_op(hsdir_request_on_new_circ(chan, get, NULL), OP_EQ, 404);
  smartlist_clear(mock_hsdir_ns->routerstatus_list);
  /* The torrc overrides the consensus, either way. */
  dos_opts->HSDirRefuseUnknownPrevHop = 0;
  tt_int_op(hsdir_request_on_new_circ(chan, get, NULL), OP_EQ, 404);
  SMARTLIST_FOREACH(mock_hsdir_ns->net_params, char *, cp, tor_free(cp));
  smartlist_clear(mock_hsdir_ns->net_params);
  dos_opts->HSDirRefuseUnknownPrevHop = 1;
  tt_int_op(hsdir_request_on_new_circ(chan, get, NULL), OP_EQ, 0);

  /* Each request was counted once: the 4 refused ones as refused, and the 3
   * others as not found. */
  tt_i64_op(GET_METRIC("refused"), OP_EQ, 3);
  tt_i64_op(POST_METRIC("refused"), OP_EQ, 1);
  tt_i64_op(GET_METRIC("not_found"), OP_EQ, 3);
  /* hsdir_unknown_prev_hop counts what the defense refuses or would refuse:
   * the requests while the previous hop was unknown, less the second one on
   * a circuit. */
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_UNKNOWN_PREV_HOP), OP_EQ, 5);

  /* Relays that aren't public never refuse. */
  get_options_mutable()->ORPort_set = 0;
  tt_int_op(dos_should_refuse_unknown_hsdir_prev_hop(), OP_EQ, 0);

 done:
  UNMOCK(connection_write_to_buf_impl_);
  UNMOCK(networkstatus_get_latest_consensus);
  SMARTLIST_FOREACH(mock_hsdir_ns->net_params, char *, cp, tor_free(cp));
  smartlist_free(mock_hsdir_ns->net_params);
  smartlist_free(mock_hsdir_ns->routerstatus_list);
  tor_free(mock_hsdir_ns);
  circuit_free_all();
  free_fake_channel(chan);
}

struct testcase_t hs_cache[] = {
  { "hsdir_request_limit_get", test_hsdir_request_limit, TT_FORK,
    &passthrough_setup, (void *) "get" },
  { "hsdir_request_limit_post", test_hsdir_request_limit, TT_FORK,
    &passthrough_setup, (void *) "post" },
  { "hsdir_request_limit_authority", test_hsdir_request_limit, TT_FORK,
    &passthrough_setup, (void *) "authority" },
  /* Encoding tests. */
  { "directory", test_directory, TT_FORK,
    NULL, NULL },
  { "clean_as_dir", test_clean_as_dir, TT_FORK,
    NULL, NULL },
  { "clean_oom_as_dir", test_clean_oom_as_dir, TT_FORK,
    NULL, NULL },
  { "hsdir_revision_counter_check", test_hsdir_revision_counter_check, TT_FORK,
    NULL, NULL },
  { "upload_and_download_hs_desc", test_upload_and_download_hs_desc, TT_FORK,
    NULL, NULL },
  { "hsdir_get_post_metrics", test_hsdir_get_post_metrics, TT_FORK,
    NULL, NULL },
  { "dir_request_response_metrics", test_dir_request_response_metrics,
    TT_FORK, NULL, NULL },
  { "dir_request_url_table_types", test_dir_request_url_table_types, TT_FORK,
    NULL, NULL },
  { "dir_server_conns_gauge", test_dir_server_conns_gauge, TT_FORK,
    NULL, NULL },
  { "hsdir_prev_hop_counter", test_hsdir_prev_hop_counter, TT_FORK,
    NULL, NULL },
  { "hsdir_prev_hop_defense", test_hsdir_prev_hop_defense, TT_FORK,
    NULL, NULL },
  { "downloaded_counter_as_dir", test_downloaded_counter_as_dir, TT_FORK,
    NULL, NULL },
  { "client_cache", test_client_cache, TT_FORK,
    NULL, NULL },
  { "client_cache_decrypt", test_client_cache_decrypt, TT_FORK,
    NULL, NULL },
  { "client_cache_remove", test_client_cache_remove, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};
