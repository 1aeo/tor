/* Copyright (c) 2018-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define DOS_PRIVATE
#define CHANNEL_OBJECT_PRIVATE
#define CIRCUITLIST_PRIVATE
#define CONNECTION_PRIVATE

#include "core/or/or.h"
#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/or/dos.h"
#include "core/or/circuitlist.h"
#include "core/or/connection_edge.h"
#include "core/or/relay.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/time/compat_time.h"
#include "feature/stats/geoip_stats.h"
#include "core/or/channel.h"
#include "core/or/command.h"
#include "feature/dircommon/directory.h"
#include "feature/stats/rephist.h"
#include "feature/nodelist/microdesc.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerlist.h"
#include "feature/hibernate/hibernate.h"
#include "feature/stats/bwhist.h"

#include "feature/nodelist/networkstatus_st.h"
#include "core/or/or_circuit_st.h"
#include "app/config/or_options_st.h"
#include "core/or/dos_options_st.h"
#include "core/or/edge_connection_st.h"
#include "core/or/or_connection_st.h"
#include "feature/nodelist/routerstatus_st.h"

#include "core/or/cell_st.h"
#include "feature/dircommon/dir_connection_st.h"

#include "test/fakechans.h"
#include "test/test.h"
#include "test/log_test_helpers.h"
#include "test/opts_test_helpers.h"

static const uint64_t BILLION = 1000000000;

static networkstatus_t *dummy_ns = NULL;
static networkstatus_t *
mock_networkstatus_get_latest_consensus(void)
{
  return dummy_ns;
}

static networkstatus_t *
mock_networkstatus_get_latest_consensus_by_flavor(consensus_flavor_t f)
{
  tor_assert(f == FLAV_MICRODESC);
  return dummy_ns;
}

/* Number of address a single node_t can have. Default to the production
 * value. This is to control the size of the bloom filter. */
static int addr_per_node = 2;
static int
mock_get_estimated_address_per_node(void)
{
  return addr_per_node;
}

static unsigned int
mock_enable_dos_protection(const networkstatus_t *ns)
{
  (void) ns;
  return 1;
}

/** Test that the connection tracker of the DoS subsystem will block clients
 *  who try to establish too many connections */
static void
test_dos_conn_creation(void *arg)
{
  uint64_t monotime_now = 0xfffffffe;

  (void) arg;

  monotime_enable_test_mocking();
  monotime_coarse_set_mock_time_nsec(monotime_now);
  MOCK(get_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_param_conn_enabled, mock_enable_dos_protection);

  /* Initialize test data */
  or_connection_t or_conn;
  memset(&or_conn, 0, sizeof or_conn);
  time_t wallclock_now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&TO_CONN(&or_conn)->addr,
                                          "18.0.0.1"));
  tor_addr_t *addr = &TO_CONN(&or_conn)->addr;

  /* Get DoS subsystem limits */
  dos_init();
  uint32_t max_concurrent_conns = get_param_conn_max_concurrent_count(NULL);

  /* Introduce new client */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, addr, NULL, wallclock_now);
  { /* Register many conns from this client but not enough to get it blocked */
    unsigned int i;
    for (i = 0; i < max_concurrent_conns; i++) {
      /* Don't trigger the connect() rate limitation so advance the clock 1
       * second for each connection. */
      monotime_coarse_set_mock_time_nsec(monotime_now += BILLION);
      update_approx_time(++wallclock_now);
      or_conn.tracked_for_dos_mitigation = 0;
      dos_new_client_conn(&or_conn, NULL);
    }
  }

  /* Check that new conns are still permitted */
  tt_int_op(DOS_CONN_DEFENSE_NONE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Register another conn and check that new conns are not allowed anymore */
  or_conn.tracked_for_dos_mitigation = 0;
  dos_new_client_conn(&or_conn, NULL);
  tt_int_op(DOS_CONN_DEFENSE_CLOSE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Close a client conn and see that a new conn will be permitted again */
  dos_close_client_conn(&or_conn);
  or_conn.tracked_for_dos_mitigation = 0;
  tt_int_op(DOS_CONN_DEFENSE_NONE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Register another conn and see that defense measures get reactivated */
  dos_new_client_conn(&or_conn, NULL);
  tt_int_op(DOS_CONN_DEFENSE_CLOSE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

 done:
  dos_free_all();
  monotime_disable_test_mocking();
}

/** Helper mock: Place a fake IP addr for this channel in <b>addr_out</b> */
static int
mock_channel_get_addr_if_possible(const channel_t *chan, tor_addr_t *addr_out)
{
  (void)chan;
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(addr_out, "18.0.0.1"));
  return 1;

 done:
  return 0;
}

/** Test that the circuit tracker of the DoS subsystem will block clients who
 *  try to establish too many circuits. */
static void
test_dos_circuit_creation(void *arg)
{
  (void) arg;
  unsigned int i;

  MOCK(get_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_param_conn_enabled, mock_enable_dos_protection);
  MOCK(channel_get_addr_if_possible,
       mock_channel_get_addr_if_possible);

  /* Initialize channels/conns/circs that will be used */
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  chan->is_client = 1;

  /* Initialize test data */
  or_connection_t or_conn;
  memset(&or_conn, 0, sizeof or_conn);
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&TO_CONN(&or_conn)->addr,
                                          "18.0.0.1"));
  tor_addr_t *addr = &TO_CONN(&or_conn)->addr;

  /* Get DoS subsystem limits */
  dos_init();
  uint32_t max_circuit_count = get_param_cc_circuit_burst(NULL);
  uint32_t min_conc_conns_for_cc =
    get_param_cc_min_concurrent_connection(NULL);

  /* Introduce new client and establish enough connections to activate the
   * circuit counting subsystem */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, addr, NULL, now);
  for (i = 0; i < min_conc_conns_for_cc ; i++) {
    or_conn.tracked_for_dos_mitigation = 0;
    dos_new_client_conn(&or_conn, NULL);
  }

  /* Register new circuits for this client and conn, but not enough to get
   * detected as dos */
  for (i=0; i < max_circuit_count-1; i++) {
    dos_cc_new_create_cell(chan);
  }
  /* see that we didn't get detected for dosing */
  tt_int_op(DOS_CC_DEFENSE_NONE, OP_EQ, dos_cc_get_defense_type(chan));

  /* Register another CREATE cell that will push us over the limit. Check that
   * the cell gets refused. */
  dos_cc_new_create_cell(chan);
  tt_int_op(DOS_CC_DEFENSE_REFUSE_CELL, OP_EQ, dos_cc_get_defense_type(chan));

  /* TODO: Wait a few seconds before sending the cell, and check that the
     buckets got refilled properly. */
  /* TODO: Actually send a Tor cell (instead of calling the DoS function) and
   * check that it will get refused */

 done:
  tor_free(chan);
  dos_free_all();
}

/** Test that the DoS subsystem properly refills the circuit token buckets. */
static void
test_dos_bucket_refill(void *arg)
{
  (void) arg;
  int i;
  /* For this test, this variable is set to the current circ count of the token
   * bucket. */
  uint32_t current_circ_count;

  MOCK(get_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_param_conn_enabled, mock_enable_dos_protection);
  MOCK(channel_get_addr_if_possible,
       mock_channel_get_addr_if_possible);

  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  update_approx_time(now);

  /* Initialize channels/conns/circs that will be used */
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  chan->is_client = 1;
  or_connection_t or_conn;
  memset(&or_conn, 0, sizeof or_conn);
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&TO_CONN(&or_conn)->addr,
                                          "18.0.0.1"));
  tor_addr_t *addr = &TO_CONN(&or_conn)->addr;

  /* Initialize DoS subsystem and get relevant limits */
  dos_init();
  uint32_t max_circuit_count = get_param_cc_circuit_burst(NULL);
  uint64_t circ_rate = get_circuit_rate_per_second();
  /* Check that the circuit rate is a positive number and smaller than the max
   * circuit count */
  tt_u64_op(circ_rate, OP_GT, 1);
  tt_u64_op(circ_rate, OP_LT, max_circuit_count);

  /* Register this client */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, addr, NULL, now);
  dos_new_client_conn(&or_conn, NULL);

  /* Fetch this client from the geoip cache and get its DoS structs */
  clientmap_entry_t *entry = geoip_lookup_client(addr, NULL,
                                                 GEOIP_CLIENT_CONNECT);
  tt_assert(entry);
  dos_client_stats_t* dos_stats = &entry->dos_stats;
  /* Check that the circuit bucket is still uninitialized */
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, 0);

  /* Send a create cell: then check that the circ token bucket got initialized
   * and one circ was subtracted. */
  dos_cc_new_create_cell(chan);
  current_circ_count = max_circuit_count - 1;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send 29 more CREATEs and ensure that the bucket is missing 30
   * tokens */
  for (i=0; i < 29; i++) {
   dos_cc_new_create_cell(chan);
   current_circ_count--;
  }
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* OK! Progress time forward one sec, refill the bucket and check that the
   * refill happened correctly. */
  now += 1;
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  /* check refill */
  current_circ_count += circ_rate;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
   dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now progress time a week forward, and check that the token bucket does not
   * have more than max_circs allowance, even tho we let it simmer for so
   * long. */
  now += 604800; /* a week */
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  current_circ_count += max_circuit_count;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now use a very large time, and check that the token bucket does not have
   * more than max_circs allowance, even tho we let it simmer for so long. */
  now = INT32_MAX; /* 2038? */
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  current_circ_count += max_circuit_count;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now use a very small time, and check that the token bucket has exactly
   * the max_circs allowance, because backward clock jumps are rare. */
  now = INT32_MIN; /* 19?? */
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  current_circ_count += max_circuit_count;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Progress time forward one sec again, refill the bucket and check that the
   * refill happened correctly. */
  now += 1;
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  /* check refill */
  current_circ_count += circ_rate;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now use a very large time (again), and check that the token bucket does
   * not have more than max_circs allowance, even tho we let it simmer for so
   * long. */
  now = INT32_MAX; /* 2038? */
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  current_circ_count += max_circuit_count;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* This code resets the time to zero with 32-bit time_t, which triggers the
   * code that initialises the bucket. */
#if SIZEOF_TIME_T == 8
  /* Now use a very very small time, and check that the token bucket has
   * exactly the max_circs allowance, because backward clock jumps are rare.
   */
  now = (time_t)INT64_MIN; /* ???? */
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  current_circ_count += max_circuit_count;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Progress time forward one sec again, refill the bucket and check that the
   * refill happened correctly. */
  now += 1;
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  /* check refill */
  current_circ_count += circ_rate;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now use a very very small time, and check that the token bucket has
   * exactly the max_circs allowance, because backward clock jumps are rare.
   */
  now = (time_t)INT64_MIN; /* ???? */
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  current_circ_count += max_circuit_count;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now use a very very large time, and check that the token bucket does not
   * have more than max_circs allowance, even tho we let it simmer for so
   * long. */
  now = (time_t)INT64_MAX; /* ???? */
  update_approx_time(now);
  cc_stats_refill_bucket(&dos_stats->cc_stats, addr);
  current_circ_count += max_circuit_count;
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);

  /* Now send as many CREATE cells as needed to deplete our token bucket
   * completely */
  for (; current_circ_count != 0; current_circ_count--) {
    dos_cc_new_create_cell(chan);
  }
  tt_uint_op(current_circ_count, OP_EQ, 0);
  tt_uint_op(dos_stats->cc_stats.circuit_bucket, OP_EQ, current_circ_count);
#endif /* SIZEOF_TIME_T == 8 */

 done:
  tor_free(chan);
  dos_free_all();
}

/* Test if we avoid counting a known relay. (We no longer do) */
static void
test_known_relay(void *arg)
{
  clientmap_entry_t *entry = NULL;
  routerstatus_t *rs = NULL;
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));

  (void) arg;

  MOCK(networkstatus_get_latest_consensus,
       mock_networkstatus_get_latest_consensus);
  MOCK(networkstatus_get_latest_consensus_by_flavor,
       mock_networkstatus_get_latest_consensus_by_flavor);
  MOCK(get_estimated_address_per_node,
       mock_get_estimated_address_per_node);
  MOCK(get_param_cc_enabled, mock_enable_dos_protection);

  dos_init();

  dummy_ns = tor_malloc_zero(sizeof(*dummy_ns));
  dummy_ns->flavor = FLAV_MICRODESC;
  dummy_ns->routerstatus_list = smartlist_new();

  /* Setup an OR conn so we can pass it to the DoS subsystem. */
  or_connection_t or_conn;
  memset(&or_conn, 0, sizeof or_conn);
  tor_addr_parse(&TO_CONN(&or_conn)->addr, "42.42.42.42");

  rs = tor_malloc_zero(sizeof(*rs));
  tor_addr_copy(&rs->ipv4_addr, &TO_CONN(&or_conn)->addr);
  crypto_rand(rs->identity_digest, sizeof(rs->identity_digest));
  smartlist_add(dummy_ns->routerstatus_list, rs);

  /* This will make the nodelist bloom filter very large
   * (the_nodelist->node_addrs) so we will fail the contain test rarely. */
  addr_per_node = 1024;
  nodelist_set_consensus(dummy_ns);

  /* We have now a node in our list so we'll make sure we don't count it as a
   * client connection. */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &TO_CONN(&or_conn)->addr,
                         NULL, 0);
  /* Suppose we have 5 connections in rapid succession */
  dos_new_client_conn(&or_conn, NULL);
  or_conn.tracked_for_dos_mitigation = 0;
  dos_new_client_conn(&or_conn, NULL);
  or_conn.tracked_for_dos_mitigation = 0;
  dos_new_client_conn(&or_conn, NULL);
  or_conn.tracked_for_dos_mitigation = 0;
  dos_new_client_conn(&or_conn, NULL);
  or_conn.tracked_for_dos_mitigation = 0;
  dos_new_client_conn(&or_conn, NULL);
  entry = geoip_lookup_client(&TO_CONN(&or_conn)->addr, NULL,
                              GEOIP_CLIENT_CONNECT);
  tt_assert(entry);
  /* We should have a count of 5. */
  tt_uint_op(entry->dos_stats.conn_stats.concurrent_count, OP_EQ, 5);

  /* A channel's previous hop is a known relay only if we know its identity,
   * and a client if it never authenticated, whatever its identity. */
  tt_int_op(channel_get_prev_hop(chan), OP_EQ, CHANNEL_PREV_HOP_UNKNOWN_RELAY);
  memcpy(chan->identity_digest, rs->identity_digest, DIGEST_LEN);
  tt_int_op(channel_get_prev_hop(chan), OP_EQ, CHANNEL_PREV_HOP_KNOWN_RELAY);
  chan->is_client = 1;
  tt_int_op(channel_get_prev_hop(chan), OP_EQ, CHANNEL_PREV_HOP_CLIENT);

 done:
  tor_free(chan);
  routerstatus_free(rs);
  smartlist_clear(dummy_ns->routerstatus_list);
  networkstatus_vote_free(dummy_ns);
  dos_free_all();
  UNMOCK(networkstatus_get_latest_consensus);
  UNMOCK(networkstatus_get_latest_consensus_by_flavor);
  UNMOCK(get_estimated_address_per_node);
  UNMOCK(get_param_cc_enabled);
}

/** Test that the connection tracker of the DoS subsystem will block clients
 *  who try to establish too many connections */
static void
test_dos_conn_rate(void *arg)
{
  (void) arg;

  MOCK(get_param_cc_enabled, mock_enable_dos_protection);
  MOCK(get_param_conn_enabled, mock_enable_dos_protection);

  /* Initialize test data */
  or_connection_t or_conn;
  memset(&or_conn, 0, sizeof or_conn);
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&TO_CONN(&or_conn)->addr,
                                          "18.0.0.1"));
  tor_addr_t *addr = &TO_CONN(&or_conn)->addr;
  update_approx_time(now);

  /* Get DoS subsystem limits */
  dos_init();
  uint32_t burst_conn = get_param_conn_connect_burst(NULL);

  /* Introduce new client */
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, addr, NULL, now);
  { /* Register many conns from this client but not enough to get it blocked */
    unsigned int i;
    for (i = 0; i < burst_conn - 1; i++) {
      or_conn.tracked_for_dos_mitigation = 0;
      dos_new_client_conn(&or_conn, NULL);
    }
  }

  /* Check that new conns are still permitted */
  tt_int_op(DOS_CONN_DEFENSE_NONE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Register another conn and check that new conns are not allowed anymore.
   * We should have reached our burst. */
  or_conn.tracked_for_dos_mitigation = 0;
  dos_new_client_conn(&or_conn, NULL);
  tt_int_op(DOS_CONN_DEFENSE_CLOSE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Advance the time 12 hours. It should still be blocked. */
  update_approx_time(now + (12 * 60 * 60));
  tt_int_op(DOS_CONN_DEFENSE_CLOSE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

  /* Advance the time 24 hours plus 13 hours. It should be unblocked.
   * Remember, we had a random value between 24 hours and rand(24/2) thus
   * adding 13 hours is safe. */
  update_approx_time(now + (37 * 60 * 60));
  tt_int_op(DOS_CONN_DEFENSE_NONE, OP_EQ,
            dos_conn_addr_get_defense_type(addr));

 done:
  dos_free_all();
}

/** Test the one BEGIN_DIR per circuit limit. */
static void
test_dos_begindir_limit(void *arg)
{
  channel_t relay_chan = {0}, client_chan = {0};
  or_circuit_t *relay_circ = NULL, *client_circ = NULL;
  (void) arg;

  channel_mark_client(&client_chan);
  relay_circ = or_circuit_new(0, NULL);
  relay_circ->p_chan = &relay_chan;
  client_circ = or_circuit_new(0, NULL);
  client_circ->p_chan = &client_chan;

  /* Disabled: the allowance is used, but nothing is refused. */
  dos_init();
  tt_assert(!dos_begindir_should_refuse(relay_circ));
  tt_uint_op(relay_circ->already_received_begindir, OP_EQ, 1);
  tt_assert(!dos_begindir_should_refuse(relay_circ));
  tt_u64_op(dos_get_num_begindir_rejected(), OP_EQ, 0);

  /* Enabled: the circuit used its allowance before, so it is refused. */
  MOCK(get_param_begindir_limit_enabled, mock_enable_dos_protection);
  dos_init();
  tt_assert(dos_begindir_should_refuse(relay_circ));
  tt_u64_op(dos_get_num_begindir_rejected(), OP_EQ, 1);

  /* Clients and bridges are never limited. */
  tt_assert(!dos_begindir_should_refuse(client_circ));
  tt_assert(!dos_begindir_should_refuse(client_circ));
  tt_uint_op(client_circ->already_received_begindir, OP_EQ, 0);
  tt_u64_op(dos_get_num_begindir_rejected(), OP_EQ, 1);

 done:
  UNMOCK(get_param_begindir_limit_enabled);
  if (relay_circ) {
    relay_circ->p_chan = NULL;
    circuit_free_(TO_CIRCUIT(relay_circ));
  }
  if (client_circ) {
    client_circ->p_chan = NULL;
    circuit_free_(TO_CIRCUIT(client_circ));
  }
  dos_free_all();
}

/** Test that dos_should_refuse_single_hop_client() follows the torrc, else
 * the consensus, and only applies on public relays. */
static void
test_dos_refuse_single_hop(void *arg)
{
  dos_options_t *dos_opts = get_dos_options(get_options_mutable());
  (void) arg;

  MOCK(networkstatus_get_latest_consensus,
       mock_networkstatus_get_latest_consensus);
  dummy_ns = tor_malloc_zero(sizeof(networkstatus_t));
  dummy_ns->net_params = smartlist_new();
  smartlist_add(dummy_ns->net_params,
                (char *) "DoSRefuseSingleHopClientRendezvous=1");
  get_options_mutable()->ORPort_set = 1;
  tt_int_op(dos_should_refuse_single_hop_client(), OP_EQ, 1);
  dos_opts->DoSRefuseSingleHopClientRendezvous = 0;
  tt_int_op(dos_should_refuse_single_hop_client(), OP_EQ, 0);
  dos_opts->DoSRefuseSingleHopClientRendezvous = 1;
  get_options_mutable()->ORPort_set = 0;
  tt_int_op(dos_should_refuse_single_hop_client(), OP_EQ, 0);

 done:
  UNMOCK(networkstatus_get_latest_consensus);
  if (dummy_ns)
    smartlist_free(dummy_ns->net_params);
  tor_free(dummy_ns);
}

static int n_connected = 0, n_end = 0, end_reason = 0;
static int
mock_relay_send_command_from_edge(streamid_t stream_id, circuit_t *circ,
                                  uint8_t relay_command, const char *payload,
                                  size_t payload_len,
                                  crypt_path_t *cpath_layer,
                                  const char *filename, int lineno)
{
  (void) stream_id;
  (void) circ;
  (void) cpath_layer;
  (void) filename;
  (void) lineno;
  if (relay_command == RELAY_COMMAND_CONNECTED)
    n_connected++;
  if (relay_command == RELAY_COMMAND_END) {
    n_end++;
    end_reason = payload_len ? payload[0] : -1;
  }
  return 0;
}

static int hibernating = 0;
static int
mock_we_are_hibernating(void)
{
  return hibernating;
}

/** Test that every CREATE cell is counted by its previous hop, even one we
 * drop, and that the circuit it makes keeps that kind. */
static void
test_dos_create_cell_prev_hop(void *arg)
{
  channel_t *chan = new_fake_channel();
  cell_t cell;
  const smartlist_t *circs = circuit_get_global_list();
  const channel_prev_hop_t hop = CHANNEL_PREV_HOP_UNKNOWN_RELAY;
  (void) arg;

  MOCK(we_are_hibernating, mock_we_are_hibernating);
  get_options_mutable()->ORPort_set = 1;
  chan->circ_id_type = CIRC_ID_TYPE_NEITHER;
  memset(&cell, 0, sizeof(cell));
  cell.command = CELL_CREATE2;

  /* Dropped: circuit ID 0. */
  command_process_cell(chan, &cell);
  tt_u64_op(rep_hist_get_create_cells()[hop], OP_EQ, 1);
  tt_int_op(smartlist_len(circs), OP_EQ, 0);
  /* An unknown handshake type makes a circuit, which we close. */
  cell.circ_id = 1;
  set_uint16(cell.payload, htons(0xffff));
  command_process_cell(chan, &cell);
  tt_u64_op(rep_hist_get_create_cells()[hop], OP_EQ, 2);
  tt_int_op(smartlist_len(circs), OP_EQ, 1);
  tt_int_op(TO_OR_CIRCUIT(smartlist_get(circs, 0))->prev_hop, OP_EQ, hop);
  chan->is_client = 1;
  cell.circ_id = 2;
  command_process_cell(chan, &cell);
  tt_u64_op(rep_hist_get_create_cells()[CHANNEL_PREV_HOP_CLIENT], OP_EQ, 1);
  tt_int_op(smartlist_len(circs), OP_EQ, 2);
  tt_int_op(TO_OR_CIRCUIT(smartlist_get(circs, 1))->prev_hop, OP_EQ,
            CHANNEL_PREV_HOP_CLIENT);

 done:
  UNMOCK(we_are_hibernating);
  circuit_free_all();
  free_fake_channel(chan);
}

/** Test that connection_exit_begin_conn() counts every BEGIN_DIR cell by its
 * place on its circuit, also those that tor refuses, and that the directory
 * connections it opens know the circuit's previous hop. */
static void
test_dos_begindir_refused(void *arg)
{
  or_circuit_t *circ = NULL;
  dos_options_t *dos_opts = get_dos_options(get_options_mutable());
  relay_msg_t msg;
  const channel_prev_hop_t hop = CHANNEL_PREV_HOP_UNKNOWN_RELAY;
  (void) arg;

  tor_init_connection_lists();
  MOCK(relay_send_command_from_edge_, mock_relay_send_command_from_edge);
  MOCK(we_are_hibernating, mock_we_are_hibernating);
  get_options_mutable()->ORPort_set = 1;
  get_options_mutable()->DirPort_set = 1;
  get_options_mutable()->DirCache = 1;
  /* The BEGIN_DIR rate limit lets a new circuit open two streams, and
   * refuses the third. Time doesn't pass. */
  monotime_enable_test_mocking();
  monotime_coarse_set_mock_time_nsec(BILLION);
  dos_opts->DoSBeginDirRateEnabled = 1;
  dos_opts->DoSBeginDirRate = 1;
  dos_opts->DoSBeginDirBurst = 2;
  dos_opts->DoSBeginDirDefenseType = DOS_STREAM_DEFENSE_REFUSE_STREAM;
  dos_init();
  circ = or_circuit_new(0, NULL);
  circ->prev_hop = hop;
  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_OR;
  memset(&msg, 0, sizeof(msg));
  msg.command = RELAY_COMMAND_BEGIN_DIR;
  msg.body = (const uint8_t *) "";

  for (msg.stream_id = 1; msg.stream_id <= 3; msg.stream_id++)
    tt_int_op(connection_exit_begin_conn(&msg, TO_CIRCUIT(circ)), OP_EQ, 0);
  tt_int_op(n_connected, OP_EQ, 2);
  tt_int_op(n_end, OP_EQ, 1);
  tt_int_op(end_reason, OP_EQ, END_STREAM_REASON_MISC);
  tt_u64_op(dos_get_num_begindir_rate_rejected(), OP_EQ, 1);
  /* Two linked pairs, whose directory connections know the previous hop. */
  tt_int_op(smartlist_len(get_connection_array()), OP_EQ, 4);
  SMARTLIST_FOREACH(get_connection_array(), connection_t *, c, {
    if (c->type == CONN_TYPE_DIR)
      tt_int_op(TO_DIR_CONN(c)->prev_hop, OP_EQ, hop);
  });
  /* Every cell is counted, the refused one too. */
  tt_u64_op(rep_hist_get_begindir_cells(hop)[NTH_BAND_1], OP_EQ, 1);
  tt_u64_op(rep_hist_get_begindir_cells(hop)[NTH_BAND_2_10], OP_EQ, 2);

  /* So are cells that tor refuses when we're not a directory cache, and
   * when we're hibernating, which it checks after the BEGIN_DIR limits. */
  get_options_mutable()->DirPort_set = 0;
  get_options_mutable()->DirCache = 0;
  tt_int_op(connection_exit_begin_conn(&msg, TO_CIRCUIT(circ)), OP_EQ, 0);
  tt_int_op(end_reason, OP_EQ, END_STREAM_REASON_NOTDIRECTORY);
  get_options_mutable()->DirPort_set = 1;
  get_options_mutable()->DirCache = 1;
  dos_opts->DoSBeginDirRateEnabled = 0;
  dos_init();
  hibernating = 1;
  msg.stream_id++;
  tt_int_op(connection_exit_begin_conn(&msg, TO_CIRCUIT(circ)), OP_EQ, 0);
  tt_int_op(end_reason, OP_EQ, END_STREAM_REASON_HIBERNATING);
  hibernating = 0;
  tt_u64_op(rep_hist_get_begindir_cells(hop)[NTH_BAND_2_10], OP_EQ, 4);
  tt_int_op(n_connected, OP_EQ, 2);

 done:
  UNMOCK(relay_send_command_from_edge_);
  UNMOCK(we_are_hibernating);
  monotime_disable_test_mocking();
  SMARTLIST_FOREACH(get_connection_array(), connection_t *, c, {
    if (c->type == CONN_TYPE_EXIT)
      TO_EDGE_CONN(c)->on_circuit = NULL;
  });
  if (circ)
    circ->n_streams = NULL;
  while (smartlist_len(get_connection_array())) {
    connection_t *c = smartlist_get(get_connection_array(), 0);
    /* Take c off the active linked list before we free it. */
    if (c->linked)
      connection_stop_reading_from_linked_conn(c);
    connection_remove(c);
    connection_free_(c);
  }
  circuit_free_all();
}

/** Test that the heartbeat shows the directory request counts of each
 * defense once it is enabled. */
static void
test_dos_dir_heartbeat(void *arg)
{
  dos_options_t *dos_opts = get_dos_options(get_options_mutable());
  (void) arg;

  get_options_mutable()->ORPort_set = 1;
  dos_opts->HSDirRefuseUnknownPrevHop = 1;
  dos_opts->HSDirFetchShedding = 1;
  dos_init();
  dos_note_dir_stat(DOS_DIR_HSDIR_FETCH_SHED);
  dos_note_dir_stat(DOS_DIR_HSDIR_UNKNOWN_PREV_HOP);
  dos_note_dir_stat(DOS_DIR_HSDIR_UNKNOWN_PREV_HOP);
  setup_full_capture_of_logs(LOG_NOTICE);
  dos_log_heartbeat();
  expect_single_log_msg_containing("2 HSDir requests from unknown relays, "
                                   "1 HSDir descriptor fetches selected "
                                   "for shedding");

 done:
  teardown_capture_of_logs();
}

static uint32_t lottery_draw;
static uint32_t
mock_hsdir_fetch_lottery_draw(void)
{
  return lottery_draw;
}

static int observed_bw;
static int
mock_bwhist_bandwidth_assess(void)
{
  return observed_bw;
}

/** Ask for <b>n</b> fetches of <b>len</b> bytes of the descriptor whose fetch
 * rate limiter is <b>bucket</b>. Return how many are answered. */
static int
hsdir_fetches(token_bucket_ctr_t *bucket, int n, size_t len)
{
  int answered = 0;
  for (int i = 0; i < n; i++)
    answered += dos_hsdir_desc_fetch_allowed(bucket, len);
  return answered;
}

static void
test_dos_hsdir_fetch_shedding(void *arg)
{
  dos_options_t *dos_opts = get_dos_options(get_options_mutable());
  or_options_t *options = get_options_mutable();
  token_bucket_ctr_t a, b, c;
  uint64_t now = 100 * BILLION;
  uint64_t shed;
  (void) arg;

  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  memset(&c, 0, sizeof(c));
  monotime_enable_test_mocking();
  monotime_coarse_set_mock_time_nsec(now);
  MOCK(hsdir_fetch_lottery_draw, mock_hsdir_fetch_lottery_draw);
  MOCK(networkstatus_get_latest_consensus,
       mock_networkstatus_get_latest_consensus);
  options->ORPort_set = 1;
  dos_opts->HSDirFetchShedding = 1;
  dos_opts->HSDirDescriptorFetchRate = 1;
  dos_opts->HSDirDescriptorFetchBurst = 1;
  dos_opts->HSDirFetchBudget = 1000; /* Ten 100-byte fetches a second. */
  lottery_draw = 999999; /* Every lottery is lost. */

  /* Within the budget, nothing is refused, even over a descriptor's rate. */
  for (int i = 0; i < 3; i++) {
    tt_int_op(hsdir_fetches(&a, 10, 100), OP_EQ, 10);
    monotime_coarse_set_mock_time_nsec(now += BILLION);
  }
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_OVER_RATE), OP_EQ, 27);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_PRESSURE), OP_EQ, 0);

  /* In a first second over it, at most half again the budget is answered. */
  tt_int_op(hsdir_fetches(&a, 100, 100), OP_EQ, 15);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_PRESSURE), OP_EQ, 90);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_SHED), OP_EQ, 85);

  /* In the next second, fetches within their descriptor's rate are answered
   * first, up to half the budget, even after the others: those are shed
   * unless they win the lottery, up to the budget. */
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&b, 1, 100), OP_EQ, 1);
  tt_int_op(hsdir_fetches(&a, 100, 100), OP_EQ, 1);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_SHED), OP_EQ, 85 + 99);
  lottery_draw = 0;
  tt_int_op(hsdir_fetches(&a, 100, 100), OP_EQ, 10);
  tt_int_op(hsdir_fetches(&c, 1, 100), OP_EQ, 1);

  /* The odds would have kept the last second within the budget: of its
   * 20200 bytes asked for, 300 were within their rates, so a fetch is
   * answered with chance (1000 - 300) / (20200 - 300). */
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  lottery_draw = 35175;
  tt_int_op(hsdir_fetches(&a, 2, 100), OP_EQ, 1);
  lottery_draw = 35174;
  tt_int_op(hsdir_fetches(&a, 1, 100), OP_EQ, 1);

  /* With the defense off, the same fetches are counted, and answered. */
  dos_opts->HSDirFetchShedding = 0;
  lottery_draw = 999999;
  shed = dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_SHED);
  tt_int_op(hsdir_fetches(&a, 10, 100), OP_EQ, 10);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_SHED), OP_EQ, shed + 10);

  /* The consensus can enable it, the torrc overrides it, and it only applies
   * to public relays. */
  dos_opts->HSDirFetchShedding = -1;
  tt_int_op(hsdir_fetches(&a, 1, 100), OP_EQ, 1);
  dummy_ns = tor_malloc_zero(sizeof(networkstatus_t));
  dummy_ns->net_params = smartlist_new();
  smartlist_add(dummy_ns->net_params, (char *) "HSDirFetchShedding=1");
  tt_int_op(hsdir_fetches(&a, 1, 100), OP_EQ, 0);
  options->ORPort_set = 0;
  tt_int_op(hsdir_fetches(&a, 1, 100), OP_EQ, 1);
  options->ORPort_set = 1;
  dos_opts->HSDirFetchShedding = 1;

  /* A flood every other second is held to half again the budget. */
  lottery_draw = 0;
  for (int i = 0; i < 2; i++) {
    monotime_coarse_set_mock_time_nsec(now += BILLION);
    tt_int_op(hsdir_fetches(&b, 1, 100), OP_EQ, 1);
    monotime_coarse_set_mock_time_nsec(now += BILLION);
    tt_int_op(hsdir_fetches(&a, 100, 100), OP_EQ, 15);
  }

  /* After a second without fetches, nothing is shed. */
  lottery_draw = 999999;
  monotime_coarse_set_mock_time_nsec(now += 2 * BILLION);
  tt_int_op(hsdir_fetches(&a, 10, 100), OP_EQ, 10);

  /* By default, the budget is a share of the lower of the configured and
   * the observed bandwidth, and at least 512 KB. */
  dos_opts->HSDirFetchBudget = 0;
  MOCK(bwhist_bandwidth_assess, mock_bwhist_bandwidth_assess);
  options->BandwidthRate = options->MaxAdvertisedBandwidth = 10000000;
  options->RelayBandwidthRate = 0;
  observed_bw = 4000000;
  tt_u64_op(hsdir_fetch_budget(), OP_EQ, 2000000);
  observed_bw = 0;
  tt_u64_op(hsdir_fetch_budget(), OP_EQ, 5000000);
  smartlist_add(dummy_ns->net_params, (char *) "HSDirFetchBudgetPercent=20");
  tt_u64_op(hsdir_fetch_budget(), OP_EQ, 2000000);
  options->BandwidthRate = 100000;
  tt_u64_op(hsdir_fetch_budget(), OP_EQ, 512 * 1024);
  /* The consensus percentage is clamped to [1, 100], and an explicit budget
   * is capped at UINT32_MAX. */
  options->BandwidthRate = options->MaxAdvertisedBandwidth = 100000000;
  smartlist_clear(dummy_ns->net_params);
  smartlist_add(dummy_ns->net_params, (char *) "HSDirFetchBudgetPercent=0");
  tt_u64_op(hsdir_fetch_budget(), OP_EQ, 1000000);
  smartlist_clear(dummy_ns->net_params);
  smartlist_add(dummy_ns->net_params, (char *) "HSDirFetchBudgetPercent=200");
  tt_u64_op(hsdir_fetch_budget(), OP_EQ, 100000000);
  dos_opts->HSDirFetchBudget = UINT64_C(1) << 40;
  tt_u64_op(hsdir_fetch_budget(), OP_EQ, UINT32_MAX);

 done:
  monotime_disable_test_mocking();
  UNMOCK(hsdir_fetch_lottery_draw);
  UNMOCK(networkstatus_get_latest_consensus);
  UNMOCK(bwhist_bandwidth_assess);
  if (dummy_ns)
    smartlist_free(dummy_ns->net_params);
  tor_free(dummy_ns);
}

/* Edges of HSDir fetch shedding that test_dos_hsdir_fetch_shedding() does
 * not reach. Budget 1000, fetches of 100 bytes, rate 1, burst 1. */
static void
test_dos_hsdir_fetch_shedding_edges(void *arg)
{
  dos_options_t *dos_opts = get_dos_options(get_options_mutable());
  or_options_t *options = get_options_mutable();
  token_bucket_ctr_t heavy, lb[6];
  uint64_t now = 0;
  uint64_t shed, over;
  uint32_t max_draw = 0;
  int n;
  (void) arg;

  memset(&heavy, 0, sizeof(heavy));
  memset(lb, 0, sizeof(lb));
  monotime_enable_test_mocking();
  monotime_coarse_set_mock_time_nsec(now);

  /* the documented defaults. */
  tt_int_op(dos_opts->HSDirDescriptorFetchRate, OP_EQ, 5);
  tt_int_op(dos_opts->HSDirDescriptorFetchBurst, OP_EQ, 20);
  tt_int_op(dos_opts->HSDirFetchShedding, OP_EQ, -1);
  tt_u64_op(dos_opts->HSDirFetchBudget, OP_EQ, 0);
  options->ORPort_set = 1;
  dos_opts->HSDirFetchShedding = 1;
  dos_opts->HSDirDescriptorFetchRate = 1;
  dos_opts->HSDirDescriptorFetchBurst = 1;
  dos_opts->HSDirFetchBudget = 1000;

  /* the real lottery draws below a million, over the whole range. */
  for (int i = 0; i < 1000; i++) {
    uint32_t d = hsdir_fetch_lottery_draw();
    tt_u64_op(d, OP_LT, 1000000);
    max_draw = MAX(max_draw, d);
  }
  tt_u64_op(max_draw, OP_GE, 500000);
  MOCK(hsdir_fetch_lottery_draw, mock_hsdir_fetch_lottery_draw);
  lottery_draw = 999999;

  /* second 0, the first of the process, is within the budget too. */
  tt_int_op(hsdir_fetches(&heavy, 10, 100), OP_EQ, 10);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_PRESSURE), OP_EQ, 0);

  /* a new HSDirFetchBudget applies from the next second. */
  dos_opts->HSDirFetchBudget = 2000;
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 20, 100), OP_EQ, 20);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_PRESSURE), OP_EQ, 0);
  dos_opts->HSDirFetchBudget = 1000;

  /* a second's first answer is never over the ceiling, however large.
   * However far over the budget a second was, a fetch the next second still
   * wins the lottery with a chance of 1000 in a million. */
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 1, 2000000), OP_EQ, 1);
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 0);
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 1); /* Within its rate. */
  lottery_draw = 999;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 1);
  lottery_draw = 1000;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 0);

  /* an over-budget second: 2000 bytes asked, 100 within their rate. */
  lottery_draw = 999999;
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 20, 100), OP_EQ, 15);

  /* while shedding, fetches within their rate are answered first up to
   * half the budget, and no further. */
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  for (n = 0; n < 6; n++)
    if (!hsdir_fetches(&lb[n], 1, 100))
      break;
  tt_int_op(n, OP_EQ, 5);
  tt_int_op(hsdir_fetches(&heavy, 20, 100), OP_EQ, 0);

  /* the share of fetches within their rate is per second; the odds
   * count at most half the budget of the 700 bytes asked within their rate:
   * (1000 - 500) / (2600 - 500), or 238095 in a million. */
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  for (n = 0; n < 6; n++)
    if (!hsdir_fetches(&lb[n], 1, 100))
      break;
  tt_int_op(n, OP_EQ, 5);
  lottery_draw = 238094;
  tt_int_op(hsdir_fetches(&heavy, 2, 100), OP_EQ, 2);
  lottery_draw = 238095;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 0);
  lottery_draw = 999999;
  tt_int_op(hsdir_fetches(&heavy, 20, 100), OP_EQ, 0);

  /* when not enforcing, fetches that would be shed don't count towards
   * the hard ceiling, so the counters mirror enforcement. */
  dos_opts->HSDirFetchShedding = 0;
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  shed = dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_SHED);
  tt_int_op(hsdir_fetches(&heavy, 20, 100), OP_EQ, 20);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_SHED), OP_EQ, shed + 19);
  tt_int_op(hsdir_fetches(&lb[0], 1, 100), OP_EQ, 1);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_SHED), OP_EQ, shed + 19);

  /* a new HSDirFetchBudget changes neither whether the second after one
   * over the old budget sheds nor its odds: (1000 - 100) / (2000 - 100), or
   * 473684 in a million. */
  dos_opts->HSDirFetchShedding = 1;
  monotime_coarse_set_mock_time_nsec(now += 2 * BILLION);
  tt_int_op(hsdir_fetches(&heavy, 20, 100), OP_EQ, 15);
  dos_opts->HSDirFetchBudget = 2000;
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 1); /* Within its rate. */
  lottery_draw = 473683;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 1);
  lottery_draw = 473684;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 0);

  /* nor how much of what was asked within its rate is answered first: half
   * the old budget. Of the 2000 bytes asked in a second over a budget of
   * 1000, 600 are within their rates, so the odds are (1000 - 500) /
   * (2000 - 500), or 333333 in a million, even if the budget is then 2000. */
  dos_opts->HSDirFetchBudget = 1000;
  lottery_draw = 999999;
  monotime_coarse_set_mock_time_nsec(now += 2 * BILLION);
  for (n = 0; n < 5; n++)
    hsdir_fetches(&lb[n], 1, 100);
  hsdir_fetches(&heavy, 15, 100);
  dos_opts->HSDirFetchBudget = 2000;
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 1); /* Within its rate. */
  lottery_draw = 333332;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 1);
  lottery_draw = 333333;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 0);

  /* the budget, the ceiling and the share answered first are exact to the
   * byte, and a second keeps the budget it started with: a second asked for
   * one byte over its budget is over it, and answers up to exactly half
   * again its budget; the next answers first up to exactly half of it; and
   * a second asked for one byte over its budget is followed by one that
   * sheds. */
  dos_opts->HSDirFetchBudget = 1000;
  lottery_draw = 999999;
  monotime_coarse_set_mock_time_nsec(now += 2 * BILLION);
  over = dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_PRESSURE);
  tt_int_op(hsdir_fetches(&heavy, 1, 1000), OP_EQ, 1);
  dos_opts->HSDirFetchBudget = 2000;
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_PRESSURE), OP_EQ, over);
  tt_int_op(hsdir_fetches(&heavy, 1, 1), OP_EQ, 1);
  tt_u64_op(dos_get_dir_stat(DOS_DIR_HSDIR_FETCH_PRESSURE), OP_EQ, over + 1);
  tt_int_op(hsdir_fetches(&heavy, 1, 499), OP_EQ, 1);
  tt_int_op(hsdir_fetches(&heavy, 1, 1), OP_EQ, 0);
  dos_opts->HSDirFetchBudget = 1000;
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&lb[0], 1, 500), OP_EQ, 1);
  dos_opts->HSDirFetchBudget = 2000;
  tt_int_op(hsdir_fetches(&lb[1], 1, 1), OP_EQ, 0);
  dos_opts->HSDirFetchBudget = 1000;
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 1, 1001), OP_EQ, 1);
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 2, 100), OP_EQ, 1);

  /* the share of fetches within their rate in the odds counts the bytes
   * asked for, answered or not: of 2000 bytes asked, 300 within their rates,
   * 200 of them shed at the ceiling, (1000 - 300) / (2000 - 300), or 411764
   * in a million. */
  dos_opts->HSDirFetchBudget = 1000;
  monotime_coarse_set_mock_time_nsec(now += 2 * BILLION);
  tt_int_op(hsdir_fetches(&heavy, 15, 100), OP_EQ, 15);
  tt_int_op(hsdir_fetches(&lb[0], 1, 100), OP_EQ, 0);
  tt_int_op(hsdir_fetches(&lb[1], 1, 100), OP_EQ, 0);
  tt_int_op(hsdir_fetches(&heavy, 3, 100), OP_EQ, 0);
  monotime_coarse_set_mock_time_nsec(now += BILLION);
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 1); /* Within its rate. */
  lottery_draw = 411763;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 1);
  lottery_draw = 411764;
  tt_int_op(hsdir_fetches(&heavy, 1, 100), OP_EQ, 0);

 done:
  monotime_disable_test_mocking();
  UNMOCK(hsdir_fetch_lottery_draw);
}

struct testcase_t dos_tests[] = {
  { "conn_creation", test_dos_conn_creation, TT_FORK, NULL, NULL },
  { "circuit_creation", test_dos_circuit_creation, TT_FORK, NULL, NULL },
  { "bucket_refill", test_dos_bucket_refill, TT_FORK, NULL, NULL },
  { "known_relay" , test_known_relay, TT_FORK,
    NULL, NULL },
  { "conn_rate", test_dos_conn_rate, TT_FORK, NULL, NULL },
  { "begindir_limit", test_dos_begindir_limit, TT_FORK, NULL, NULL },
  { "refuse_single_hop", test_dos_refuse_single_hop, TT_FORK, NULL, NULL },
  { "begindir_refused", test_dos_begindir_refused, TT_FORK, NULL, NULL },
  { "create_cell_prev_hop", test_dos_create_cell_prev_hop, TT_FORK,
    NULL, NULL },
  { "dir_heartbeat", test_dos_dir_heartbeat, TT_FORK, NULL, NULL },
  { "hsdir_fetch_shedding", test_dos_hsdir_fetch_shedding, TT_FORK,
    NULL, NULL },
  { "hsdir_fetch_shedding_edges", test_dos_hsdir_fetch_shedding_edges,
    TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
