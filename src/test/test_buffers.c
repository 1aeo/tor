/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define BUFFERS_PRIVATE
#define PROTO_HTTP_PRIVATE
#include "core/or/or.h"
#include "lib/buf/buffers.h"
#include "lib/tls/buffers_tls.h"
#include "lib/tls/tortls.h"
#include "lib/compress/compress.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "core/proto/proto_http.h"
#include "core/proto/proto_socks.h"
#include "lib/net/buffers_net.h"
#include "test/rng_test_helpers.h"
#include "test/test.h"

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

/* When built with AddressSanitizer, the bug 41377 tests below poison the
 * memory of each chunk that is not buffer data while the code under test
 * runs, so that ASan reports a search that so much as reads it, even when the
 * stale value would not change the answer.  (ASan works in 8-byte granules,
 * so up to 7 bytes at the end of each such region can stay addressable; the
 * start of an empty chunk's memory, where a stale read begins, is always
 * poisoned.)  Without ASan, all of this compiles to nothing. */
#if defined(__SANITIZE_ADDRESS__)
/* GCC */
#define BUF_TEST_HAVE_ASAN
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
/* clang */
#define BUF_TEST_HAVE_ASAN
#endif
#endif /* defined(__SANITIZE_ADDRESS__) || ... */

#ifdef BUF_TEST_HAVE_ASAN
#if defined(__has_include)
#if __has_include(<sanitizer/asan_interface.h>)
#include <sanitizer/asan_interface.h>
#define BUF_TEST_HAVE_ASAN_INTERFACE_H
#endif
#endif /* defined(__has_include) */
#ifndef BUF_TEST_HAVE_ASAN_INTERFACE_H
/* Every ASan runtime provides these, even where the header is missing. */
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
void __asan_set_death_callback(void (*callback)(void));
#endif /* !defined(BUF_TEST_HAVE_ASAN_INTERFACE_H) */
#define BUF_TEST_POISON(p, n) __asan_poison_memory_region((p), (n))
#define BUF_TEST_UNPOISON(p, n) __asan_unpoison_memory_region((p), (n))
/* An ASan report kills the process before tinytest can print the seed of a
 * failed reproducible-RNG test, so have ASan print it. */
#define BUF_TEST_ON_ASAN_DEATH(fn) __asan_set_death_callback(fn)
#else /* !defined(BUF_TEST_HAVE_ASAN) */
#define BUF_TEST_POISON(p, n) ((void)(p), (void)(n))
#define BUF_TEST_UNPOISON(p, n) ((void)(p), (void)(n))
#define BUF_TEST_ON_ASAN_DEATH(fn) ((void)0)
#endif /* defined(BUF_TEST_HAVE_ASAN) */

/** Run unit tests for buffers.c */
static void
test_buffers_basic(void *arg)
{
  char str[256];
  char str2[256];

  buf_t *buf = NULL, *buf2 = NULL;
  const char *cp;

  int j;
  size_t r;
  (void) arg;

  /****
   * buf_new
   ****/
  if (!(buf = buf_new()))
    TT_DIE(("Assertion failed."));

  //test_eq(buf_capacity(buf), 4096);
  tt_int_op(buf_datalen(buf),OP_EQ, 0);

  /****
   * General pointer frobbing
   */
  for (j=0;j<256;++j) {
    str[j] = (char)j;
  }
  buf_add(buf, str, 256);
  buf_add(buf, str, 256);
  tt_int_op(buf_datalen(buf),OP_EQ, 512);
  buf_get_bytes(buf, str2, 200);
  tt_mem_op(str,OP_EQ, str2, 200);
  tt_int_op(buf_datalen(buf),OP_EQ, 312);
  memset(str2, 0, sizeof(str2));

  buf_get_bytes(buf, str2, 256);
  tt_mem_op(str+200,OP_EQ, str2, 56);
  tt_mem_op(str,OP_EQ, str2+56, 200);
  tt_int_op(buf_datalen(buf),OP_EQ, 56);
  memset(str2, 0, sizeof(str2));
  /* Okay, now we should be 512 bytes into the 4096-byte buffer.  If we add
   * another 3584 bytes, we hit the end. */
  for (j=0;j<15;++j) {
    buf_add(buf, str, 256);
  }
  buf_assert_ok(buf);
  tt_int_op(buf_datalen(buf),OP_EQ, 3896);
  buf_get_bytes(buf, str2, 56);
  tt_int_op(buf_datalen(buf),OP_EQ, 3840);
  tt_mem_op(str+200,OP_EQ, str2, 56);
  for (j=0;j<15;++j) {
    memset(str2, 0, sizeof(str2));
    buf_get_bytes(buf, str2, 256);
    tt_mem_op(str,OP_EQ, str2, 256);
  }
  tt_int_op(buf_datalen(buf),OP_EQ, 0);
  buf_free(buf);
  buf = NULL;

  /* Okay, now make sure growing can work. */
  buf = buf_new_with_capacity(16);
  //test_eq(buf_capacity(buf), 16);
  buf_add(buf, str+1, 255);
  //test_eq(buf_capacity(buf), 256);
  buf_get_bytes(buf, str2, 254);
  tt_mem_op(str+1,OP_EQ, str2, 254);
  //test_eq(buf_capacity(buf), 256);
  buf_assert_ok(buf);
  buf_add(buf, str, 32);
  //test_eq(buf_capacity(buf), 256);
  buf_assert_ok(buf);
  buf_add(buf, str, 256);
  buf_assert_ok(buf);
  //test_eq(buf_capacity(buf), 512);
  tt_int_op(buf_datalen(buf),OP_EQ, 33+256);
  buf_get_bytes(buf, str2, 33);
  tt_int_op(*str2,OP_EQ, str[255]);

  tt_mem_op(str2+1,OP_EQ, str, 32);
  //test_eq(buf_capacity(buf), 512);
  tt_int_op(buf_datalen(buf),OP_EQ, 256);
  buf_get_bytes(buf, str2, 256);
  tt_mem_op(str,OP_EQ, str2, 256);

  /* now try shrinking: case 1. */
  buf_free(buf);
  buf = buf_new_with_capacity(33668);
  for (j=0;j<67;++j) {
    buf_add(buf, str,255);
  }
  //test_eq(buf_capacity(buf), 33668);
  tt_int_op(buf_datalen(buf),OP_EQ, 17085);
  for (j=0; j < 40; ++j) {
    buf_get_bytes(buf, str2, 255);
    tt_mem_op(str2,OP_EQ, str, 255);
  }

  /* now try shrinking: case 2. */
  buf_free(buf);
  buf = buf_new_with_capacity(33668);
  for (j=0;j<67;++j) {
    buf_add(buf, str, 255);
  }
  for (j=0; j < 20; ++j) {
    buf_get_bytes(buf, str2, 255);
    tt_mem_op(str2,OP_EQ, str, 255);
  }
  for (j=0;j<80;++j) {
    buf_add(buf, str, 255);
  }
  //test_eq(buf_capacity(buf),33668);
  for (j=0; j < 120; ++j) {
    buf_get_bytes(buf, str2, 255);
    tt_mem_op(str2,OP_EQ, str, 255);
  }

  /* Move from buf to buf. */
  buf_free(buf);
  buf = buf_new_with_capacity(4096);
  buf2 = buf_new_with_capacity(4096);
  for (j=0;j<100;++j)
    buf_add(buf, str, 255);
  tt_int_op(buf_datalen(buf),OP_EQ, 25500);
  for (j=0;j<100;++j) {
    r = 10;
    buf_move_to_buf(buf2, buf, &r);
    tt_int_op(r,OP_EQ, 0);
  }
  tt_int_op(buf_datalen(buf),OP_EQ, 24500);
  tt_int_op(buf_datalen(buf2),OP_EQ, 1000);
  for (j=0;j<3;++j) {
    buf_get_bytes(buf2, str2, 255);
    tt_mem_op(str2,OP_EQ, str, 255);
  }
  r = 8192; /*big move*/
  buf_move_to_buf(buf2, buf, &r);
  tt_int_op(r,OP_EQ, 0);
  r = 30000; /* incomplete move */
  buf_move_to_buf(buf2, buf, &r);
  tt_int_op(r,OP_EQ, 13692);
  for (j=0;j<97;++j) {
    buf_get_bytes(buf2, str2, 255);
    tt_mem_op(str2,OP_EQ, str, 255);
  }
  buf_free(buf);
  buf_free(buf2);
  buf = buf2 = NULL;

  buf = buf_new_with_capacity(5);
  cp = "Testing. This is a moderately long Testing string.";
  for (j = 0; cp[j]; j++)
    buf_add(buf, cp+j, 1);
  tt_int_op(0,OP_EQ, buf_find_string_offset(buf, "Testing", 7));
  tt_int_op(1,OP_EQ, buf_find_string_offset(buf, "esting", 6));
  tt_int_op(1,OP_EQ, buf_find_string_offset(buf, "est", 3));
  tt_int_op(39,OP_EQ, buf_find_string_offset(buf, "ing str", 7));
  tt_int_op(35,OP_EQ, buf_find_string_offset(buf, "Testing str", 11));
  tt_int_op(32,OP_EQ, buf_find_string_offset(buf, "ng ", 3));
  tt_int_op(43,OP_EQ, buf_find_string_offset(buf, "string.", 7));
  tt_int_op(-1,OP_EQ, buf_find_string_offset(buf, "shrdlu", 6));
  tt_int_op(-1,OP_EQ, buf_find_string_offset(buf, "Testing thing", 13));
  tt_int_op(-1,OP_EQ, buf_find_string_offset(buf, "ngx", 3));
  buf_free(buf);
  buf = NULL;

  /* Try adding a string too long for any freelist. */
  {
    char *mem = tor_malloc_zero(65536);
    buf = buf_new();
    buf_add(buf, mem, 65536);
    tor_free(mem);

    tt_int_op(buf_datalen(buf), OP_EQ, 65536);
    buf_free(buf);
    buf = NULL;
  }

 done:
  if (buf)
    buf_free(buf);
  if (buf2)
    buf_free(buf2);
}

static void
test_buffer_pullup(void *arg)
{
  buf_t *buf;
  char *stuff, *tmp;
  const char *cp;
  size_t sz;
  (void)arg;
  stuff = tor_malloc(16384);
  tmp = tor_malloc(16384);

  buf = buf_new_with_capacity(3000); /* rounds up to next power of 2. */

  tt_assert(buf);
  tt_int_op(buf_get_default_chunk_size(buf), OP_EQ, 4096);

  tt_int_op(buf_get_total_allocation(), OP_EQ, 0);

  /* There are a bunch of cases for pullup.  One is the trivial case. Let's
     mess around with an empty buffer. */
  buf_pullup(buf, 16, &cp, &sz);
  tt_ptr_op(cp, OP_EQ, NULL);
  tt_uint_op(sz, OP_EQ, 0);

  /* Let's make sure nothing got allocated */
  tt_int_op(buf_get_total_allocation(), OP_EQ, 0);

  /* Case 1: everything puts into the first chunk with some moving. */

  /* Let's add some data. */
  crypto_rand(stuff, 16384);
  buf_add(buf, stuff, 3000);
  buf_add(buf, stuff+3000, 3000);
  buf_pullup(buf, 0, &cp, &sz);
  tt_ptr_op(cp, OP_NE, NULL);
  tt_int_op(sz, OP_LE, 4096);

  /* Make room for 3000 bytes in the first chunk, so that the pullup-move code
   * can get tested. */
  tt_int_op(buf_get_bytes(buf, tmp, 3000), OP_EQ, 3000);
  tt_mem_op(tmp,OP_EQ, stuff, 3000);
  buf_pullup(buf, 2048, &cp, &sz);
  buf_assert_ok(buf);
  tt_ptr_op(cp, OP_NE, NULL);
  tt_int_op(sz, OP_GE, 2048);
  tt_mem_op(cp,OP_EQ, stuff+3000, 2048);
  tt_int_op(3000, OP_EQ, buf_datalen(buf));
  tt_int_op(buf_get_bytes(buf, tmp, 3000), OP_EQ, 0);
  tt_mem_op(tmp,OP_EQ, stuff+3000, 2048);

  buf_free(buf);

  /* Now try the large-chunk case. */
  buf = buf_new_with_capacity(3000); /* rounds up to next power of 2. */
  buf_add(buf, stuff, 4000);
  buf_add(buf, stuff+4000, 4000);
  buf_add(buf, stuff+8000, 4000);
  buf_add(buf, stuff+12000, 4000);
  tt_int_op(buf_datalen(buf), OP_EQ, 16000);
  buf_pullup(buf, 0, &cp, &sz);
  tt_ptr_op(cp, OP_NE, NULL);
  tt_int_op(sz, OP_LE, 4096);

  buf_pullup(buf, 12500, &cp, &sz);
  buf_assert_ok(buf);
  tt_ptr_op(cp, OP_NE, NULL);
  tt_int_op(sz, OP_GE, 12500);
  tt_mem_op(cp,OP_EQ, stuff, 12500);
  tt_int_op(buf_datalen(buf), OP_EQ, 16000);

  buf_get_bytes(buf, tmp, 12400);
  tt_mem_op(tmp,OP_EQ, stuff, 12400);
  tt_int_op(buf_datalen(buf), OP_EQ, 3600);
  buf_get_bytes(buf, tmp, 3500);
  tt_mem_op(tmp,OP_EQ, stuff+12400, 3500);
  buf_get_bytes(buf, tmp, 100);
  tt_mem_op(tmp,OP_EQ, stuff+15900, 10);

  buf_free(buf);

  /* Make sure that the pull-up-whole-buffer case works */
  buf = buf_new_with_capacity(3000); /* rounds up to next power of 2. */
  buf_add(buf, stuff, 4000);
  buf_add(buf, stuff+4000, 4000);
  buf_get_bytes(buf, tmp, 100); /* dump 100 bytes from first chunk */
  buf_pullup(buf, 16000, &cp, &sz);
  buf_assert_ok(buf);
  tt_ptr_op(cp, OP_NE, NULL);
  tt_int_op(sz, OP_EQ, 7900);
  tt_mem_op(cp,OP_EQ, stuff+100, 7900);

  buf_free(buf);
  buf = NULL;

  tt_int_op(buf_get_total_allocation(), OP_EQ, 0);
 done:
  buf_free(buf);
  tor_free(stuff);
  tor_free(tmp);
}

static void
test_buffers_move_all(void *arg)
{
  (void)arg;
  buf_t *input = buf_new();
  buf_t *output = buf_new();
  char *s = NULL;

  /* Move from empty buffer to nonempty buffer. (This is a regression test for
   * #40076) */
  buf_add(output, "abc", 3);
  buf_assert_ok(input);
  buf_assert_ok(output);
  buf_move_all(output, input);
  buf_assert_ok(input);
  buf_assert_ok(output);
  tt_int_op(buf_datalen(output), OP_EQ, 3);
  s = buf_extract(output, NULL);
  tt_str_op(s, OP_EQ, "abc");
  buf_free(output);
  buf_free(input);
  tor_free(s);

  /* Move from empty to empty. */
  output = buf_new();
  input = buf_new();
  buf_move_all(output, input);
  buf_assert_ok(input);
  buf_assert_ok(output);
  tt_int_op(buf_datalen(output), OP_EQ, 0);
  buf_free(output);
  buf_free(input);

  /* Move from nonempty to empty. */
  output = buf_new();
  input = buf_new();
  buf_add(input, "longstanding bugs", 17);
  buf_move_all(output, input);
  buf_assert_ok(input);
  buf_assert_ok(output);
  s = buf_extract(output, NULL);
  tt_str_op(s, OP_EQ, "longstanding bugs");
  buf_free(output);
  buf_free(input);
  tor_free(s);

  /* Move from nonempty to nonempty. */
  output = buf_new();
  input = buf_new();
  buf_add(output, "the start of", 12);
  buf_add(input, " a string", 9);
  buf_move_all(output, input);
  buf_assert_ok(input);
  buf_assert_ok(output);
  s = buf_extract(output, NULL);
  tt_str_op(s, OP_EQ, "the start of a string");

 done:
  buf_free(output);
  buf_free(input);
  tor_free(s);
}

static void
test_buffer_copy(void *arg)
{
  buf_t *buf=NULL, *buf2=NULL;
  const char *s;
  size_t len;
  char b[256];
  int i;
  (void)arg;

  buf = buf_new();
  tt_assert(buf);

  /* Copy an empty buffer. */
  tt_int_op(0, OP_EQ, buf_set_to_copy(&buf2, buf));
  tt_assert(buf2);
  tt_int_op(0, OP_EQ, buf_datalen(buf2));

  /* Now try with a short buffer. */
  s = "And now comes an act of enormous enormance!";
  len = strlen(s);
  buf_add(buf, s, len);
  tt_int_op(len, OP_EQ, buf_datalen(buf));
  /* Add junk to buf2 so we can test replacing.*/
  buf_add(buf2, "BLARG", 5);
  tt_int_op(0, OP_EQ, buf_set_to_copy(&buf2, buf));
  tt_int_op(len, OP_EQ, buf_datalen(buf2));
  buf_get_bytes(buf2, b, len);
  tt_mem_op(b, OP_EQ, s, len);
  /* Now free buf2 and retry so we can test allocating */
  buf_free(buf2);
  buf2 = NULL;
  tt_int_op(0, OP_EQ, buf_set_to_copy(&buf2, buf));
  tt_int_op(len, OP_EQ, buf_datalen(buf2));
  buf_get_bytes(buf2, b, len);
  tt_mem_op(b, OP_EQ, s, len);
  /* Clear buf for next test */
  buf_get_bytes(buf, b, len);
  tt_int_op(buf_datalen(buf),OP_EQ,0);

  /* Okay, now let's try a bigger buffer. */
  s = "Quis autem vel eum iure reprehenderit qui in ea voluptate velit "
    "esse quam nihil molestiae consequatur, vel illum qui dolorem eum "
    "fugiat quo voluptas nulla pariatur?";
  len = strlen(s);
  for (i = 0; i < 256; ++i) {
    b[0]=i;
    buf_add(buf, b, 1);
    buf_add(buf, s, len);
  }
  tt_int_op(0, OP_EQ, buf_set_to_copy(&buf2, buf));
  tt_int_op(buf_datalen(buf2), OP_EQ, buf_datalen(buf));
  for (i = 0; i < 256; ++i) {
    buf_get_bytes(buf2, b, len+1);
    tt_int_op((unsigned char)b[0],OP_EQ,i);
    tt_mem_op(b+1, OP_EQ, s, len);
  }

 done:
  if (buf)
    buf_free(buf);
  if (buf2)
    buf_free(buf2);
}

static void
test_buffer_allocation_tracking(void *arg)
{
  char *junk = tor_malloc(16384);
  buf_t *buf1 = NULL, *buf2 = NULL;
  int i;

  (void)arg;

  crypto_rand(junk, 16384);
  tt_int_op(buf_get_total_allocation(), OP_EQ, 0);

  buf1 = buf_new();
  tt_assert(buf1);
  buf2 = buf_new();
  tt_assert(buf2);

  tt_int_op(buf_allocation(buf1), OP_EQ, 0);
  tt_int_op(buf_get_total_allocation(), OP_EQ, 0);

  buf_add(buf1, junk, 4000);
  buf_add(buf1, junk, 4000);
  buf_add(buf1, junk, 4000);
  buf_add(buf1, junk, 4000);
  tt_int_op(buf_allocation(buf1), OP_EQ, 16384);
  buf_get_bytes(buf1, junk, 100);
  tt_int_op(buf_allocation(buf1), OP_EQ, 16384); /* still 4 4k chunks */

  tt_int_op(buf_get_total_allocation(), OP_EQ, 16384);

  buf_get_bytes(buf1, junk, 4096); /* drop a 1k chunk... */
  tt_int_op(buf_allocation(buf1), OP_EQ, 3*4096); /* now 3 4k chunks */

  tt_int_op(buf_get_total_allocation(), OP_EQ, 12288); /* that chunk was really
                                                       freed. */

  buf_add(buf2, junk, 4000);
  tt_int_op(buf_allocation(buf2), OP_EQ, 4096); /* another 4k chunk. */
  /*
   * We bounce back up to 16384 by allocating a new chunk.
   */
  tt_int_op(buf_get_total_allocation(), OP_EQ, 16384);
  buf_add(buf2, junk, 4000);
  tt_int_op(buf_allocation(buf2), OP_EQ, 8192); /* another 4k chunk. */
  tt_int_op(buf_get_total_allocation(),
            OP_EQ, 5*4096); /* that chunk was new. */

  /* Make a really huge buffer */
  for (i = 0; i < 1000; ++i) {
    buf_add(buf2, junk, 4000);
  }
  tt_int_op(buf_allocation(buf2), OP_GE, 4008000);
  tt_int_op(buf_get_total_allocation(), OP_GE, 4008000);
  buf_free(buf2);
  buf2 = NULL;

  tt_int_op(buf_get_total_allocation(), OP_LT, 4008000);
  tt_int_op(buf_get_total_allocation(), OP_EQ, buf_allocation(buf1));
  buf_free(buf1);
  buf1 = NULL;
  tt_int_op(buf_get_total_allocation(), OP_EQ, 0);

 done:
  buf_free(buf1);
  buf_free(buf2);
  tor_free(junk);
}

static void
test_buffer_time_tracking(void *arg)
{
  buf_t *buf=NULL, *buf2=NULL;
  const time_t START = 1389288246;
  const uint64_t START_NSEC = ((uint64_t)START) * 1000000000;
  int i;
  char tmp[4096];
  (void)arg;

  crypto_rand(tmp, sizeof(tmp));

  monotime_enable_test_mocking();

  buf = buf_new_with_capacity(3000); /* rounds up to next power of 2. */
  tt_assert(buf);

  monotime_coarse_set_mock_time_nsec(START_NSEC);
  const uint32_t START_TS = monotime_coarse_get_stamp();

  /* Empty buffer means the timestamp is 0. */
  tt_int_op(0, OP_EQ, buf_get_oldest_chunk_timestamp(buf, START_TS));
  tt_int_op(0, OP_EQ, buf_get_oldest_chunk_timestamp(buf, START_TS+1000));

  buf_add(buf, "ABCDEFG", 7);
  tt_int_op(1000, OP_EQ, buf_get_oldest_chunk_timestamp(buf, START_TS+1000));

  buf2 = buf_copy(buf);
  tt_assert(buf2);
  tt_int_op(1234, OP_EQ,
            buf_get_oldest_chunk_timestamp(buf2, START_TS+1234));

  /* Now add more bytes; enough to overflow the first chunk. */
  monotime_coarse_set_mock_time_nsec(START_NSEC + 123 * (uint64_t)1000000);
  const uint32_t TS2 = monotime_coarse_get_stamp();
  for (i = 0; i < 600; ++i)
    buf_add(buf, "ABCDEFG", 7);
  tt_int_op(4207, OP_EQ, buf_datalen(buf));

  /* The oldest bytes are still in the front. */
  tt_int_op(2000, OP_EQ, buf_get_oldest_chunk_timestamp(buf, START_TS+2000));

  /* Once those bytes are dropped, the chunk is still on the first
   * timestamp. */
  buf_get_bytes(buf, tmp, 100);
  tt_int_op(2000, OP_EQ, buf_get_oldest_chunk_timestamp(buf, START_TS+2000));

  /* But once we discard the whole first chunk, we get the data in the second
   * chunk. */
  buf_get_bytes(buf, tmp, 4000);
  tt_int_op(107, OP_EQ, buf_datalen(buf));
  tt_int_op(2000, OP_EQ, buf_get_oldest_chunk_timestamp(buf, TS2+2000));

  /* This time we'll be grabbing a chunk from the freelist, and making sure
     its time gets updated */
  monotime_coarse_set_mock_time_nsec(START_NSEC + 5617 * (uint64_t)1000000);
  const uint32_t TS3 = monotime_coarse_get_stamp();
  for (i = 0; i < 600; ++i)
    buf_add(buf, "ABCDEFG", 7);
  tt_int_op(4307, OP_EQ, buf_datalen(buf));

  tt_int_op(2000, OP_EQ, buf_get_oldest_chunk_timestamp(buf, TS2+2000));
  buf_get_bytes(buf, tmp, 4000);
  buf_get_bytes(buf, tmp, 306);
  tt_int_op(0, OP_EQ, buf_get_oldest_chunk_timestamp(buf, TS3));
  tt_int_op(383, OP_EQ, buf_get_oldest_chunk_timestamp(buf, TS3+383));

 done:
  buf_free(buf);
  buf_free(buf2);
  monotime_disable_test_mocking();
}

static void
test_buffers_compress_fin_at_chunk_end_impl(compress_method_t method,
                                            compression_level_t level)
{
  char *msg = NULL;
  char *contents = NULL;
  char *expanded = NULL;
  buf_t *buf = NULL;
  tor_compress_state_t *compress_state = NULL;
  size_t out_len, in_len;
  size_t sz, headerjunk;

  buf = buf_new_with_capacity(128); /* will round up */
  sz = buf_get_default_chunk_size(buf);
  msg = tor_malloc_zero(sz);

  buf_add(buf, msg, 1);
  tt_assert(buf->head);

  /* Fill up the chunk so the compression stuff won't fit in one chunk. */
  tt_uint_op(buf->head->memlen, OP_LT, sz);
  headerjunk = buf->head->memlen - 7;
  buf_add(buf, msg, headerjunk-1);
  tt_uint_op(buf->head->datalen, OP_EQ, headerjunk);
  tt_uint_op(buf_datalen(buf), OP_EQ, headerjunk);
  /* Write an empty string, with finalization on. */
  compress_state = tor_compress_new(1, method, level);
  tt_int_op(buf_add_compress(buf, compress_state, "", 0, 1), OP_EQ, 0);

  in_len = buf_datalen(buf);
  contents = tor_malloc(in_len);

  tt_int_op(buf_get_bytes(buf, contents, in_len), OP_EQ, 0);

  if (method == NO_METHOD) {
    tt_uint_op(in_len, OP_EQ, headerjunk);
  } else {
    tt_uint_op(in_len, OP_GT, headerjunk);
  }

  tt_int_op(0, OP_EQ, tor_uncompress(&expanded, &out_len,
                                     contents + headerjunk,
                                     in_len - headerjunk,
                                     method, 1,
                                     LOG_WARN));

  tt_int_op(out_len, OP_EQ, 0);
  tt_assert(expanded);

 done:
  buf_free(buf);
  tor_compress_free(compress_state);
  tor_free(contents);
  tor_free(expanded);
  tor_free(msg);
}

static void
test_buffers_compress_impl(compress_method_t method,
                           compression_level_t level,
                           int finalize_with_nil)
{
  char *msg = NULL;
  char *contents = NULL;
  char *expanded = NULL;
  buf_t *buf = NULL;
  tor_compress_state_t *compress_state = NULL;
  size_t out_len, in_len;
  int done;

  buf = buf_new_with_capacity(128); /* will round up */
  compress_state = tor_compress_new(1, method, level);

  msg = tor_malloc(512);
  crypto_rand(msg, 512);
  tt_int_op(buf_add_compress(buf, compress_state,
                                  msg, 128, 0), OP_EQ, 0);
  tt_int_op(buf_add_compress(buf, compress_state,
                                  msg+128, 128, 0), OP_EQ, 0);
  tt_int_op(buf_add_compress(buf, compress_state,
                                  msg+256, 256, 0), OP_EQ, 0);
  done = !finalize_with_nil;
  tt_int_op(buf_add_compress(buf, compress_state,
                                  "all done", 9, done), OP_EQ, 0);
  if (finalize_with_nil) {
    tt_int_op(buf_add_compress(buf, compress_state, "", 0, 1), OP_EQ, 0);
  }

  in_len = buf_datalen(buf);
  contents = tor_malloc(in_len);

  tt_int_op(buf_get_bytes(buf, contents, in_len), OP_EQ, 0);

  tt_int_op(0, OP_EQ, tor_uncompress(&expanded, &out_len,
                                     contents, in_len,
                                     method, 1,
                                     LOG_WARN));

  tt_int_op(out_len, OP_GE, 128);
  tt_mem_op(msg, OP_EQ, expanded, 128);
  tt_int_op(out_len, OP_GE, 512);
  tt_mem_op(msg, OP_EQ, expanded, 512);
  tt_int_op(out_len, OP_EQ, 512+9);
  tt_mem_op("all done", OP_EQ, expanded+512, 9);

 done:
  buf_free(buf);
  tor_compress_free(compress_state);
  tor_free(contents);
  tor_free(expanded);
  tor_free(msg);
}

static void
test_buffers_compress(void *arg)
{
  const char *methodname = arg;
  tt_assert(methodname);

  compress_method_t method = compression_method_get_by_name(methodname);
  tt_int_op(method, OP_NE, UNKNOWN_METHOD);

  if (! tor_compress_supports_method(method)) {
    tt_skip();
  }

  compression_level_t levels[] = {
    BEST_COMPRESSION,
    HIGH_COMPRESSION,
    MEDIUM_COMPRESSION,
    LOW_COMPRESSION
  };

  for (unsigned l = 0; l < ARRAY_LENGTH(levels); ++l) {
    compression_level_t level = levels[l];

    test_buffers_compress_impl(method, level, 0);
    test_buffers_compress_impl(method, level, 1);
    test_buffers_compress_fin_at_chunk_end_impl(method, level);
  }

 done:
  ;
}

static const uint8_t *tls_read_ptr;
static int n_remaining;
static int next_reply_val[16];

static int
mock_tls_read(tor_tls_t *tls, char *cp, size_t len)
{
  (void)tls;
  int rv = next_reply_val[0];
  if (rv > 0) {
    int max = rv > (int)len ? (int)len : rv;
    if (max > n_remaining)
      max = n_remaining;
    memcpy(cp, tls_read_ptr, max);
    rv = max;
    n_remaining -= max;
    tls_read_ptr += max;
  }

  memmove(next_reply_val, next_reply_val + 1, 15*sizeof(int));
  return rv;
}

static void
test_buffers_tls_read_mocked(void *arg)
{
  uint8_t *mem;
  buf_t *buf;
  (void)arg;

  mem = tor_malloc(64*1024);
  crypto_rand((char*)mem, 64*1024);
  tls_read_ptr = mem;
  n_remaining = 64*1024;

  MOCK(tor_tls_read, mock_tls_read);

  buf = buf_new();

  next_reply_val[0] = 1024;
  tt_int_op(128, OP_EQ, buf_read_from_tls(buf, NULL, 128));

  next_reply_val[0] = 5000;
  next_reply_val[1] = 5000;
  tt_int_op(6000, OP_EQ, buf_read_from_tls(buf, NULL, 6000));

 done:
  UNMOCK(tor_tls_read);
  tor_free(mem);
  buf_free(buf);
}

static void
test_buffers_chunk_size(void *arg)
{
  (void)arg;
  const int min = 256;
  const int max = 65536;
  tt_uint_op(buf_preferred_chunk_size(3), OP_EQ, min);
  tt_uint_op(buf_preferred_chunk_size(25), OP_EQ, min);
  tt_uint_op(buf_preferred_chunk_size(0), OP_EQ, min);
  tt_uint_op(buf_preferred_chunk_size(256), OP_EQ, 512);
  tt_uint_op(buf_preferred_chunk_size(65400), OP_EQ, max);
  /* Here, we're implicitly saying that the chunk header overhead is
   * between 1 and 100 bytes. 24..48 would probably be more accurate. */
  tt_uint_op(buf_preferred_chunk_size(65536), OP_GT, 65536);
  tt_uint_op(buf_preferred_chunk_size(65536), OP_LT, 65536+100);
  tt_uint_op(buf_preferred_chunk_size(165536), OP_GT, 165536);
  tt_uint_op(buf_preferred_chunk_size(165536), OP_LT, 165536+100);
 done:
  ;
}

static void
test_buffers_find_contentlen(void *arg)
{
  static const struct {
    const char *headers;
    int r;
    int contentlen;
  } results[] = {
    { "Blah blah\r\nContent-Length: 1\r\n\r\n", 1, 1 },
    { "Blah blah\r\n\r\n", 0, 0 }, /* no content-len */
    { "Blah blah Content-Length: 1\r\n", 0, 0 }, /* no content-len. */
    { "Blah blah\r\nContent-Length: 100000\r\n", 1, 100000},
    { "Blah blah\r\nContent-Length: 1000000000000000000000000\r\n", -1, 0},
    { "Blah blah\r\nContent-Length: 0\r\n", 1, 0},
    { "Blah blah\r\nContent-Length: -1\r\n", -1, 0},
    { "Blah blah\r\nContent-Length: 1x\r\n", -1, 0},
    { "Blah blah\r\nContent-Length: 1 x\r\n", -1, 0},
    { "Blah blah\r\nContent-Length: 1 \r\n", 1, 1},
    { "Blah blah\r\nContent-Length:  \r\n", -1, 0},
    { "Blah blah\r\nContent-Length: ", -1, 0},
    { "Blah blah\r\nContent-Length: 5050", -1, 0},
    { NULL, 0, 0 }
  };
  int i;

  (void)arg;

  for (i = 0; results[i].headers; ++i) {
    int r;
    size_t sz;
    size_t headerlen = strlen(results[i].headers);
    char * tmp = tor_memdup(results[i].headers, headerlen);/* ensure no eos */
    sz = 999; /* to ensure it gets set */
    r = buf_http_find_content_length(tmp, headerlen, &sz);
    tor_free(tmp);
    log_debug(LD_DIR, "%d: %s", i, escaped(results[i].headers));
    tt_int_op(r, OP_EQ, results[i].r);
    tt_int_op(sz, OP_EQ, results[i].contentlen);
  }
 done:
  ;
}

static void
test_buffer_peek_startswith(void *arg)
{
  (void)arg;
  buf_t *buf;
  buf = buf_new();
  tt_ptr_op(buf, OP_NE, NULL);

  tt_assert(buf_peek_startswith(buf, ""));
  tt_assert(! buf_peek_startswith(buf, "X"));

  buf_add(buf, "Tor", 3);

  tt_assert(buf_peek_startswith(buf, ""));
  tt_assert(buf_peek_startswith(buf, "T"));
  tt_assert(buf_peek_startswith(buf, "To"));
  tt_assert(buf_peek_startswith(buf, "Tor"));
  tt_assert(! buf_peek_startswith(buf, "Top"));
  tt_assert(! buf_peek_startswith(buf, "For"));
  tt_assert(! buf_peek_startswith(buf, "Tork"));
  tt_assert(! buf_peek_startswith(buf, "Torpor"));

 done:
  buf_free(buf);
}

/* ---- Tests for bug 41377: searching a buffer across empty chunks. ---- */

/** Append an empty chunk to the end of <b>buf</b>, as a socket, pipe or TLS
 * read does when it allocates a chunk and then gets nothing.  Fill the
 * chunk's never-written memory with <b>stale</b>, so that a search that
 * wrongly reads it gives a visibly wrong answer. */
static chunk_t *
buf_add_empty_chunk_for_test(buf_t *buf, char stale)
{
  chunk_t *ch = buf_add_chunk_with_capacity(buf, 1, 1);
  memset(ch->mem, stale, ch->memlen);
  return ch;
}

/** Append a chunk of capacity <b>cap</b> filled completely (datalen == memlen)
 * with <b>prefix</b>, repeated <b>pad_ch</b>, and <b>suffix</b>. */
static chunk_t *
buf_add_full_chunk_for_test(buf_t *buf, size_t cap, const char *prefix,
                            const char *suffix, char pad_ch)
{
  size_t plen = strlen(prefix);
  size_t slen = strlen(suffix);
  chunk_t *ch = buf_add_chunk_with_capacity(buf, cap, 1);
  tor_assert(ch);
  tor_assert(ch->memlen >= plen + slen);
  size_t padlen = ch->memlen - plen - slen;
  if (plen)
    memcpy(ch->data, prefix, plen);
  if (padlen)
    memset(ch->data + plen, (unsigned char)pad_ch, padlen);
  if (slen)
    memcpy(ch->data + plen + padlen, suffix, slen);
  ch->datalen = ch->memlen;
  buf->datalen += ch->memlen;
  return ch;
}

/** Append <b>len</b> copies of <b>c</b> to <b>buf</b>, in new chunks of
 * their own, using buf_move_all() the way linked connections move data.
 * If <b>small</b>, use the smallest chunks that buffers allocate. */
static void
buf_move_bytes_for_test(buf_t *buf, char c, size_t len, int small)
{
  buf_t *tmp = small ? buf_new_with_capacity(1) : buf_new();
  char *s = tor_malloc(len);
  memset(s, c, len);
  buf_add(tmp, s, len);
  buf_move_all(buf, tmp);
  buf_free(tmp);
  tor_free(s);
}

/** Append <b>s</b> to <b>buf</b> in new chunk(s) of its own, using
 * buf_move_all(). */
static void
buf_move_string_for_test(buf_t *buf, const char *s)
{
  buf_t *tmp = buf_new();
  buf_add_string(tmp, s);
  buf_move_all(buf, tmp);
  buf_free(tmp);
}

/** Return the number of empty chunks in <b>buf</b> other than its tail. */
static int
buf_n_empty_nontail_chunks_for_test(const buf_t *buf)
{
  int n = 0;
  for (const chunk_t *ch = buf->head; ch; ch = ch->next) {
    if (ch->datalen == 0 && ch != buf->tail)
      ++n;
  }
  return n;
}

/** Return the usable size of a chunk allocated by a buffer made with
 * buf_new_with_capacity(<b>capacity</b>), or by buf_new() if
 * <b>capacity</b> is 0.  (It depends on the platform's struct layout.) */
static size_t
chunk_memlen_for_test(size_t capacity)
{
  buf_t *probe = capacity ? buf_new_with_capacity(capacity) : buf_new();
  buf_add(probe, "x", 1);
  size_t memlen = probe->head->memlen;
  buf_free(probe);
  return memlen;
}

/** With ASan, make the memory of every chunk in <b>buf</b> that is not
 * buffer data (the drained space before chunk->data, and the free space after
 * the data) unaddressable, as far as ASan's granularity allows, except in
 * <b>skip</b> if it is not NULL.  Nothing may write into or repack those
 * chunks until buf_unpoison_for_test(). */
static void
buf_poison_unused_for_test(buf_t *buf, const chunk_t *skip)
{
  if (!buf)
    return;
  for (chunk_t *ch = buf->head; ch; ch = ch->next) {
    if (ch == skip)
      continue;
    size_t lead = (size_t)(ch->data - ch->mem);
    if (lead > 0)
      BUF_TEST_POISON(ch->mem, lead);
    size_t rem = CHUNK_REMAINING_CAPACITY(ch);
    if (rem > 0)
      BUF_TEST_POISON(CHUNK_WRITE_PTR(ch), rem);
  }
}

/** Undo buf_poison_unused_for_test() for every chunk still in <b>buf</b>. */
static void
buf_unpoison_for_test(buf_t *buf)
{
  if (!buf)
    return;
  for (chunk_t *ch = buf->head; ch; ch = ch->next)
    BUF_TEST_UNPOISON(ch->mem, ch->memlen);
}

/** As buf_find_string_offset(), with <b>buf</b>'s non-data memory poisoned.
 */
static int
find_string_poisoned(buf_t *buf, const char *s, size_t n)
{
  buf_poison_unused_for_test(buf, NULL);
  int r = buf_find_string_offset(buf, s, n);
  buf_unpoison_for_test(buf);
  return r;
}

/** As fetch_from_buf_http(), with <b>buf</b>'s non-data memory poisoned,
 * except in the head chunk: buf_pullup() legitimately repacks the head chunk
 * and copies data into its free space.  (A search can only reach a chunk's
 * memory from the chunk before it, so it never reads the head's.) */
static int
fetch_http_poisoned(buf_t *buf, char **headers_out, size_t max_headerlen,
                    char **body_out, size_t *body_used, size_t max_bodylen,
                    int force_complete)
{
  buf_poison_unused_for_test(buf, buf->head);
  int r = fetch_from_buf_http(buf, headers_out, max_headerlen, body_out,
                              body_used, max_bodylen, force_complete);
  buf_unpoison_for_test(buf);
  return r;
}

/** The bug 41377 test case that is running.  An ASan report kills the test
 * process before tinytest can say which assertion it was in, so we record
 * the case up front and have the ASan death callback print it. */
static char buf_test_case[96];
/** True while a case that uses the reproducible RNG is running. */
static int buf_test_case_uses_rng = 0;

#ifdef BUF_TEST_HAVE_ASAN
/** ASan death callback: say which case was running, and for a randomized
 * case, which seed reproduces it. */
static void
buf_test_asan_death(void)
{
  if (buf_test_case[0])
    fprintf(stderr, "\nbuffer test case: %s\n", buf_test_case);
  if (buf_test_case_uses_rng) {
    testing_dump_reproducible_rng_seed();
    fflush(stdout);
  }
}
#endif /* defined(BUF_TEST_HAVE_ASAN) */

/** Record <b>name</b> as the running test case, for buf_test_asan_death(). */
static void
buf_test_set_case(const char *name)
{
  strlcpy(buf_test_case, name, sizeof(buf_test_case));
  BUF_TEST_ON_ASAN_DEATH(buf_test_asan_death);
}

/** Forget the running test case when a test ends, so that under --no-fork a
 * later, unrelated ASan report is not blamed on it. */
static void
buf_test_clear_case(void)
{
  buf_test_case[0] = '\0';
  buf_test_case_uses_rng = 0;
  BUF_TEST_ON_ASAN_DEATH(NULL);
}

#define BIG_HDR 50000
#define BIG_BODY (1<<24)

/* In the tests below, "main" means the code before the fix (which compared
 * against stale bytes in empty chunks), and "2a9408f" means the reverted fix
 * (which stopped searching at the first empty chunk).  Each case says which
 * of them it catches. */

static void
test_buffers_find_string_empty_tail(void *arg)
{
  (void)arg;
  buf_t *buf = buf_new();
  char *headers = NULL, *body = NULL;
  size_t body_len = 0;
  const char req[] = "GET /tor/server/authority HTTP/1.0\r\nHost: x\r\n\r";
  const int reqlen = (int)strlen(req);

  buf_test_set_case("empty_tail: uninitialised empty tail");
  /* Leave the empty tail chunk's memory uninitialised, so that valgrind and
   * MSan report any read of it, whatever it happens to contain.  (This case
   * comes first so that no failed assertion stops the test before it.) */
  buf_add(buf, req, reqlen);
  buf_add_chunk_with_capacity(buf, 1, 1);
  tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, -1);
  buf_free(buf);

  buf_test_set_case("empty_tail: full chunk CR LF CR, then an empty tail");
  /* Production geometry: a 100%-full chunk (datalen == memlen) ending in a
   * prefix of the pattern, followed by an empty tail chunk whose stale memory
   * would complete the pattern.  Catches main. */
  buf = buf_new_with_capacity(128);
  chunk_t *c0 = buf_add_full_chunk_for_test(
      buf, 128, "GET /tor/status HTTP/1.0\r\nX-Pad: ", "\r\n\r", 'A');
  size_t c0_len = c0->memlen;
  buf_add_empty_chunk_for_test(buf, '\n');
  buf_assert_ok(buf);

  tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, -1);
  /* A match that ends exactly at the end of the data is still found. */
  tt_int_op(find_string_poisoned(buf, "\r\n\r", 3), OP_EQ, (int)c0_len - 3);
  /* Not complete yet: must be 0 ("wait for more"), not -1 ("reject"). */
  tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                BIG_BODY, 0), OP_EQ, 0);
  tt_ptr_op(headers, OP_EQ, NULL);
  tt_ptr_op(body, OP_EQ, NULL);

  /* The final LF goes into the formerly empty tail chunk. */
  buf_add(buf, "\n", 1);
  tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, (int)c0_len - 3);
  tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                BIG_BODY, 0), OP_EQ, 1);
  tt_ptr_op(headers, OP_NE, NULL);
  tt_size_op(strlen(headers), OP_EQ, c0_len + 1);
  tt_size_op(body_len, OP_EQ, 0);
  tt_size_op(buf_datalen(buf), OP_EQ, 0);
  tor_free(headers);
  tor_free(body);
  buf_free(buf);

  buf_test_set_case("empty_tail: partial chunk CR LF CR, then an empty tail");
  /* Same with slack remaining in the first chunk.  Catches main. */
  buf = buf_new();
  buf_add(buf, req, reqlen);
  buf_add_empty_chunk_for_test(buf, '\n');
  buf_assert_ok(buf);
  tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, -1);
  tt_int_op(find_string_poisoned(buf, "\r", 1), OP_EQ, 34);
  buf_add(buf, "\n", 1);
  tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                BIG_BODY, 0), OP_EQ, 1);
  tt_str_op(headers, OP_EQ,
            "GET /tor/server/authority HTTP/1.0\r\nHost: x\r\n\r\n");
  tt_size_op(body_len, OP_EQ, 0);
  tor_free(headers);
  tor_free(body);
  buf_free(buf);

  buf_test_set_case("empty_tail: complete request, then an empty tail");
  /* A complete request followed by an empty tail chunk. */
  buf = buf_new();
  buf_add_string(buf, "GET / HTTP/1.0\r\n\r\n");
  buf_add_empty_chunk_for_test(buf, '\r');
  tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, 14);
  tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                BIG_BODY, 0), OP_EQ, 1);
  tt_str_op(headers, OP_EQ, "GET / HTTP/1.0\r\n\r\n");

 done:
  tor_free(headers);
  tor_free(body);
  buf_free(buf);
  buf_test_clear_case();
}

static void
test_buffers_find_string_empty_interior(void *arg)
{
  (void)arg;
  buf_t *buf = NULL;
  char *headers = NULL, *body = NULL;
  size_t body_len = 0;

  buf_test_set_case("empty_interior (a): CR before a hole, delimiter after");
  /* (a) A first-character candidate is the last byte before an empty
   * interior chunk; the real delimiter comes later.  Catches 2a9408f, and
   * main under ASan. */
  {
    const char a[] = "HTTP/1.0 200 OK\r\nX-A: 1\r";
    const char c[] = "\nX-Final: yup\r\n\r\n";
    buf = buf_new();
    buf_add_string(buf, a);
    buf_add_empty_chunk_for_test(buf, 'x');
    buf_move_string_for_test(buf, c);
    buf_assert_ok(buf);
    tt_int_op(buf_n_empty_nontail_chunks_for_test(buf), OP_EQ, 1);
    tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ,
              (int)(strlen(a) + strlen(c) - 4));
    tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                  BIG_BODY, 0), OP_EQ, 1);
    tt_str_op(headers, OP_EQ,
              "HTTP/1.0 200 OK\r\nX-A: 1\r\nX-Final: yup\r\n\r\n");
    tor_free(headers);
    tor_free(body);
    buf_free(buf);
  }

  buf_test_set_case("empty_interior (b): delimiter straddles a hole");
  /* (b) The delimiter itself straddles an empty interior chunk.  Catches
   * main and 2a9408f. */
  {
    const char a[] = "HTTP/1.0 200 OK\r\n";
    buf = buf_new();
    buf_add_string(buf, a);
    buf_add_empty_chunk_for_test(buf, 'x');
    buf_move_string_for_test(buf, "\r\nbody");
    buf_assert_ok(buf);
    tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ,
              (int)strlen(a) - 2);
    tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                  BIG_BODY, 0), OP_EQ, 1);
    tt_str_op(headers, OP_EQ, "HTTP/1.0 200 OK\r\n\r\n");
    tt_size_op(body_len, OP_EQ, 4);
    tt_str_op(body, OP_EQ, "body");
    tor_free(headers);
    tor_free(body);
    buf_free(buf);
  }

  buf_test_set_case("empty_interior (c): stale bytes in a hole");
  /* (c) Stale bytes in an empty interior chunk must not complete a match
   * at the wrong place.  Catches main and 2a9408f. */
  {
    const char a[] = "HTTP/1.0 200 OK\r\nX-A: 1\r\n\r";
    const char c[] = "X-B: 2\r\n\r\n";
    buf = buf_new();
    buf_add_string(buf, a);
    buf_add_empty_chunk_for_test(buf, '\n');
    buf_move_string_for_test(buf, c);
    buf_assert_ok(buf);
    tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ,
              (int)(strlen(a) + strlen(c) - 4));
    buf_free(buf);
  }

  buf_test_set_case("empty_interior (d): delimiter split across two chunks");
  /* (d) A delimiter split across two nonempty chunks, with no empty chunk:
   * the existing tests never cross a chunk boundary. */
  {
    buf = buf_new();
    buf_add_string(buf, "GET / HTTP/1.0\r\n\r");
    buf_move_string_for_test(buf, "\nbody");
    tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, 14);
    tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                  BIG_BODY, 0), OP_EQ, 1);
    tt_str_op(headers, OP_EQ, "GET / HTTP/1.0\r\n\r\n");
    tt_size_op(body_len, OP_EQ, 4);
    tt_str_op(body, OP_EQ, "body");
    tor_free(headers);
    tor_free(body);
    buf_free(buf);
  }

  buf_test_set_case("empty_interior (e): runs of holes, including the head");
  /* (e) Several empty chunks in a row, including at the head.  Catches main
   * and 2a9408f. */
  {
    buf = buf_new();
    buf_add_empty_chunk_for_test(buf, '\r');
    buf_add_empty_chunk_for_test(buf, '\n');
    buf_move_string_for_test(buf, "ab\r");
    buf_add_empty_chunk_for_test(buf, '\r');
    buf_add_empty_chunk_for_test(buf, '\n');
    buf_move_string_for_test(buf, "\n");
    buf_add_empty_chunk_for_test(buf, 'x');
    buf_move_string_for_test(buf, "\r\ncd");
    buf_assert_ok(buf);
    tt_int_op(buf_n_empty_nontail_chunks_for_test(buf), OP_EQ, 5);
    tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, 2);
    tt_int_op(find_string_poisoned(buf, "ab", 2), OP_EQ, 0);
    tt_int_op(find_string_poisoned(buf, "\ncd", 3), OP_EQ, 5);
    tt_int_op(find_string_poisoned(buf, "cd\r", 3), OP_EQ, -1);
    buf_free(buf);
  }

  buf_test_set_case("empty_interior (f): leading holes, no match");
  /* (f) Leading empty chunks, then data without the needle, with the data
   * at least as long as the needle: the walk, not the length check,
   * decides. */
  {
    buf = buf_new();
    buf_add_empty_chunk_for_test(buf, '\r');
    buf_add_empty_chunk_for_test(buf, '\n');
    buf_move_string_for_test(buf, "abcd");
    tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, -1);
    tt_int_op(find_string_poisoned(buf, "abcd", 4), OP_EQ, 0);
    tt_int_op(find_string_poisoned(buf, "cd", 2), OP_EQ, 2);
    buf_free(buf);
  }

  buf_test_set_case("empty_interior (g): only empty chunks");
  /* (g) Nothing but empty chunks: every needle is longer than the data. */
  {
    buf = buf_new();
    buf_add_empty_chunk_for_test(buf, '\r');
    buf_add_empty_chunk_for_test(buf, '\n');
    buf_assert_ok(buf);
    tt_int_op(find_string_poisoned(buf, "\r", 1), OP_EQ, -1);
    tt_int_op(find_string_poisoned(buf, "\r\n", 2), OP_EQ, -1);
    tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                  BIG_BODY, 0), OP_EQ, 0);
    buf_free(buf);
  }

  buf_test_set_case("empty_interior (h): drained chunk, then holes");
  /* (h) A partly drained chunk, whose consumed space holds '\r' bytes,
   * then empty chunks, then the end of the delimiter.  Catches main and
   * 2a9408f. */
  {
    buf = buf_new();
    buf_add_string(buf, "\r\r\r\r\rGET / HTTP/1.0\r\n");
    buf_drain(buf, 5);
    tt_ptr_op(buf->head->data, OP_EQ, buf->head->mem + 5);
    buf_add_empty_chunk_for_test(buf, '\r');
    buf_add_empty_chunk_for_test(buf, '\n');
    tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, -1);
    buf_move_string_for_test(buf, "\r\n");
    tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, 14);
    tt_int_op(find_string_poisoned(buf, "GET", 3), OP_EQ, 0);
  }

 done:
  tor_free(headers);
  tor_free(body);
  buf_free(buf);
  buf_test_clear_case();
}

/** Needles longer than a chunk.  Except where noted, keep buf_datalen() at
 * least as long as the needle, so that the walk (not the needle-length check)
 * decides the result.  The stale bytes must fit inside the empty chunk's
 * memory to catch main: past it, every chunk has zeroed sentinel bytes, and
 * main's walk stops there. */
static void
test_buffers_find_string_long_needle(void *arg)
{
  (void)arg;
  buf_t *buf = NULL;
  const size_t small = chunk_memlen_for_test(1);
  const size_t n_a = 2 * small + 420;
  char *a = tor_malloc(n_a);
  memset(a, 'A', n_a);

  buf_test_set_case("long_needle: stale bytes in a default-sized hole");
  /* [220 X][208 A][empty default-sized chunk, stale 'A']: the data has only
   * 208 'A's.  Catches main (its walk completes the needle with stale bytes
   * and reports offset 220). */
  buf = buf_new();
  buf_move_bytes_for_test(buf, 'X', 220, 0);
  buf_move_bytes_for_test(buf, 'A', 208, 0);
  buf_add_empty_chunk_for_test(buf, 'A');
  tt_size_op(buf_datalen(buf), OP_EQ, 428);
  tt_int_op(find_string_poisoned(buf, a, 420), OP_EQ, -1);
  tt_int_op(find_string_poisoned(buf, a, 209), OP_EQ, -1);
  tt_int_op(find_string_poisoned(buf, a, 208), OP_EQ, 220);
  buf_free(buf);

  buf_test_set_case("long_needle: needle ends at the end of a small hole");
  /* The same with the smallest chunks: one chunk of 'A's, then an empty
   * chunk of the same size, and a needle that would end exactly at the end
   * of the empty chunk's memory.  Catches main. */
  buf = buf_new_with_capacity(1);
  buf_move_bytes_for_test(buf, 'X', 2 * small, 1);
  buf_move_bytes_for_test(buf, 'A', small, 1);
  buf_add_empty_chunk_for_test(buf, 'A');
  tt_size_op(buf->tail->memlen, OP_EQ, small);
  tt_size_op(buf_datalen(buf), OP_EQ, 3 * small);
  tt_int_op(find_string_poisoned(buf, a, 2 * small), OP_EQ, -1);
  tt_int_op(find_string_poisoned(buf, a, small), OP_EQ, (int)(2 * small));
  buf_free(buf);

  buf_test_set_case("long_needle: 420 real bytes split by a hole");
  /* [220 X][208 A][empty, stale 'B'][212 A]: 420 real 'A's, split by an
   * empty chunk whose stale memory differs.  Catches main and 2a9408f. */
  buf = buf_new();
  buf_move_bytes_for_test(buf, 'X', 220, 0);
  buf_move_bytes_for_test(buf, 'A', 208, 0);
  buf_add_empty_chunk_for_test(buf, 'B');
  buf_move_bytes_for_test(buf, 'A', 212, 0);
  tt_size_op(buf_datalen(buf), OP_EQ, 640);
  tt_int_op(find_string_poisoned(buf, a, 420), OP_EQ, 220);
  tt_int_op(find_string_poisoned(buf, a, 421), OP_EQ, -1);
  buf_free(buf);

  buf_test_set_case("long_needle: needle longer than the data");
  /* A needle longer than all of the data (decided by the needle-length
   * check).  Main completes it with the stale byte. */
  buf = buf_new();
  buf_add_string(buf, "AAA");
  buf_add_empty_chunk_for_test(buf, 'A');
  tt_int_op(find_string_poisoned(buf, a, 4), OP_EQ, -1);
  tt_int_op(find_string_poisoned(buf, a, 3), OP_EQ, 0);

 done:
  buf_free(buf);
  tor_free(a);
  buf_test_clear_case();
}

/** Build many random chunk layouts (with empty chunks at the head, in the
 * middle and at the tail, partly-drained heads, and plausible garbage in
 * all memory that isn't buffer data), and check buf_find_string_offset()
 * against a search of the flattened contents. */
static void
test_buffers_find_string_random(void *arg)
{
  (void)arg;
  static const char alphabet[] = "\r\nab";
  /* Needles with repeated prefixes, which make a match restart. */
  static const char *fixed_needles[] = {
    "\r\n\r\n", "\r\n", "a", "ab", "aba\r\n", "\r\na\r\n\r\n",
  };
  buf_t *buf = NULL, *tmp = NULL;
  char *flat = NULL;
  size_t flatlen = 0;

  testing_enable_reproducible_rng();
  buf_test_case_uses_rng = 1;
  buf_test_set_case("random");

  for (int iter = 0; iter < 2000; ++iter) {
    tor_snprintf(buf_test_case, sizeof(buf_test_case),
                 "random: iteration %d", iter);
    buf = buf_new_with_capacity(1);
    int n_ops = crypto_rand_int_range(1, 16);
    for (int op = 0; op < n_ops; ++op) {
      char seg[64];
      size_t seglen = crypto_rand_int_range(1, sizeof(seg));
      for (size_t i = 0; i < seglen; ++i)
        seg[i] = alphabet[crypto_rand_int(4)];
      switch (crypto_rand_int(4)) {
        case 0: /* Append in place (this may fill an empty tail chunk). */
          buf_add(buf, seg, seglen);
          break;
        case 1: /* Splice on a separate buffer's chunks. */
          tmp = buf_new_with_capacity(1);
          buf_add(tmp, seg, seglen);
          if (crypto_rand_int(2))
            buf_add_chunk_with_capacity(tmp, 1, 1);
          buf_move_all(buf, tmp);
          buf_free(tmp);
          break;
        case 2: /* Empty chunk at the tail, for now. */
          buf_add_chunk_with_capacity(buf, 1, 1);
          break;
        case 3: /* Consume a little from the front. */
          if (buf_datalen(buf)) {
            size_t max = MIN(buf_datalen(buf), 20);
            buf_drain(buf, crypto_rand_int_range(1, (unsigned)max + 1));
          }
          break;
      }
    }
    /* Make every byte that isn't buffer data look like plausible data. */
    for (chunk_t *ch = buf->head; ch; ch = ch->next) {
      for (char *p = ch->mem; p < ch->data; ++p)
        *p = alphabet[crypto_rand_int(4)];
      for (char *p = CHUNK_WRITE_PTR(ch); p < ch->mem + ch->memlen; ++p)
        *p = alphabet[crypto_rand_int(4)];
    }
    buf_assert_ok(buf);

    flat = buf_extract(buf, &flatlen);
    for (int k = 0; k < 24; ++k) {
      char pat[260];
      size_t patlen;
      if (k < (int)ARRAY_LENGTH(fixed_needles)) {
        patlen = strlen(fixed_needles[k]);
        memcpy(pat, fixed_needles[k], patlen);
      } else if (k % 3 == 0 && flatlen) {
        /* A slice of the data, so that long matches spanning many chunks
         * (and the empty chunks between them) must be found. */
        size_t maxlen = MIN(flatlen, sizeof(pat));
        size_t start;
        patlen = crypto_rand_int_range(1, (unsigned)maxlen + 1);
        start = crypto_rand_int_range(0, (unsigned)(flatlen - patlen) + 1);
        memcpy(pat, flat + start, patlen);
      } else {
        patlen = crypto_rand_int_range(1, (k % 3 == 1) ? 40 : 6);
        for (size_t i = 0; i < patlen; ++i)
          pat[i] = alphabet[crypto_rand_int(4)];
      }
      const char *hit = flatlen ? tor_memmem(flat, flatlen, pat, patlen) :
        NULL;
      int expected = hit ? (int)(hit - flat) : -1;
      tt_int_op(find_string_poisoned(buf, pat, patlen), OP_EQ, expected);
    }
    tor_free(flat);
    buf_free(buf);
  }

 done:
  testing_disable_reproducible_rng();
  tor_free(flat);
  buf_free(buf);
  buf_test_clear_case();
}

#ifndef _WIN32
/** Helper: Return a new buffer holding <b>memlen</b> bytes of <b>data</b>
 * read from a pipe the way a DirPort connection would read them: in two
 * read events, the second of which fills the tail chunk exactly, allocates
 * a new chunk, and then gets EAGAIN.  The result is [full chunk][empty
 * chunk]. */
static buf_t *
buf_from_pipe_with_empty_tail_for_test(const char *data, size_t memlen)
{
  int fds[2] = { -1, -1 };
  int eof = 0, err = 0;
  buf_t *buf = NULL;
  /* The write end is non-blocking too, so that a pipe too small to hold
   * memlen bytes makes the test fail rather than hang. */
  if (pipe(fds) < 0 || fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0 ||
      fcntl(fds[1], F_SETFL, O_NONBLOCK) < 0)
    goto err;
  if (write(fds[1], data, memlen) != (ssize_t)memlen)
    goto err;
  buf = buf_new();
  if (buf_read_from_pipe(buf, fds[0], memlen - 100, &eof, &err) !=
      (int)memlen - 100)
    goto err;
  if (buf_read_from_pipe(buf, fds[0], 200, &eof, &err) != 100)
    goto err;
  if (eof || buf->head == buf->tail || buf->head->datalen != memlen ||
      buf->tail->datalen != 0 || buf->head->next != buf->tail)
    goto err;
  close(fds[0]);
  close(fds[1]);
  return buf;
 err:
  if (fds[0] >= 0)
    close(fds[0]);
  if (fds[1] >= 0)
    close(fds[1]);
  buf_free(buf);
  return NULL;
}
#endif /* !defined(_WIN32) */

/** End-to-end versions of the tests above, through fetch_from_buf_http(),
 * with the empty chunk produced by a real pipe read. */
static void
test_buffers_find_string_pipe(void *arg)
{
  (void)arg;
#ifdef _WIN32
  tt_skip();
 done:
  ;
#else /* !defined(_WIN32) */
  buf_t *buf = NULL, *rest = NULL;
  char *req = NULL, *headers = NULL, *body = NULL;
  size_t body_len = 0;
  const size_t memlen = chunk_memlen_for_test(0);
  const char final[] = "\nX-Final: yup\r\n\r\n";

  tt_size_op(memlen, OP_GT, 200);
  req = tor_malloc(memlen);
  memset(req, 'a', memlen);
  memcpy(req, "GET / HTTP/1.0\r\nX-Pad: ", 23);

  buf_test_set_case("pipe 1: CR LF CR, then an empty tail from a read");
  /* 1. The original bug: the first chunk ends in "\r\n\r" and the empty
   * tail chunk's stale memory starts with "\n".  Catches main. */
  memcpy(req + memlen - 3, "\r\n\r", 3);
  buf = buf_from_pipe_with_empty_tail_for_test(req, memlen);
  tt_assert(buf);
  memset(buf->tail->mem, '\n', buf->tail->memlen);
  tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ, -1);
  tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                BIG_BODY, 0), OP_EQ, 0);

  buf_test_set_case("pipe 2: delimiter straddles the hole");
  /* 2. The rest arrives via buf_move_all(), leaving the empty chunk in the
   * middle; the real delimiter straddles it.  Catches main and 2a9408f. */
  memset(buf->tail->mem, 'x', buf->tail->memlen);
  rest = buf_new();
  buf_add_string(rest, final);
  buf_move_all(buf, rest);
  buf_free(rest);
  buf_assert_ok(buf);
  tt_int_op(buf_n_empty_nontail_chunks_for_test(buf), OP_EQ, 1);
  tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ,
            (int)memlen - 3);
  tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                BIG_BODY, 0), OP_EQ, 1);
  tt_size_op(strlen(headers), OP_EQ, memlen + 1);
  tt_str_op(body, OP_EQ, final + 1);
  tor_free(headers);
  tor_free(body);
  buf_free(buf);

  buf_test_set_case("pipe 3: delimiter after the hole");
  /* 3. The first chunk ends with the CR of a header line, the rest arrives
   * via buf_move_all(), and the real delimiter is entirely after the empty
   * chunk.  Catches 2a9408f. */
  req[memlen - 3] = 'a';
  req[memlen - 2] = 'a';
  req[memlen - 1] = '\r';
  buf = buf_from_pipe_with_empty_tail_for_test(req, memlen);
  tt_assert(buf);
  memset(buf->tail->mem, 'x', buf->tail->memlen);
  rest = buf_new();
  buf_add_string(rest, final);
  buf_move_all(buf, rest);
  buf_free(rest);
  buf_assert_ok(buf);
  tt_int_op(find_string_poisoned(buf, "\r\n\r\n", 4), OP_EQ,
            (int)(memlen + strlen(final) - 4));
  tt_int_op(fetch_http_poisoned(buf, &headers, BIG_HDR, &body, &body_len,
                                BIG_BODY, 0), OP_EQ, 1);
  tt_size_op(strlen(headers), OP_EQ, memlen + strlen(final));
  tt_size_op(body_len, OP_EQ, 0);

 done:
  tor_free(req);
  tor_free(headers);
  tor_free(body);
  buf_free(buf);
  buf_test_clear_case();
#endif /* defined(_WIN32) */
}

struct testcase_t buffer_tests[] = {
  { "basic", test_buffers_basic, TT_FORK, NULL, NULL },
  { "copy", test_buffer_copy, TT_FORK, NULL, NULL },
  { "pullup", test_buffer_pullup, TT_FORK, NULL, NULL },
  { "move_all", test_buffers_move_all, 0, NULL, NULL },
  { "startswith", test_buffer_peek_startswith, 0, NULL, NULL },
  { "allocation_tracking", test_buffer_allocation_tracking, TT_FORK,
    NULL, NULL },
  { "time_tracking", test_buffer_time_tracking, TT_FORK, NULL, NULL },
  { "tls_read_mocked", test_buffers_tls_read_mocked, 0,
    NULL, NULL },
  { "chunk_size", test_buffers_chunk_size, 0, NULL, NULL },
  { "find_contentlen", test_buffers_find_contentlen, 0, NULL, NULL },
  { "find_string_empty_tail", test_buffers_find_string_empty_tail,
    TT_FORK, NULL, NULL },
  { "find_string_empty_interior", test_buffers_find_string_empty_interior,
    TT_FORK, NULL, NULL },
  { "find_string_long_needle", test_buffers_find_string_long_needle,
    TT_FORK, NULL, NULL },
  { "find_string_random", test_buffers_find_string_random,
    TT_FORK, NULL, NULL },
  { "find_string_pipe", test_buffers_find_string_pipe,
    TT_FORK, NULL, NULL },

  { "compress/zlib", test_buffers_compress, TT_FORK,
    &passthrough_setup, (char*)"deflate" },
  { "compress/gzip", test_buffers_compress, TT_FORK,
    &passthrough_setup, (char*)"gzip" },
  { "compress/zstd", test_buffers_compress, TT_FORK,
    &passthrough_setup, (char*)"x-zstd" },
  { "compress/lzma", test_buffers_compress, TT_FORK,
    &passthrough_setup, (char*)"x-tor-lzma" },
  { "compress/none", test_buffers_compress, TT_FORK,
    &passthrough_setup, (char*)"identity" },

  END_OF_TESTCASES
};
