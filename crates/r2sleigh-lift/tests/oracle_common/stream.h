// The input stream both CPU oracles draw from; oracle_common/mod.rs draws the same values.
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static uint64_t s = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) {
  s ^= s << 13;
  s ^= s >> 7;
  s ^= s << 17;
  return s;
}
static uint64_t pick(void) {
  uint64_t k = rnd() % 13;
  switch (k) {
  case 0: return 0;
  case 1: return 1;
  case 2: return ~0ULL;
  case 3: return 0x8000000000000000ULL;
  case 4: return 0x7fffffffffffffffULL;
  case 5: return 0x80000000ULL;
  case 6: return 0x7fffffffULL;
  case 7: return 0xffffffffULL;
  case 8: return rnd() % 64;
  case 9: return rnd() << 32;
  case 10: return (uint64_t)(int64_t)(int32_t)rnd();
  case 11: return 0xffffffff80000000ULL;
  default: return rnd();
  }
}
static const uint64_t DP[] = {
    0, 0x8000000000000000ULL, 0x3ff0000000000000ULL, 0xbff8000000000000ULL,
    0x4004000000000000ULL, 0x3fe0000000000000ULL, 0x7ff0000000000000ULL,
    0xfff0000000000000ULL, 0x7ff8000000000000ULL, 0x7ff4000000000001ULL,
    0x7ff8dead0000beefULL, 0x1ULL, 0x7e37e43c8800759cULL, 0xc3e158e460913d00ULL,
    0x43e0000000000000ULL, 0x43f0000000000000ULL, 0xc3e0000000000000ULL,
    0x41e0000000000000ULL, 0xc1e0000000200000ULL, 0x41f0000000000000ULL,
    0x3fdfffffffffffffULL, 0xc004000000000000ULL, 0x400c000000000000ULL,
    0x3ff8000000000000ULL, 0xfff8000000000001ULL, 0x000fffffffffffffULL};
static const uint32_t SP[] = {
    0, 0x80000000, 0x3f800000, 0xbfc00000, 0x40200000, 0x3f000000,
    0x7f800000, 0xff800000, 0x7fc00000, 0x7fa00001, 0x7fc0beef, 1,
    0x5f000000, 0xdf000000, 0x4f000000, 0xcf000001, 0x4f800000, 0x3effffff,
    0xc0200000, 0x40600000, 0x7f7fffff, 0x007fffff};
#define NDP (sizeof DP / sizeof DP[0])
#define NSP (sizeof SP / sizeof SP[0])
static double frand(void) { return ((double)(int64_t)rnd()) / 9.2e12; }
static uint32_t fbits(void) {
  float f = (float)frand();
  uint32_t a;
  memcpy(&a, &f, 4);
  return a;
}
// Every operand is drawn in its own statement: C leaves operand order open.
static void fplane(uint8_t *v) {
  uint64_t lo, hi, a, b;
  switch (rnd() % 4) {
  case 0: lo = DP[rnd() % NDP]; break;
  case 1: { double d = frand(); memcpy(&lo, &d, 8); } break;
  case 2: a = SP[rnd() % NSP]; b = SP[rnd() % NSP]; lo = a | (b << 32); break;
  default: a = fbits(); b = fbits(); lo = a | (b << 32);
  }
  switch (rnd() % 3) {
  case 0: hi = DP[rnd() % NDP]; break;
  case 1: a = SP[rnd() % NSP]; b = SP[rnd() % NSP]; hi = a | (b << 32); break;
  default: hi = rnd();
  }
  memcpy(v, &lo, 8);
  memcpy(v + 8, &hi, 8);
}

static uint64_t fnv(uint64_t h, const void *p, size_t n) {
  const uint8_t *b = p;
  for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 0x100000001b3ULL;
  return h;
}
