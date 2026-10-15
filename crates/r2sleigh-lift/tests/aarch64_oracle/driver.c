// Runs each case of cases.txt on the host CPU and prints what it changed.
// The input state comes from one xorshift stream that aarch64_oracle.rs
// replays exactly, so the recording holds only the output differences.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint64_t x[31];
  uint64_t nzcv, fpcr, fpsr;
  uint8_t v[32][16];
  uint64_t taken;
} St;
struct Case {
  const char *name, *flags;
  void (*fn)(void *, void *);
  char *insn, *end, *tgt;
};
#include "cases.h"

#define MEMSZ 1024
// Zero bytes after the random ones, so an offset past them (`ldr x0, [x9, #4088]`) reads a known value.
#define GUARD 8192
__attribute__((aligned(4096))) uint8_t oracle_mem[MEMSZ + GUARD];

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
// Pointers into the scratch memory hash as offsets, which do not depend on where it sits.
static uint64_t input_hash(const St *st, const uint8_t *mem) {
  uint64_t h = 0xcbf29ce484222325ULL, base = (uint64_t)(uintptr_t)oracle_mem;
  for (int i = 0; i < 31; i++) {
    uint64_t x = st->x[i];
    if (x >= base && x < base + MEMSZ) x -= base;
    h = fnv(h, &x, 8);
  }
  h = fnv(h, &st->nzcv, 8);
  h = fnv(h, st->v, sizeof st->v);
  return fnv(h, mem, MEMSZ);
}

static void generate(St *in, const char *flags) {
  for (int i = 0; i < 31; i++) in->x[i] = pick();
  if (strchr(flags, 'F'))
    for (int i = 0; i < 32; i++) fplane(in->v[i]);
  else
    for (int i = 0; i < 32; i++) {
      uint64_t a = rnd(), b = rnd();
      memcpy(in->v[i], &a, 8);
      memcpy(in->v[i] + 8, &b, 8);
    }
  in->nzcv = (rnd() & 0xf) << 28;
  for (int i = 0; i < MEMSZ; i++) oracle_mem[i] = (uint8_t)rnd();
  memset(oracle_mem + MEMSZ, 0, GUARD);
  if (strchr(flags, 'P')) {
    uint64_t a = rnd() % 16, b = rnd() % 16;
    in->x[9] = (uint64_t)(uintptr_t)(oracle_mem + 384 + 16 * a);
    in->x[10] = (uint64_t)(uintptr_t)(oracle_mem + 384 + 16 * b);
  }
  int64_t small = (int64_t)(rnd() % 33) - 16;
  if (strchr(flags, 'I')) in->x[11] = (uint64_t)small;
  if (strchr(flags, 'J')) {
    if (rnd() % 2) in->x[11] = (uint64_t)small;
    else {
      uint64_t hi = rnd() << 32;
      in->x[11] = hi | ((uint64_t)small & 0xffffffffULL);
    }
  }
  if (strchr(flags, 'U')) {
    uint64_t hi = rnd() << 32;
    in->x[11] = hi | (rnd() % 17);
  }
  if (strchr(flags, 'E') && rnd() % 2) {
    memcpy((void *)(uintptr_t)in->x[9], &in->x[0], 8);
    memcpy((void *)(uintptr_t)(in->x[9] + 8), &in->x[1], 8);
  }
  in->x[18] = 0;
}

int main(int argc, char **argv) {
  int runs = argc > 1 ? atoi(argv[1]) : 16;
  int n = sizeof CASES / sizeof CASES[0];
  uint64_t base = (uint64_t)(uintptr_t)oracle_mem;
  for (int c = 0; c < n; c++) {
    struct Case *k = &CASES[c];
    int words = (int)((k->end - k->insn) / 4);
    uint64_t code = (uint64_t)(uintptr_t)k->insn;
    // The code's page offset fixes what `adrp` computes; the slide is the loader's.
    printf("C %s %s %llx %lld", k->name, k->flags, (unsigned long long)(code & 0xfff),
           (long long)(k->tgt - k->insn));
    for (int i = 0; i < words; i++) printf(" %08x", ((uint32_t *)k->insn)[i]);
    printf("\n");
    for (int r = 0; r < runs; r++) {
      St in, out;
      memset(&in, 0, sizeof in);
      memset(&out, 0, sizeof out);
      generate(&in, k->flags);
      uint8_t before[MEMSZ + GUARD];
      memcpy(before, oracle_mem, MEMSZ + GUARD);
      uint64_t h = input_hash(&in, before);
      k->fn(&in, &out);
      printf("R %016llx", (unsigned long long)h);
      for (int i = 0; i < 31; i++) {
        if (i == 18 || out.x[i] == in.x[i]) continue;
        uint64_t x = out.x[i];
        int64_t from_code = (int64_t)(x - code);
        // A base register written back (post-indexed) is its offset from the memory.
        int pointer = (i == 9 || i == 10) && strchr(k->flags, 'P');
        // An address computed from the code (`adr`, `adrp`) is its distance from the case.
        if (strchr(k->flags, 'A')) printf(" c%d=%lld", i, (long long)from_code);
        else if (pointer || (x >= base && x < base + MEMSZ))
          printf(" p%d=%llx", i, (unsigned long long)(x - base));
        else printf(" x%d=%llx", i, (unsigned long long)x);
      }
      if (out.nzcv != in.nzcv) printf(" n=%llx", (unsigned long long)(out.nzcv >> 28));
      for (int i = 0; i < 32; i++) {
        if (!memcmp(out.v[i], in.v[i], 16)) continue;
        printf(" v%d=", i);
        for (int j = 15; j >= 0; j--) printf("%02x", out.v[i][j]);
      }
      for (int i = 0; i < MEMSZ + GUARD; i++) {
        if (oracle_mem[i] == before[i]) continue;
        int j = i;
        while (j < MEMSZ + GUARD && oracle_mem[j] != before[j]) j++;
        printf(" m%d=", i);
        for (int b = i; b < j; b++) printf("%02x", oracle_mem[b]);
        i = j;
      }
      if (out.taken) printf(" t");
      printf("\n");
    }
  }
  return 0;
}
