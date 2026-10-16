// Runs each case of cases.txt on the host x86-64 CPU and prints what it changed.
// The input state comes from the stream x86_64_oracle.rs replays exactly, so the
// recording holds only the output differences, and only what the SDM defines.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint64_t r[16];
  uint64_t rflags, pad;
  uint8_t xmm[16][16];
} St;
struct Case {
  const char *name, *flags, *undefined;
  uint64_t flag_mask, reg_mask;
  void (*fn)(void *);
  char *insn, *end;
};
#include "cases.h"

#define MEMSZ 1024
#define GUARD 8192
// The RFLAGS bits drawn and compared: CF PF AF ZF SF DF OF.
#define DRAWN 0xcd5ULL
enum { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI };
__attribute__((aligned(4096))) uint8_t oracle_mem[MEMSZ + GUARD];

#include "stream.h"

// Pointers into the scratch memory hash as offsets, which do not depend on where it sits.
static uint64_t input_hash(const St *st, const uint8_t *mem) {
  uint64_t h = 0xcbf29ce484222325ULL, base = (uint64_t)(uintptr_t)oracle_mem;
  for (int i = 0; i < 16; i++) {
    uint64_t x = st->r[i];
    if (x >= base && x < base + MEMSZ) x -= base;
    h = fnv(h, &x, 8);
  }
  h = fnv(h, &st->rflags, 8);
  h = fnv(h, st->xmm, sizeof st->xmm);
  return fnv(h, mem, MEMSZ);
}

// A divisor nonzero at every width, so no `div` or `idiv` faults.
static void divisor(St *in) {
  if ((uint8_t)in->r[RBX] == 0) in->r[RBX] |= 1;
}

static void generate(St *in, const char *flags) {
  for (int i = 0; i < 16; i++) in->r[i] = pick();
  if (strchr(flags, 'F'))
    for (int i = 0; i < 16; i++) fplane(in->xmm[i]);
  else
    for (int i = 0; i < 16; i++) {
      uint64_t a = rnd(), b = rnd();
      memcpy(in->xmm[i], &a, 8);
      memcpy(in->xmm[i] + 8, &b, 8);
    }
  in->rflags = 0x202 | (rnd() & DRAWN);
  for (int i = 0; i < MEMSZ; i++) oracle_mem[i] = (uint8_t)rnd();
  memset(oracle_mem + MEMSZ, 0, GUARD);
  if (strchr(flags, 'P')) {
    uint64_t a = rnd() % 16, b = rnd() % 16;
    in->r[RSI] = (uint64_t)(uintptr_t)(oracle_mem + 384 + 16 * a);
    in->r[RDI] = (uint64_t)(uintptr_t)(oracle_mem + 384 + 16 * b);
  }
  if (strchr(flags, 'E') && rnd() % 2) {
    memcpy((void *)(uintptr_t)in->r[RDI], &in->r[RAX], 8);
    in->r[RBX] = in->r[RAX];
  }
  if (strchr(flags, 'N') && (uint16_t)in->r[RBX] == 0) in->r[RBX] |= 1ULL << (rnd() % 16);
  if (strchr(flags, 'D')) {
    in->r[RDX] = 0;
    in->r[RAX] &= ~0xff00ULL;
    divisor(in);
  }
  if (strchr(flags, 'S')) {
    int64_t small = (int64_t)(rnd() % 128) - 64;
    in->r[RAX] = (uint64_t)small;
    in->r[RDX] = small < 0 ? ~0ULL : 0;
    divisor(in);
  }
  in->r[RSP] = 0;
}

static void changes(const struct Case *k, const St *in, const St *out, const uint8_t *before) {
  uint64_t base = (uint64_t)(uintptr_t)oracle_mem;
  for (int i = 0; i < 16; i++) {
    if (i == RSP || (k->reg_mask >> i) & 1 || out->r[i] == in->r[i]) continue;
    uint64_t x = out->r[i];
    // A string operation's pointer is its offset from the memory.
    int pointer = (i == RSI || i == RDI) && strchr(k->flags, 'P');
    if (pointer || (x >= base && x < base + MEMSZ))
      printf(" p%d=%llx", i, (unsigned long long)(x - base));
    else printf(" r%d=%llx", i, (unsigned long long)x);
  }
  // An undefined flag is printed as it was: the recording holds no CPU's choice for it.
  uint64_t kept = DRAWN & ~k->flag_mask;
  uint64_t flags = (out->rflags & kept) | (in->rflags & DRAWN & k->flag_mask);
  if (flags != (in->rflags & DRAWN)) printf(" f=%llx", (unsigned long long)flags);
  for (int i = 0; i < 16; i++) {
    if (!memcmp(out->xmm[i], in->xmm[i], 16)) continue;
    printf(" x%d=", i);
    for (int j = 15; j >= 0; j--) printf("%02x", out->xmm[i][j]);
  }
  for (int i = 0; i < MEMSZ + GUARD; i++) {
    if (oracle_mem[i] == before[i]) continue;
    int j = i;
    while (j < MEMSZ + GUARD && oracle_mem[j] != before[j]) j++;
    printf(" m%d=", i);
    for (int b = i; b < j; b++) printf("%02x", oracle_mem[b]);
    i = j;
  }
}

int main(int argc, char **argv) {
  int runs = argc > 1 ? atoi(argv[1]) : 16;
  int n = sizeof CASES / sizeof CASES[0];
  for (int c = 0; c < n; c++) {
    struct Case *k = &CASES[c];
    printf("C %s %s %s ", k->name, k->flags, k->undefined);
    for (char *b = k->insn; b < k->end; b++) printf("%02x", (uint8_t)*b);
    printf("\n");
    for (int r = 0; r < runs; r++) {
      St in, out;
      memset(&in, 0, sizeof in);
      generate(&in, k->flags);
      uint8_t before[MEMSZ + GUARD];
      memcpy(before, oracle_mem, MEMSZ + GUARD);
      uint64_t h = input_hash(&in, before);
      out = in;
      k->fn(&out);
      printf("R %016llx", (unsigned long long)h);
      changes(k, &in, &out, before);
      printf("\n");
    }
  }
  return 0;
}
