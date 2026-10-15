/* Atomic read-modify-writes as C11 programs use them: counters, flags, a
 * lock, a reference count. Each function is built for ARMv8.1-A on AArch64,
 * so the compilers emit its LSE instruction (`ldadd`, `ldset`, `ldclr`,
 * `ldeor`, `swp`, `cas`, `stadd`) rather than a call to the outline helper;
 * on x86-64 they are `lock` operations, `xchg` and `lock cmpxchg` loops. */
#include <stdint.h>

#if defined(__aarch64__)
#define LSE __attribute__((target("arch=armv8.1-a")))
#else
#define LSE
#endif

LSE uint32_t counter_next(uint32_t *counter)
{
    return __atomic_fetch_add(counter, 1, __ATOMIC_RELAXED);
}

LSE uint64_t ticket_take(uint64_t *next, uint64_t count)
{
    return __atomic_fetch_add(next, count, __ATOMIC_SEQ_CST);
}

LSE void total_add(uint64_t *total, uint64_t amount)
{
    __atomic_add_fetch(total, amount, __ATOMIC_RELAXED);
}

LSE uint32_t flags_set(uint32_t *flags, uint32_t bits)
{
    return __atomic_fetch_or(flags, bits, __ATOMIC_ACQUIRE);
}

LSE uint32_t flags_clear(uint32_t *flags, uint32_t bits)
{
    return __atomic_fetch_and(flags, ~bits, __ATOMIC_RELEASE);
}

LSE uint16_t parity_toggle(uint16_t *word, uint16_t mask)
{
    return __atomic_fetch_xor(word, mask, __ATOMIC_RELAXED);
}

LSE uint8_t slot_swap(uint8_t *slot, uint8_t value)
{
    return __atomic_exchange_n(slot, value, __ATOMIC_SEQ_CST);
}

LSE int lock_try(int32_t *lock)
{
    int32_t expected = 0;
    return __atomic_compare_exchange_n(lock, &expected, 1, 0, __ATOMIC_ACQUIRE,
                                       __ATOMIC_RELAXED);
}

LSE uint64_t cell_exchange(uint64_t *cell, uint64_t expected, uint64_t desired)
{
    __atomic_compare_exchange_n(cell, &expected, desired, 0, __ATOMIC_SEQ_CST,
                                __ATOMIC_SEQ_CST);
    return expected;
}

LSE int reference_release(int32_t *count)
{
    return __atomic_sub_fetch(count, 1, __ATOMIC_ACQ_REL) == 0;
}
