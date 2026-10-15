/* Loops whose carried value only a conditional write changes, run more than
 * once: a running maximum and minimum (`cmovcc` on x86-64, `csel` on AArch64)
 * and a compare-and-exchange that fails once before it succeeds. A rendering
 * that reads the value the loop was entered with on every pass differs. */
#include <stdint.h>

uint64_t spread(const int64_t *values, int count)
{
    int64_t most = INT64_MIN;
    int64_t least = INT64_MAX;
    for (int i = 0; i < count; i++) {
        if (values[i] > most)
            most = values[i];
        if (values[i] < least)
            least = values[i];
    }
    return (uint64_t)most - (uint64_t)least;
}

/* The store makes the first compare fail, so the second compares against the
 * value the first loaded. */
uint64_t exchange_after_store(uint64_t *cell)
{
    uint64_t expected = *cell;
    *cell = expected + 1;
    while (!__atomic_compare_exchange_n(cell, &expected, expected + 10, 0,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        ;
    return expected;
}
