/* Loops that leave by more than one exit. Every function is noinline so the optimizer keeps it as written. */
#define NOINL __attribute__((noinline))

static volatile int sink;

/* The exit the loop takes on a match is a test and two returns of its own. */
NOINL int find_then_choose(const char *s, int c, int strict)
{
    for (; *s; s++) {
        sink = *s;
        if (*s == c) {
            if (strict) {
                sink = 1;
                return 10;
            }
            sink = 2;
            return 20;
        }
    }
    sink = 3;
    return 0;
}

/* Two loops in a row, each leaving through the return after it and through one of its own. */
NOINL int skip_then_find(const char *s, int c, int limit)
{
    int n = 0;
    while (*s == ' ') {
        s++;
        if (++n > limit) {
            sink = n;
            return -1;
        }
    }
    for (; *s; s++) {
        if (*s == c) {
            sink = n;
            return n + 100;
        }
        n++;
    }
    return 0;
}

int main(void)
{
    return find_then_choose("a b", 'b', 1) + skip_then_find("  x", 'x', 4);
}
