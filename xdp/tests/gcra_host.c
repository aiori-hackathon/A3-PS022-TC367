/* Host-only deterministic and concurrent checks; not kernel acceptance. */
#define KAVACH_HOST_TEST
#include "../gcra.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>

static __u64 shared;
static unsigned allowed[8];
static void *worker(void *arg)
{
    unsigned id = *(unsigned *)arg;
    for (unsigned i = 0; i < 10000; i++)
        if (gcra(&shared, 1000000000ULL, 1000000ULL, 99000000ULL) == GCRA_ALLOW)
            allowed[id]++;
    return NULL;
}
int main(void)
{
    __u64 tat = 0;
    unsigned pass = 0;
    for (unsigned i = 0; i < 6; i++)
        pass += gcra(&tat, 1000000000ULL, 20000000ULL, 80000000ULL) == GCRA_ALLOW;
    assert(pass == 5);
    __u64 saved = tat;
    assert(gcra(&tat, 1000000000ULL, 20000000ULL, 80000000ULL) == GCRA_DROP);
    assert(tat == saved);
    tat = 0; pass = 0;
    for (unsigned i = 0; i < 1000; i++)
        pass += gcra(&tat, 1000000000ULL + i * 10000000ULL,
                     20000000ULL, 80000000ULL) == GCRA_ALLOW;
    assert(pass == 504);
    assert(gcra(&tat, 100000000000ULL, 20000000ULL, 80000000ULL) == GCRA_ALLOW);
    assert(gcra(&tat, 100000000000ULL, 0, 0) == GCRA_DROP);
    tat = ~(__u64)0 - 1;
    assert(gcra(&tat, tat, 10, 0) == GCRA_DROP);

    pthread_t threads[8]; unsigned ids[8];
    for (unsigned i = 0; i < 8; i++) {
        ids[i] = i;
        assert(pthread_create(&threads[i], NULL, worker, &ids[i]) == 0);
    }
    unsigned total = 0;
    for (unsigned i = 0; i < 8; i++) {
        assert(pthread_join(threads[i], NULL) == 0);
        total += allowed[i];
    }
    assert(total == 100);
    puts("PASS: deterministic GCRA, overflow guards, and 8-thread fixed-time burst");
    return 0;
}
