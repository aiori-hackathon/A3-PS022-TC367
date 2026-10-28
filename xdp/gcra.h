/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KAVACH_GCRA_H
#define KAVACH_GCRA_H
#ifdef KAVACH_HOST_TEST
#include <stdint.h>
typedef uint64_t __u64;
#define KAVACH_INLINE inline __attribute__((always_inline))
#define KAVACH_READ(p) __atomic_load_n((p), __ATOMIC_RELAXED)
#else
#include <linux/types.h>
#define KAVACH_INLINE __always_inline
#define KAVACH_READ(p) (*(volatile __u64 *)(p))
#endif
#define GCRA_ALLOW 1
#define GCRA_DROP 0
#define GCRA_BUSY (-1)
#define GCRA_TRIES 8

static KAVACH_INLINE int gcra(__u64 *slot, __u64 now,
                              __u64 interval, __u64 tolerance)
{
#ifndef KAVACH_HOST_TEST
#pragma unroll
#endif
    for (int i = 0; i < GCRA_TRIES; i++) {
        __u64 old = KAVACH_READ(slot);
        __u64 base = old > now ? old : now;
        if (base - now > tolerance)
            return GCRA_DROP;
        /* Reject invalid/overflowing time arithmetic without mutating state. */
        if (!interval || base > (~(__u64)0) - interval)
            return GCRA_DROP;
#ifdef KAVACH_APPROXIMATE
#ifdef KAVACH_HOST_TEST
        __atomic_store_n(slot, base + interval, __ATOMIC_RELAXED);
#else
        *(volatile __u64 *)slot = base + interval;
#endif
        return GCRA_ALLOW;
#else
        if (__sync_val_compare_and_swap(slot, old, base + interval) == old)
            return GCRA_ALLOW;
#endif
    }
    return GCRA_BUSY;
}
#endif
