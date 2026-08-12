/* MIB object registry: a small fixed set of build-time-sorted `const`
 * arrays (one per registered module), searched with binary search. See
 * mib_tree.h for why a flat sorted array beats a pointer-based tree at
 * this scale (~15-25 scalar objects). No ESP-IDF dependency -- host-
 * testable, see host_tests/test_mib_registry.c. */
#include "mib_tree.h"
#include <string.h>

#define MIB_MAX_MODULES 4

typedef struct {
    const mib_object_t *objects;
    size_t               count;
} mib_module_t;

static mib_module_t s_modules[MIB_MAX_MODULES];
static size_t s_module_count = 0;

int mib_oid_compare(const uint32_t *a, size_t a_len, const uint32_t *b, size_t b_len)
{
    size_t n = a_len < b_len ? a_len : b_len;
    for (size_t i = 0; i < n; i++) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    if (a_len < b_len) {
        return -1;
    }
    if (a_len > b_len) {
        return 1;
    }
    return 0;
}

int mib_registry_register_module(const mib_object_t *objects, size_t count)
{
    if (s_module_count >= MIB_MAX_MODULES) {
        return -1;
    }
    s_modules[s_module_count].objects = objects;
    s_modules[s_module_count].count = count;
    s_module_count++;
    return 0;
}

void mib_registry_reset(void)
{
    s_module_count = 0;
    memset(s_modules, 0, sizeof(s_modules));
}

size_t mib_registry_count(void)
{
    size_t total = 0;
    for (size_t m = 0; m < s_module_count; m++) {
        total += s_modules[m].count;
    }
    return total;
}

const mib_object_t *mib_registry_find(const uint32_t *oid, size_t oid_len)
{
    for (size_t m = 0; m < s_module_count; m++) {
        const mib_object_t *objs = s_modules[m].objects;
        size_t lo = 0;
        size_t hi = s_modules[m].count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int c = mib_oid_compare(objs[mid].oid, objs[mid].oid_len, oid, oid_len);
            if (c == 0) {
                return &objs[mid];
            }
            if (c < 0) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
    }
    return NULL;
}

const mib_object_t *mib_registry_find_next(const uint32_t *oid, size_t oid_len)
{
    const mib_object_t *best = NULL;
    for (size_t m = 0; m < s_module_count; m++) {
        const mib_object_t *objs = s_modules[m].objects;
        size_t lo = 0;
        size_t hi = s_modules[m].count;
        /* upper_bound: first index whose OID is strictly greater than the target. */
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int c = mib_oid_compare(objs[mid].oid, objs[mid].oid_len, oid, oid_len);
            if (c > 0) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        if (lo < s_modules[m].count) {
            const mib_object_t *cand = &objs[lo];
            if (best == NULL || mib_oid_compare(cand->oid, cand->oid_len, best->oid, best->oid_len) < 0) {
                best = cand;
            }
        }
    }
    return best;
}
