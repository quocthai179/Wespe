#ifndef WESPE_MIB_TREE_H
#define WESPE_MIB_TREE_H

#include "mib_object.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Register a build-time-sorted (ascending OID, lexicographic on arcs)
 * array of objects as one MIB module. Called once per module (mib_ii,
 * mib_wespe) during startup. A small fixed number of modules (see
 * MIB_MAX_MODULES in mib_registry.c) are searched as independent sorted
 * runs rather than merged into one array -- appropriate at this object
 * count (~15-25 total) and keeps each module's array a simple `const`
 * table with no registration-time sorting/copying required.
 * Returns 0 on success, -1 if the module table is full. */
int mib_registry_register_module(const mib_object_t *objects, size_t count);

/* Exact-match lookup for GetRequest: binary search within each registered
 * module. Returns NULL if no object has this OID. */
const mib_object_t *mib_registry_find(const uint32_t *oid, size_t oid_len);

/* Lower-bound lookup for GetNextRequest/GetBulkRequest: the object with
 * the smallest OID that is strictly greater than `oid`, across all
 * registered modules. Returns NULL if `oid` is at or past the end of the
 * whole MIB view (the GetNext/GetBulk handlers turn that into
 * MIB_END_OF_VIEW / a v1 noSuchName). */
const mib_object_t *mib_registry_find_next(const uint32_t *oid, size_t oid_len);

/* Total number of objects across all registered modules (mainly for
 * tests). */
size_t mib_registry_count(void);

/* Test-only: drop all registered modules so a test can start from a clean
 * registry. Production firmware registers modules once at boot and never
 * deregisters. */
void mib_registry_reset(void);

/* Lexicographic OID comparison, unsigned arc-by-arc, shorter-is-less on a
 * common prefix. Exposed because PDU handlers (GetBulk's repeat-until-
 * endOfMibView loop, GetNext's view boundary check) and tests both need it. */
int mib_oid_compare(const uint32_t *a, size_t a_len, const uint32_t *b, size_t b_len);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_TREE_H */
