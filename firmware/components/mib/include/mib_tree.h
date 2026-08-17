#ifndef WESPE_MIB_TREE_H
#define WESPE_MIB_TREE_H

#include "mib_object.h"
#include "mib_table.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * Scalar module registration -- unchanged since Phase 0-9. Kept as its
 * own API (rather than folded away) because host_tests/test_mib_registry.c
 * exercises it directly, and it remains the right tool for a module that
 * really is just a flat list of scalars (mib_ii.c). Table-aware callers
 * (snmp_core's PDU handlers) use the resolve API below instead, which
 * covers both scalars and table cells through one interface.
 * ------------------------------------------------------------------- */

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

/* Total number of scalar objects across all registered modules (mainly
 * for tests; does not count table cells, which don't have a fixed
 * count). */
size_t mib_registry_count(void);

/* Test-only: drop all registered modules and tables so a test can start
 * from a clean registry. Production firmware registers modules/tables
 * once at boot and never deregisters. */
void mib_registry_reset(void);

/* Lexicographic OID comparison, unsigned arc-by-arc, shorter-is-less on a
 * common prefix. Exposed because PDU handlers (GetBulk's repeat-until-
 * endOfMibView loop, GetNext's view boundary check) and tests both need it. */
int mib_oid_compare(const uint32_t *a, size_t a_len, const uint32_t *b, size_t b_len);

/* ---------------------------------------------------------------------
 * Table registration (docs/PLAN-TABLES.md Phase 11).
 * ------------------------------------------------------------------- */

/* Registers a conceptual table (see mib_table.h). Returns 0 on success,
 * -1 if the table registration slot table is full. */
int mib_registry_register_table(const mib_table_t *table);

/* ---------------------------------------------------------------------
 * Unified resolve API: scalars and table cells through one interface, so
 * snmp_core's PDU handlers never branch on which kind an OID names. This
 * is what GetRequest/GetNextRequest/SetRequest/GetBulkRequest actually
 * call; mib_registry_find*() above stays scalar-only and is what this is
 * built on top of.
 * ------------------------------------------------------------------- */

typedef enum {
    MIB_RESOLVED_SCALAR,
    MIB_RESOLVED_CELL,
} mib_resolved_kind_t;

typedef struct {
    uint32_t     oid[BER_MAX_OID_LEN]; /* the fully-resolved instance OID */
    uint8_t      oid_len;
    uint8_t      value_tag;
    mib_access_t access;

    mib_resolved_kind_t kind;
    union {
        const mib_object_t *scalar; /* kind == MIB_RESOLVED_SCALAR */
        struct {
            const mib_table_t *table;
            uint32_t            column;
            uint32_t            index;
        } cell; /* kind == MIB_RESOLVED_CELL */
    };
} mib_resolved_t;

/* Exact-match resolve, for GetRequest/SetRequest. Distinguishes
 * MIB_NO_SUCH_OBJECT (nothing registered at this OID at all -- e.g. an
 * unknown column, or no scalar/table claims this OID) from
 * MIB_NO_SUCH_INSTANCE (the column/object is real, but this particular
 * row doesn't currently exist) per RFC3416 3.2.2; both scalars and table
 * cells can produce either. */
mib_result_t mib_registry_resolve(const uint32_t *oid, size_t oid_len, mib_resolved_t *out);

/* Lower-bound resolve, for GetNextRequest/GetBulkRequest: the smallest
 * OID strictly greater than `oid` across every registered scalar module
 * and table (column-major within each table -- see mib_table.h). Returns
 * MIB_END_OF_VIEW if `oid` is at or past everything registered. */
mib_result_t mib_registry_resolve_next(const uint32_t *oid, size_t oid_len, mib_resolved_t *out);

/* Reads/writes through a previously-resolved object or cell. */
mib_result_t mib_resolved_get(const mib_resolved_t *r, snmp_varbind_t *vb);
mib_result_t mib_resolved_set(const mib_resolved_t *r, const snmp_varbind_t *vb);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_TREE_H */
