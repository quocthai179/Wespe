#ifndef WESPE_MIB_TABLE_H
#define WESPE_MIB_TABLE_H

#include "mib_types.h"
#include "mib_object.h" /* mib_access_t */

#ifdef __cplusplus
extern "C" {
#endif

/* One column definition within a conceptual table -- the per-column
 * counterpart of mib_object_t for scalars. `number` is the column's own
 * sub-identifier (e.g. ifIndex=1, ifDescr=2 in IF-MIB's ifEntry); a
 * cell's full OID is {table->entry_oid}.{number}.{row index}. */
typedef struct {
    uint32_t     number;
    uint8_t      value_tag; /* expected BER_TAG_* / SNMP_TAG_* for this column's cells */
    mib_access_t access;
} mib_column_t;

/* Row-iteration and cell-access callbacks. Rows are identified by a
 * single uint32_t index (INTEGER32-shaped -- e.g. ifIndex, a sensor
 * number); multi-part or string-valued indices are not supported by this
 * MVP (see docs/PLAN-TABLES.md's "explicitly still deferred" list).
 *
 * first_index()/next_index() must enumerate existing rows in strictly
 * ascending index order and are called fresh on every resolve step --
 * rows are explicitly allowed to appear or disappear between calls (see
 * mib_sensor_table.c's optional volatile-rows mode), and these callbacks
 * are how the registry finds out. Both return MIB_OK with *out_index set,
 * or MIB_END_OF_VIEW if there is no (further) row. */
typedef mib_result_t (*mib_table_first_index_fn)(uint32_t *out_index);
typedef mib_result_t (*mib_table_next_index_fn)(uint32_t current_index, uint32_t *out_index);

/* Fills `vb` for cell (column, index); vb->oid/oid_len are NOT
 * pre-populated by the caller for table cells (unlike scalar getters --
 * the resolved instance OID is already in the mib_resolved_t the caller
 * built vb->oid from). Only value_tag and the matching value field need
 * filling in. */
typedef mib_result_t (*mib_table_get_cell_fn)(uint32_t column, uint32_t index, snmp_varbind_t *vb);
typedef mib_result_t (*mib_table_set_cell_fn)(uint32_t column, uint32_t index, const snmp_varbind_t *vb);

/* A conceptual (indexed) table. `columns` MUST be sorted ascending by
 * `number` -- the registry's column-major GETNEXT walk
 * (mib_registry.c's table_find_next()) relies on that order to find the
 * lexicographically-next cell by checking columns in sequence and
 * stopping at the first one with any candidate, rather than comparing
 * across every column on every step; see that function's comment for
 * why that shortcut is valid (it follows directly from OID ordering:
 * every cell in an earlier column sorts before every cell in a later
 * one, regardless of row index). */
typedef struct {
    const uint32_t      *entry_oid;     /* e.g. ifEntry's OID, without column or index */
    uint8_t               entry_oid_len;
    const mib_column_t  *columns;
    size_t                column_count;
    mib_table_first_index_fn first_index;
    mib_table_next_index_fn  next_index;
    mib_table_get_cell_fn    get_cell;
    mib_table_set_cell_fn    set_cell; /* NULL if the table has no writable columns */
} mib_table_t;

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_TABLE_H */
