/* Dedicated tests for the table-resolve logic added in
 * firmware/components/mib/mib_registry.c (docs/PLAN-TABLES.md Phase 11)
 * -- exact-match cell lookup, column-major GETNEXT ordering, sparse/
 * disappearing rows, and falling out of a table into whatever's
 * registered next. This is the part of the whole tables feature most
 * likely to have an off-by-one in it, so it gets the most dedicated
 * coverage of anything in this phase. */
#include "unity_mini.h"
#include "mib_tree.h"
#include <string.h>

/* --- A mock table: rows {1, 2, 5} (deliberately sparse -- 3, 4 don't
 * exist), two columns (col 1 RO INTEGER, col 2 RW OCTET STRING),
 * bracketed by a scalar before and a scalar after so cross-source
 * ordering (scalar -> table -> scalar) is exercised too. --- */

static const uint32_t OID_SCALAR_BEFORE[] = {1, 3, 6, 1, 4, 1, 22222, 1, 1, 0};
static const uint32_t TABLE_ENTRY_OID[]   = {1, 3, 6, 1, 4, 1, 22222, 2, 1};
static const uint32_t OID_SCALAR_AFTER[]  = {1, 3, 6, 1, 4, 1, 22222, 3, 1, 0};

typedef struct {
    uint32_t index;
    int32_t  col1_value;
    char     col2_value[16];
    int      active; /* toggled off to simulate a disappearing row */
} mock_row_t;

static mock_row_t s_rows[] = {
    {1, 100, "row-one", 1},
    {2, 200, "row-two", 1},
    {5, 500, "row-five", 1},
};
#define ROW_COUNT (sizeof(s_rows) / sizeof(s_rows[0]))

static mock_row_t *find_row(uint32_t index)
{
    for (size_t i = 0; i < ROW_COUNT; i++) {
        if (s_rows[i].index == index && s_rows[i].active) {
            return &s_rows[i];
        }
    }
    return NULL;
}

static mib_result_t mock_first_index(uint32_t *out_index)
{
    for (size_t i = 0; i < ROW_COUNT; i++) {
        if (s_rows[i].active) {
            *out_index = s_rows[i].index;
            return MIB_OK;
        }
    }
    return MIB_END_OF_VIEW;
}

static mib_result_t mock_next_index(uint32_t current_index, uint32_t *out_index)
{
    /* s_rows is declared in ascending index order; a real table with a
     * more dynamic row set would sort or scan for the smallest active
     * index > current_index, same contract either way. */
    for (size_t i = 0; i < ROW_COUNT; i++) {
        if (s_rows[i].active && s_rows[i].index > current_index) {
            *out_index = s_rows[i].index;
            return MIB_OK;
        }
    }
    return MIB_END_OF_VIEW;
}

static mib_result_t mock_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    mock_row_t *row = find_row(index);
    if (row == NULL) {
        return MIB_NO_SUCH_INSTANCE;
    }
    if (column == 1) {
        vb->value_tag = BER_TAG_INTEGER;
        vb->int_value = row->col1_value;
        return MIB_OK;
    }
    if (column == 2) {
        vb->value_tag = BER_TAG_OCTET_STRING;
        vb->octets_len = strlen(row->col2_value);
        memcpy(vb->octets, row->col2_value, vb->octets_len);
        return MIB_OK;
    }
    return MIB_NO_SUCH_OBJECT;
}

static mib_result_t mock_set_cell(uint32_t column, uint32_t index, const snmp_varbind_t *vb)
{
    mock_row_t *row = find_row(index);
    if (row == NULL) {
        return MIB_NO_SUCH_INSTANCE;
    }
    if (column != 2) {
        /* col 1 is RO -- a real PDU handler checks mib_resolved_t.access
         * before ever calling mib_resolved_set(), so reaching here with
         * column 1 shouldn't happen via the normal request path; this is
         * this mock's own second layer of defense, same spirit as
         * mib_wespe.c's setters validating what the generic type check
         * can't express. */
        return MIB_NOT_WRITABLE;
    }
    if (vb->value_tag != BER_TAG_OCTET_STRING || vb->octets_len >= sizeof(row->col2_value)) {
        return MIB_WRONG_VALUE;
    }
    memcpy(row->col2_value, vb->octets, vb->octets_len);
    row->col2_value[vb->octets_len] = '\0';
    return MIB_OK;
}

static const mib_column_t s_columns[] = {
    {1, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {2, BER_TAG_OCTET_STRING, MIB_ACCESS_RW},
};

static const mib_table_t s_table = {
    .entry_oid = TABLE_ENTRY_OID,
    .entry_oid_len = 9,
    .columns = s_columns,
    .column_count = 2,
    .first_index = mock_first_index,
    .next_index = mock_next_index,
    .get_cell = mock_get_cell,
    .set_cell = mock_set_cell,
};

/* A second, read-only table (no set_cell at all) purely to test
 * mib_resolved_set()'s defensive "table has no set_cell" path. */
static const uint32_t RO_TABLE_ENTRY_OID[] = {1, 3, 6, 1, 4, 1, 22222, 4, 1};
static mib_result_t ro_first_index(uint32_t *out_index)
{
    *out_index = 1;
    return MIB_OK;
}
static mib_result_t ro_next_index(uint32_t current_index, uint32_t *out_index)
{
    (void)current_index;
    (void)out_index;
    return MIB_END_OF_VIEW;
}
static mib_result_t ro_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    (void)column;
    (void)index;
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = 42;
    return MIB_OK;
}
static const mib_column_t s_ro_columns[] = {{1, BER_TAG_INTEGER, MIB_ACCESS_RO}};
static const mib_table_t s_ro_table = {
    .entry_oid = RO_TABLE_ENTRY_OID,
    .entry_oid_len = 9,
    .columns = s_ro_columns,
    .column_count = 1,
    .first_index = ro_first_index,
    .next_index = ro_next_index,
    .get_cell = ro_get_cell,
    .set_cell = NULL,
};

static mib_result_t get_scalar_before(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = -1;
    return MIB_OK;
}
static mib_result_t get_scalar_after(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = -2;
    return MIB_OK;
}
static const mib_object_t s_scalars[] = {
    {OID_SCALAR_BEFORE, 10, BER_TAG_INTEGER, MIB_ACCESS_RO, get_scalar_before, NULL},
    {OID_SCALAR_AFTER, 10, BER_TAG_INTEGER, MIB_ACCESS_RO, get_scalar_after, NULL},
};

static void setup(void)
{
    mib_registry_reset();
    mib_registry_register_module(s_scalars, 2);
    mib_registry_register_table(&s_table);
    s_rows[0].active = 1;
    s_rows[1].active = 1;
    s_rows[2].active = 1;
    strcpy(s_rows[0].col2_value, "row-one");
    strcpy(s_rows[1].col2_value, "row-two");
    strcpy(s_rows[2].col2_value, "row-five");
}

static uint32_t cell_oid(uint32_t column, uint32_t index, uint32_t *buf)
{
    memcpy(buf, TABLE_ENTRY_OID, 9 * sizeof(uint32_t));
    buf[9] = column;
    buf[10] = index;
    return 11;
}

/* ---- Exact match (mib_registry_resolve) ---- */

UM_TEST(test_resolve_exact_cell_found)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(1, 2, oid);
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve(oid, len, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.kind, MIB_RESOLVED_CELL);
    UM_CHECK_EQ_INT(r.value_tag, BER_TAG_INTEGER);
    UM_CHECK_EQ_INT(r.access, MIB_ACCESS_RO);
    snmp_varbind_t vb;
    memset(&vb, 0, sizeof(vb));
    UM_CHECK_EQ_INT(mib_resolved_get(&r, &vb), MIB_OK);
    UM_CHECK_EQ_INT(vb.int_value, 200);
}

UM_TEST(test_resolve_exact_cell_missing_row_is_no_such_instance)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(1, 3, oid); /* row 3 doesn't exist (sparse) */
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve(oid, len, &r), MIB_NO_SUCH_INSTANCE);
}

UM_TEST(test_resolve_exact_unknown_column_is_no_such_object)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(99, 1, oid);
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve(oid, len, &r), MIB_NO_SUCH_OBJECT);
}

UM_TEST(test_resolve_exact_wrong_shape_is_no_such_object)
{
    setup();
    /* Table entry OID with no column/index suffix at all. */
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve(TABLE_ENTRY_OID, 9, &r), MIB_NO_SUCH_OBJECT);
}

/* ---- GETNEXT ordering (mib_registry_resolve_next) ---- */

UM_TEST(test_resolve_next_from_before_scalar_reaches_scalar)
{
    setup();
    uint32_t before[] = {1};
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(before, 1, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.kind, MIB_RESOLVED_SCALAR);
    UM_CHECK(r.scalar->oid == OID_SCALAR_BEFORE);
}

UM_TEST(test_resolve_next_from_scalar_enters_table_at_first_cell)
{
    setup();
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(OID_SCALAR_BEFORE, 10, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.kind, MIB_RESOLVED_CELL);
    UM_CHECK_EQ_INT(r.cell.column, 1);
    UM_CHECK_EQ_INT(r.cell.index, 1); /* first row of first column */
}

UM_TEST(test_resolve_next_within_column_walks_rows_ascending)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(1, 1, oid);
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(oid, len, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.cell.column, 1);
    UM_CHECK_EQ_INT(r.cell.index, 2);
}

UM_TEST(test_resolve_next_skips_sparse_gap)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(1, 2, oid);
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(oid, len, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.cell.column, 1);
    UM_CHECK_EQ_INT(r.cell.index, 5); /* skips 3, 4 -- they don't exist */
}

UM_TEST(test_resolve_next_crosses_column_boundary)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(1, 5, oid); /* last row of column 1 */
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(oid, len, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.cell.column, 2); /* -> first row of column 2, not column 1 wrapping */
    UM_CHECK_EQ_INT(r.cell.index, 1);
}

UM_TEST(test_resolve_next_falls_out_of_table_into_next_scalar)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(2, 5, oid); /* last cell of the last column */
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(oid, len, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.kind, MIB_RESOLVED_SCALAR);
    UM_CHECK(r.scalar->oid == OID_SCALAR_AFTER);
}

UM_TEST(test_resolve_next_past_everything_is_end_of_view)
{
    setup();
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(OID_SCALAR_AFTER, 10, &r), MIB_END_OF_VIEW);
}

UM_TEST(test_resolve_next_on_exact_match_advances_not_repeats)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(1, 2, oid);
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(oid, len, &r), MIB_OK);
    UM_CHECK(r.cell.index != 2 || r.cell.column != 1);
}

UM_TEST(test_resolve_next_entering_from_bare_column_prefix)
{
    setup();
    /* Column 2's node with no index yet -- must land on its first row,
     * not be treated as "past" the column. */
    uint32_t oid[16];
    memcpy(oid, TABLE_ENTRY_OID, 9 * sizeof(uint32_t));
    oid[9] = 2;
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(oid, 10, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.cell.column, 2);
    UM_CHECK_EQ_INT(r.cell.index, 1);
}

/* ---- Disappearing rows ---- */

UM_TEST(test_resolve_next_skips_deactivated_row)
{
    setup();
    s_rows[1].active = 0; /* row index 2 vanishes mid-walk */
    uint32_t oid[16];
    uint32_t len = cell_oid(1, 1, oid);
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve_next(oid, len, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.cell.index, 5); /* not 2 -- it's gone */
}

UM_TEST(test_resolve_exact_deactivated_row_is_no_such_instance)
{
    setup();
    s_rows[1].active = 0;
    uint32_t oid[16];
    uint32_t len = cell_oid(1, 2, oid);
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve(oid, len, &r), MIB_NO_SUCH_INSTANCE);
}

/* ---- SET through the resolved handle ---- */

UM_TEST(test_resolved_set_writes_through_to_the_table)
{
    setup();
    uint32_t oid[16];
    uint32_t len = cell_oid(2, 1, oid);
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve(oid, len, &r), MIB_OK);

    snmp_varbind_t vb;
    memset(&vb, 0, sizeof(vb));
    vb.value_tag = BER_TAG_OCTET_STRING;
    vb.octets_len = 8;
    memcpy(vb.octets, "rack-top", 8);
    UM_CHECK_EQ_INT(mib_resolved_set(&r, &vb), MIB_OK);
    UM_CHECK_EQ_MEM(s_rows[0].col2_value, "rack-top", 8);
}

/* ---- Multiple tables registered simultaneously (Phase 13a's real
 * ifTable + ifXTable coexisting is the motivating case -- every test
 * above only ever registers one table at a time, which doesn't exercise
 * mib_registry_resolve_next()'s "best candidate across every table"
 * comparison the way a >1-table registry actually does in production). --- */

UM_TEST(test_resolve_next_walks_across_two_tables_via_intervening_scalar)
{
    /* OID order here: OID_SCALAR_BEFORE(.1.1) < s_table(.2.1.*) <
     * OID_SCALAR_AFTER(.3.1) < s_ro_table(.4.1.*) -- registering both
     * tables plus both scalars at once means resolve_next has two live
     * table candidates to choose the global-smallest from at every step,
     * not just one. */
    setup(); /* registers s_scalars + s_table */
    mib_registry_register_table(&s_ro_table);

    uint32_t oid[16];
    uint32_t len = cell_oid(2, 5, oid); /* last cell of s_table's last column */
    mib_resolved_t r;

    UM_CHECK_EQ_INT(mib_registry_resolve_next(oid, len, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.kind, MIB_RESOLVED_SCALAR);
    UM_CHECK(r.scalar->oid == OID_SCALAR_AFTER); /* falls out of s_table, not into s_ro_table yet */

    UM_CHECK_EQ_INT(mib_registry_resolve_next(OID_SCALAR_AFTER, 10, &r), MIB_OK);
    UM_CHECK_EQ_INT(r.kind, MIB_RESOLVED_CELL);
    UM_CHECK(r.cell.table == &s_ro_table); /* now the *other* table, correctly picked over s_table */
    UM_CHECK_EQ_INT(r.cell.column, 1);
    UM_CHECK_EQ_INT(r.cell.index, 1);

    UM_CHECK_EQ_INT(mib_registry_resolve_next(r.oid, r.oid_len, &r), MIB_END_OF_VIEW); /* nothing after the second table's one cell */
}

UM_TEST(test_resolve_exact_disambiguates_between_two_tables_by_prefix)
{
    /* Exact-match resolve must pick the table whose entry_oid prefix
     * actually matches -- not just "the first one registered" -- even
     * though both are live in the registry at once. */
    setup();
    mib_registry_register_table(&s_ro_table);

    uint32_t oid[16];
    memcpy(oid, RO_TABLE_ENTRY_OID, 9 * sizeof(uint32_t));
    oid[9] = 1;
    oid[10] = 1;
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve(oid, 11, &r), MIB_OK);
    UM_CHECK(r.cell.table == &s_ro_table);

    snmp_varbind_t vb;
    memset(&vb, 0, sizeof(vb));
    UM_CHECK_EQ_INT(mib_resolved_get(&r, &vb), MIB_OK);
    UM_CHECK_EQ_INT(vb.int_value, 42); /* s_ro_table's fixed value, not s_table's */
}

UM_TEST(test_resolved_set_on_table_with_no_set_cell_is_not_writable)
{
    mib_registry_reset();
    mib_registry_register_table(&s_ro_table);
    uint32_t oid[16];
    memcpy(oid, RO_TABLE_ENTRY_OID, 9 * sizeof(uint32_t));
    oid[9] = 1;
    oid[10] = 1;
    mib_resolved_t r;
    UM_CHECK_EQ_INT(mib_registry_resolve(oid, 11, &r), MIB_OK);
    snmp_varbind_t vb;
    memset(&vb, 0, sizeof(vb));
    vb.value_tag = BER_TAG_INTEGER;
    vb.int_value = 1;
    UM_CHECK_EQ_INT(mib_resolved_set(&r, &vb), MIB_NOT_WRITABLE);
}

int main(void)
{
    UM_RUN(test_resolve_exact_cell_found);
    UM_RUN(test_resolve_exact_cell_missing_row_is_no_such_instance);
    UM_RUN(test_resolve_exact_unknown_column_is_no_such_object);
    UM_RUN(test_resolve_exact_wrong_shape_is_no_such_object);
    UM_RUN(test_resolve_next_from_before_scalar_reaches_scalar);
    UM_RUN(test_resolve_next_from_scalar_enters_table_at_first_cell);
    UM_RUN(test_resolve_next_within_column_walks_rows_ascending);
    UM_RUN(test_resolve_next_skips_sparse_gap);
    UM_RUN(test_resolve_next_crosses_column_boundary);
    UM_RUN(test_resolve_next_falls_out_of_table_into_next_scalar);
    UM_RUN(test_resolve_next_past_everything_is_end_of_view);
    UM_RUN(test_resolve_next_on_exact_match_advances_not_repeats);
    UM_RUN(test_resolve_next_entering_from_bare_column_prefix);
    UM_RUN(test_resolve_next_skips_deactivated_row);
    UM_RUN(test_resolve_exact_deactivated_row_is_no_such_instance);
    UM_RUN(test_resolved_set_writes_through_to_the_table);
    UM_RUN(test_resolve_next_walks_across_two_tables_via_intervening_scalar);
    UM_RUN(test_resolve_exact_disambiguates_between_two_tables_by_prefix);
    UM_RUN(test_resolved_set_on_table_with_no_set_cell_is_not_writable);
    return um_summary();
}
