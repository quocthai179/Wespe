/* MIB object registry: a small fixed set of build-time-sorted `const`
 * arrays (one per registered scalar module), searched with binary
 * search, plus (Phase 11, docs/PLAN-TABLES.md) a small fixed set of
 * registered conceptual tables, searched by column-major row iteration.
 * See mib_tree.h for why a flat sorted array beats a pointer-based tree
 * for scalars at this scale (~15-25 objects). No ESP-IDF dependency --
 * host-testable, see host_tests/test_mib_registry.c and
 * host_tests/test_mib_table.c. */
#include "mib_tree.h"
#include <string.h>

#define MIB_MAX_MODULES 4
#define MIB_MAX_TABLES  4

typedef struct {
    const mib_object_t *objects;
    size_t               count;
} mib_module_t;

static mib_module_t s_modules[MIB_MAX_MODULES];
static size_t s_module_count = 0;

static const mib_table_t *s_tables[MIB_MAX_TABLES];
static size_t s_table_count = 0;

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

int mib_registry_register_table(const mib_table_t *table)
{
    if (s_table_count >= MIB_MAX_TABLES) {
        return -1;
    }
    s_tables[s_table_count++] = table;
    return 0;
}

void mib_registry_reset(void)
{
    s_module_count = 0;
    memset(s_modules, 0, sizeof(s_modules));
    s_table_count = 0;
    memset(s_tables, 0, sizeof(s_tables));
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

/* ---------------------------------------------------------------------
 * Table support (Phase 11)
 * ------------------------------------------------------------------- */

static void populate_scalar(mib_resolved_t *out, const mib_object_t *obj)
{
    memcpy(out->oid, obj->oid, (size_t)obj->oid_len * sizeof(uint32_t));
    out->oid_len = obj->oid_len;
    out->value_tag = obj->value_tag;
    out->access = obj->access;
    out->kind = MIB_RESOLVED_SCALAR;
    out->scalar = obj;
}

static void populate_cell(mib_resolved_t *out, const mib_table_t *t, const mib_column_t *col, uint32_t index)
{
    memcpy(out->oid, t->entry_oid, (size_t)t->entry_oid_len * sizeof(uint32_t));
    out->oid[t->entry_oid_len] = col->number;
    out->oid[t->entry_oid_len + 1] = index;
    out->oid_len = (uint8_t)(t->entry_oid_len + 2);
    out->value_tag = col->value_tag;
    out->access = col->access;
    out->kind = MIB_RESOLVED_CELL;
    out->cell.table = t;
    out->cell.column = col->number;
    out->cell.index = index;
}

/* Exact-match within one table: is `oid` shaped like {entry_oid}.{a
 * defined column}.{an existing row}? See mib_tree.h's
 * mib_registry_resolve() doc comment for the NO_SUCH_OBJECT vs.
 * NO_SUCH_INSTANCE distinction this makes. */
static mib_result_t table_find_exact(const mib_table_t *t, const uint32_t *oid, size_t oid_len, mib_resolved_t *out)
{
    if (oid_len != (size_t)t->entry_oid_len + 2) {
        return MIB_NO_SUCH_OBJECT; /* not cell-shaped at all */
    }
    if (mib_oid_compare(oid, t->entry_oid_len, t->entry_oid, t->entry_oid_len) != 0) {
        return MIB_NO_SUCH_OBJECT; /* doesn't even share this table's entry prefix */
    }

    uint32_t col_num = oid[t->entry_oid_len];
    uint32_t idx = oid[t->entry_oid_len + 1];

    const mib_column_t *col = NULL;
    for (size_t i = 0; i < t->column_count; i++) {
        if (t->columns[i].number == col_num) {
            col = &t->columns[i];
            break;
        }
    }
    if (col == NULL) {
        return MIB_NO_SUCH_OBJECT; /* right table, but no such column */
    }

    uint32_t cur;
    mib_result_t r = t->first_index(&cur);
    int exists = 0;
    while (r == MIB_OK) {
        if (cur == idx) {
            exists = 1;
            break;
        }
        if (cur > idx) {
            break; /* indices are strictly ascending -- passed it, so it doesn't exist */
        }
        r = t->next_index(cur, &cur);
    }
    if (!exists) {
        return MIB_NO_SUCH_INSTANCE; /* right column, this row just isn't there (right now) */
    }

    populate_cell(out, t, col, idx);
    return MIB_OK;
}

/* Lower-bound within one table: the smallest cell OID strictly greater
 * than `oid`, or MIB_END_OF_VIEW if none.
 *
 * `columns` is required to be sorted ascending by number (mib_table.h),
 * which is what makes the loop below correct: for column C, iterating
 * its rows in ascending index order and returning the first cell that
 * exceeds `oid` gives the smallest surviving candidate *in that column*;
 * because the column arc sorts before the index arc in every cell's OID,
 * that candidate is guaranteed smaller than *every* cell in any later
 * column, regardless of row index. So the first column (processed in
 * ascending order) that yields any candidate at all has already found
 * the global smallest one -- no need to keep scanning or to compare
 * across columns. This also transparently handles every entry point: a
 * bare prefix of `entry_oid` (nothing in any column is excluded, so the
 * very first row of the very first column wins), sparse/disappeared
 * indices (first_index()/next_index() simply never produce them), and
 * falling out the far end of the last column (the loop finds nothing in
 * any column and returns MIB_END_OF_VIEW). */
static mib_result_t table_find_next(const mib_table_t *t, const uint32_t *oid, size_t oid_len, mib_resolved_t *out)
{
    for (size_t ci = 0; ci < t->column_count; ci++) {
        const mib_column_t *col = &t->columns[ci];
        uint32_t idx;
        mib_result_t r = t->first_index(&idx);
        while (r == MIB_OK) {
            uint32_t cand[BER_MAX_OID_LEN];
            memcpy(cand, t->entry_oid, (size_t)t->entry_oid_len * sizeof(uint32_t));
            size_t cand_len = t->entry_oid_len;
            cand[cand_len++] = col->number;
            cand[cand_len++] = idx;
            if (mib_oid_compare(cand, cand_len, oid, oid_len) > 0) {
                populate_cell(out, t, col, idx);
                return MIB_OK;
            }
            r = t->next_index(idx, &idx);
        }
    }
    return MIB_END_OF_VIEW;
}

mib_result_t mib_registry_resolve(const uint32_t *oid, size_t oid_len, mib_resolved_t *out)
{
    const mib_object_t *scalar = mib_registry_find(oid, oid_len);
    if (scalar != NULL) {
        populate_scalar(out, scalar);
        return MIB_OK;
    }

    for (size_t i = 0; i < s_table_count; i++) {
        mib_result_t r = table_find_exact(s_tables[i], oid, oid_len, out);
        if (r == MIB_OK || r == MIB_NO_SUCH_INSTANCE) {
            /* Either a real match, or a definitive "this table owns that
             * shape of OID but the row's gone" -- either way, no other
             * module/table needs to be consulted. */
            return r;
        }
    }
    return MIB_NO_SUCH_OBJECT;
}

mib_result_t mib_registry_resolve_next(const uint32_t *oid, size_t oid_len, mib_resolved_t *out)
{
    mib_resolved_t best;
    int have_best = 0;

    const mib_object_t *scalar = mib_registry_find_next(oid, oid_len);
    if (scalar != NULL) {
        populate_scalar(&best, scalar);
        have_best = 1;
    }

    for (size_t i = 0; i < s_table_count; i++) {
        mib_resolved_t cand;
        mib_result_t r = table_find_next(s_tables[i], oid, oid_len, &cand);
        if (r == MIB_OK && (!have_best || mib_oid_compare(cand.oid, cand.oid_len, best.oid, best.oid_len) < 0)) {
            best = cand;
            have_best = 1;
        }
    }

    if (!have_best) {
        return MIB_END_OF_VIEW;
    }
    *out = best;
    return MIB_OK;
}

mib_result_t mib_resolved_get(const mib_resolved_t *r, snmp_varbind_t *vb)
{
    if (r->kind == MIB_RESOLVED_SCALAR) {
        return r->scalar->getter(vb);
    }
    return r->cell.table->get_cell(r->cell.column, r->cell.index, vb);
}

mib_result_t mib_resolved_set(const mib_resolved_t *r, const snmp_varbind_t *vb)
{
    if (r->kind == MIB_RESOLVED_SCALAR) {
        if (r->scalar->setter == NULL) {
            return MIB_NOT_WRITABLE;
        }
        return r->scalar->setter(vb);
    }
    if (r->cell.table->set_cell == NULL) {
        return MIB_NOT_WRITABLE;
    }
    return r->cell.table->set_cell(r->cell.column, r->cell.index, vb);
}
