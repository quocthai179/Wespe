/* wespeSensorTable (1.3.6.1.4.1.99999.2.6) -- custom-MIB conceptual
 * table, see mib_sensor_table.h, mibs/WESPE-MIB.txt, and
 * docs/PLAN-TABLES.md Phase 13b. Rows are sensors 1..sensor_count()
 * (device_hal/sensor.h); unlike mib_iftable.c's permanently single row,
 * this table's row set can genuinely change at runtime -- both for real
 * hardware (a 1-Wire bus could in principle gain/lose devices, though
 * today's driver doesn't detect that) and, deliberately, for
 * sensor_mock.c's opt-in CONFIG_WESPE_SENSOR_VOLATILE_ROWS mode, so this
 * is the table that actually exercises the "rows disappear mid-walk"
 * scenario mib_table.h's contract was designed around.
 *
 * wespeSensorLabel (column 2) and wespeSensorReadCount (column 4) are
 * presentation-layer bookkeeping this module owns directly (not
 * device_hal state) -- same split as mib_ii.c owning sysName/sysContact
 * itself rather than pushing them into a HAL. Labels are not persisted
 * across reboots (matches sysName/sysContact/sysLocation's existing
 * scope -- see docs/architecture.md); a row's label resets to its
 * generated default ("sensor<N>") whenever that row disappears and later
 * reappears, since there is nowhere size-bounded to remember a label for
 * a sensor that (from this table's perspective) no longer exists. */
#include "mib_sensor_table.h"
#include "mib_tree.h"
#include "mib_types.h"
#include "ber_types.h"
#include "sensor.h"
#include <string.h>
#include <stdio.h>

#define WESPE_SENSOR_LABEL_MAX 32

#define COL_INDEX      1u
#define COL_LABEL      2u
#define COL_TEMP       3u
#define COL_READ_COUNT 4u
#define COL_STATUS     5u

static char     s_labels[SENSOR_MAX_COUNT][WESPE_SENSOR_LABEL_MAX];
static uint64_t s_read_count[SENSOR_MAX_COUNT];

static int row_exists(uint32_t index)
{
    return index >= 1 && index <= (uint32_t)sensor_count();
}

static const char *label_for(uint32_t index)
{
    char *slot = s_labels[index - 1];
    if (slot[0] == '\0') {
        snprintf(slot, WESPE_SENSOR_LABEL_MAX, "sensor%u", (unsigned)index);
    }
    return slot;
}

static mib_result_t sensor_first_index(uint32_t *out_index)
{
    if (sensor_count() < 1) {
        return MIB_END_OF_VIEW;
    }
    *out_index = 1;
    return MIB_OK;
}

static mib_result_t sensor_next_index(uint32_t current_index, uint32_t *out_index)
{
    /* Row indices are the dense range [1, sensor_count()] -- no sparse
     * gaps to skip, unlike mib_iftable.c or a hypothetical table keyed
     * by a hardware-assigned ID. current_index+1 either exists right now
     * (per this call's own fresh sensor_count() read) or it doesn't. */
    uint32_t next = current_index + 1;
    if (!row_exists(next)) {
        return MIB_END_OF_VIEW;
    }
    *out_index = next;
    return MIB_OK;
}

static mib_result_t sensor_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    if (!row_exists(index)) {
        /* The row existed when the walk found it but has since vanished
         * (CONFIG_WESPE_SENSOR_VOLATILE_ROWS) -- exactly the race
         * mib_table.h's contract documents as legitimate, not a bug. */
        return MIB_NO_SUCH_INSTANCE;
    }

    switch (column) {
        case COL_INDEX:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = (int32_t)index;
            return MIB_OK;
        case COL_LABEL: {
            const char *label = label_for(index);
            vb->value_tag = BER_TAG_OCTET_STRING;
            vb->octets_len = strlen(label);
            memcpy(vb->octets, label, vb->octets_len);
            return MIB_OK;
        }
        case COL_TEMP: {
            int32_t decidegrees = 0;
            if (sensor_read_decidegrees_indexed(index, &decidegrees) != 0) {
                return MIB_GEN_ERR; /* never fabricate a reading -- same rule as wespeTemperature */
            }
            s_read_count[index - 1]++; /* real count of successful reads served, not fabricated */
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = decidegrees;
            return MIB_OK;
        }
        case COL_READ_COUNT:
            vb->value_tag = SNMP_TAG_COUNTER64;
            vb->counter64_value = s_read_count[index - 1];
            return MIB_OK;
        case COL_STATUS: {
            int32_t decidegrees = 0;
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = (sensor_read_decidegrees_indexed(index, &decidegrees) == 0) ? 1 /* ok */ : 2 /* readError */;
            return MIB_OK;
        }
        default:
            return MIB_GEN_ERR; /* unreachable: registry pre-validates column existence */
    }
}

static mib_result_t sensor_set_cell(uint32_t column, uint32_t index, const snmp_varbind_t *vb)
{
    if (!row_exists(index)) {
        return MIB_NO_SUCH_INSTANCE;
    }
    if (column != COL_LABEL) {
        /* Every other column is RO -- the two-pass SetRequest handler
         * already checks mib_resolved_t.access before ever calling this,
         * so reaching here otherwise shouldn't happen; second layer of
         * defense, same spirit as mib_wespe.c's setters. */
        return MIB_NOT_WRITABLE;
    }
    if (vb->value_tag != BER_TAG_OCTET_STRING) {
        return MIB_WRONG_TYPE;
    }
    if (vb->octets_len >= WESPE_SENSOR_LABEL_MAX) {
        return MIB_WRONG_VALUE;
    }
    memcpy(s_labels[index - 1], vb->octets, vb->octets_len);
    s_labels[index - 1][vb->octets_len] = '\0';
    return MIB_OK;
}

static const uint32_t SENSOR_TABLE_ENTRY_OID[] = {1, 3, 6, 1, 4, 1, 99999, 2, 6, 1};
static const mib_column_t s_sensor_table_columns[] = {
    {COL_INDEX, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {COL_LABEL, BER_TAG_OCTET_STRING, MIB_ACCESS_RW},
    {COL_TEMP, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {COL_READ_COUNT, SNMP_TAG_COUNTER64, MIB_ACCESS_RO},
    {COL_STATUS, BER_TAG_INTEGER, MIB_ACCESS_RO},
};
static const mib_table_t s_sensor_table = {
    .entry_oid = SENSOR_TABLE_ENTRY_OID,
    .entry_oid_len = 10,
    .columns = s_sensor_table_columns,
    .column_count = sizeof(s_sensor_table_columns) / sizeof(s_sensor_table_columns[0]),
    .first_index = sensor_first_index,
    .next_index = sensor_next_index,
    .get_cell = sensor_get_cell,
    .set_cell = sensor_set_cell,
};

void mib_sensor_table_register(void)
{
    memset(s_labels, 0, sizeof(s_labels));
    memset(s_read_count, 0, sizeof(s_read_count));
    mib_registry_register_table(&s_sensor_table);
}
