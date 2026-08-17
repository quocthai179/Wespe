/* Standard `interfaces` group (1.3.6.1.2.1.2) subset, plus the matching
 * ifXTable (1.3.6.1.2.1.31.1.1) Counter64 columns -- see mib_iftable.h and
 * docs/PLAN-TABLES.md Phase 13a. This device has exactly one interface
 * worth reporting (the WiFi station), so both tables are permanently
 * single-row: first_index()/next_index() below never report a second row
 * or a disappearing one, unlike mib_sensor_table.c's optional volatile
 * rows.
 *
 * Known, deliberate gap: ifInOctets/ifOutOctets/ifHCInOctets/
 * ifHCOutOctets currently always read 0. The plan's intent was to source
 * them from lwIP's per-netif mib2_counters (LWIP_MIB2_CALLBACKS), but
 * that requires real ESP-IDF hardware bring-up to verify is actually
 * enabled and populated -- not something checkable from this host-only
 * development environment. Reporting a fabricated nonzero number would be
 * worse than reporting a correctly-typed, honestly-zero counter, so this
 * is a documented placeholder, not a bug: see docs/mib-design.md's
 * "Known gaps" section. Every other column here is real device data. */
#include "mib_iftable.h"
#include "mib_tree.h"
#include "mib_types.h"
#include "ber_types.h"
#include "sysinfo.h"
#include <string.h>

#define IF_INDEX_STA 1u /* the one row this device has */

static const uint32_t OID_IF_NUMBER[] = {1, 3, 6, 1, 2, 1, 2, 1, 0};

static mib_result_t get_if_number(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = 1;
    return MIB_OK;
}

static const mib_object_t s_iftable_scalars[] = {
    {OID_IF_NUMBER, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, get_if_number, NULL},
};

/* Both tables below share this row set (the single WiFi STA "interface"),
 * so one pair of index callbacks serves both mib_table_t registrations. */
static mib_result_t if_first_index(uint32_t *out_index)
{
    *out_index = IF_INDEX_STA;
    return MIB_OK;
}
static mib_result_t if_next_index(uint32_t current_index, uint32_t *out_index)
{
    (void)current_index;
    (void)out_index;
    return MIB_END_OF_VIEW; /* exactly one row, always */
}

/* ---------------------------------------------------------------------
 * ifTable (1.3.6.1.2.1.2.2.1) -- ifEntry column numbers are fixed by
 * RFC1213/RFC2863, not something this project assigns.
 * ------------------------------------------------------------------- */

#define IF_COL_INDEX        1u
#define IF_COL_DESCR        2u
#define IF_COL_TYPE         3u
#define IF_COL_MTU          4u
#define IF_COL_SPEED        5u
#define IF_COL_PHYS_ADDRESS 6u
#define IF_COL_ADMIN_STATUS 7u
#define IF_COL_OPER_STATUS  8u
#define IF_COL_LAST_CHANGE  9u
#define IF_COL_IN_OCTETS    10u
#define IF_COL_OUT_OCTETS   16u

static mib_result_t iftable_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    (void)index; /* only ever IF_INDEX_STA -- the table has one row */
    switch (column) {
        case IF_COL_INDEX:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = (int32_t)IF_INDEX_STA;
            return MIB_OK;
        case IF_COL_DESCR: {
            static const char s[] = "wifi0 (ESP32-S3 WiFi Station)";
            vb->value_tag = BER_TAG_OCTET_STRING;
            vb->octets_len = sizeof(s) - 1;
            memcpy(vb->octets, s, vb->octets_len);
            return MIB_OK;
        }
        case IF_COL_TYPE:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = 71; /* ieee80211(71), IANAifType-MIB */
            return MIB_OK;
        case IF_COL_MTU:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = 1500; /* lwIP's default netif MTU on this target */
            return MIB_OK;
        case IF_COL_SPEED:
            vb->value_tag = SNMP_TAG_GAUGE32;
            /* Nominal 802.11n HT20 single-stream (MCS7) capability, not a
             * measured/negotiated rate -- ESP-IDF has no API for the
             * latter. Documented simplification, not fabricated traffic
             * data (see file header). */
            vb->int_value = 72200000;
            return MIB_OK;
        case IF_COL_PHYS_ADDRESS: {
            uint8_t mac[6];
            if (sysinfo_wifi_mac(mac) != 0) {
                return MIB_GEN_ERR;
            }
            vb->value_tag = BER_TAG_OCTET_STRING;
            vb->octets_len = sizeof(mac);
            memcpy(vb->octets, mac, sizeof(mac));
            return MIB_OK;
        }
        case IF_COL_ADMIN_STATUS:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = 1; /* up(1) -- no admin-disable feature exists */
            return MIB_OK;
        case IF_COL_OPER_STATUS: {
            bool up = false;
            (void)sysinfo_wifi_oper_up(&up);
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = up ? 1 : 2; /* up(1) / down(2) */
            return MIB_OK;
        }
        case IF_COL_LAST_CHANGE:
            vb->value_tag = SNMP_TAG_TIMETICKS;
            vb->int_value = (int32_t)sysinfo_wifi_last_change_ticks();
            return MIB_OK;
        case IF_COL_IN_OCTETS:
        case IF_COL_OUT_OCTETS:
            vb->value_tag = SNMP_TAG_COUNTER32;
            vb->int_value = 0; /* known gap -- see file header */
            return MIB_OK;
        default:
            return MIB_GEN_ERR; /* unreachable: registry pre-validates column existence */
    }
}

static const uint32_t IF_TABLE_ENTRY_OID[] = {1, 3, 6, 1, 2, 1, 2, 2, 1};
static const mib_column_t s_iftable_columns[] = {
    {IF_COL_INDEX, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {IF_COL_DESCR, BER_TAG_OCTET_STRING, MIB_ACCESS_RO},
    {IF_COL_TYPE, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {IF_COL_MTU, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {IF_COL_SPEED, SNMP_TAG_GAUGE32, MIB_ACCESS_RO},
    {IF_COL_PHYS_ADDRESS, BER_TAG_OCTET_STRING, MIB_ACCESS_RO},
    {IF_COL_ADMIN_STATUS, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {IF_COL_OPER_STATUS, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {IF_COL_LAST_CHANGE, SNMP_TAG_TIMETICKS, MIB_ACCESS_RO},
    {IF_COL_IN_OCTETS, SNMP_TAG_COUNTER32, MIB_ACCESS_RO},
    {IF_COL_OUT_OCTETS, SNMP_TAG_COUNTER32, MIB_ACCESS_RO},
};
static const mib_table_t s_iftable = {
    .entry_oid = IF_TABLE_ENTRY_OID,
    .entry_oid_len = 9,
    .columns = s_iftable_columns,
    .column_count = sizeof(s_iftable_columns) / sizeof(s_iftable_columns[0]),
    .first_index = if_first_index,
    .next_index = if_next_index,
    .get_cell = iftable_get_cell,
    .set_cell = NULL, /* every column above is read-only */
};

/* ---------------------------------------------------------------------
 * ifXTable (1.3.6.1.2.1.31.1.1.1) -- subset: ifName plus the Counter64
 * high-capacity pair the plan specifically calls out. Column numbers are
 * RFC2863's, same as ifTable above.
 * ------------------------------------------------------------------- */

#define IFX_COL_NAME           1u
#define IFX_COL_HC_IN_OCTETS   6u
#define IFX_COL_HC_OUT_OCTETS 10u

static mib_result_t ifxtable_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    (void)index;
    switch (column) {
        case IFX_COL_NAME: {
            static const char s[] = "wifi0";
            vb->value_tag = BER_TAG_OCTET_STRING;
            vb->octets_len = sizeof(s) - 1;
            memcpy(vb->octets, s, vb->octets_len);
            return MIB_OK;
        }
        case IFX_COL_HC_IN_OCTETS:
        case IFX_COL_HC_OUT_OCTETS:
            /* Widened from the same (currently zero) source as ifTable's
             * 32-bit counters -- known gap, see file header. Still
             * correctly typed as Counter64, exercising the real (not
             * mocked) Phase 12 encode path end to end. */
            vb->value_tag = SNMP_TAG_COUNTER64;
            vb->counter64_value = 0;
            return MIB_OK;
        default:
            return MIB_GEN_ERR;
    }
}

static const uint32_t IFX_TABLE_ENTRY_OID[] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1};
static const mib_column_t s_ifxtable_columns[] = {
    {IFX_COL_NAME, BER_TAG_OCTET_STRING, MIB_ACCESS_RO},
    {IFX_COL_HC_IN_OCTETS, SNMP_TAG_COUNTER64, MIB_ACCESS_RO},
    {IFX_COL_HC_OUT_OCTETS, SNMP_TAG_COUNTER64, MIB_ACCESS_RO},
};
static const mib_table_t s_ifxtable = {
    .entry_oid = IFX_TABLE_ENTRY_OID,
    .entry_oid_len = 10,
    .columns = s_ifxtable_columns,
    .column_count = sizeof(s_ifxtable_columns) / sizeof(s_ifxtable_columns[0]),
    .first_index = if_first_index,
    .next_index = if_next_index,
    .get_cell = ifxtable_get_cell,
    .set_cell = NULL,
};

void mib_iftable_register(void)
{
    mib_registry_register_module(s_iftable_scalars, sizeof(s_iftable_scalars) / sizeof(s_iftable_scalars[0]));
    mib_registry_register_table(&s_iftable);
    mib_registry_register_table(&s_ifxtable);
}
