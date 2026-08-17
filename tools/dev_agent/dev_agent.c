/* Standalone Linux host build of the Wespe SNMP agent core, for local
 * integration testing against real SNMP clients (net-snmp's snmpget/
 * snmpwalk/snmpset/snmpbulkwalk, pysnmp, etc.) without any ESP32
 * hardware. Links the exact same components/ber, components/mib, and
 * components/snmp_core sources the firmware uses -- only the transport
 * (plain POSIX sockets instead of lwIP) and the MIB object bindings
 * (in-memory state instead of hal/ hardware drivers) are host-specific,
 * mirroring what components/transport/snmp_udp.c and
 * components/mib/mib_wespe.c do on real hardware.
 *
 * Built as part of host_tests/ (see host_tests/CMakeLists.txt's
 * `dev_agent` target) but is not itself a test -- it's a long-running
 * server, run manually. See docs/testing.md for example sessions. */
#include "ber_types.h"
#include "mib_tree.h"
#include "mib_types.h"
#include "snmp_message.h"
#include "snmp_security_community.h"
#include "snmp_security_usm_stub.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEV_AGENT_DEFAULT_PORT 1161
#define MAX_PACKET_LEN 1472

static time_t s_boot_time;
static int32_t s_relay_on = 0;
static int32_t s_temperature_decidegrees = 235; /* fixed mock reading, like sensor_mock.c */

static const uint32_t OID_SYS_DESCR[]     = {1, 3, 6, 1, 2, 1, 1, 1, 0};
static const uint32_t OID_SYS_OBJECT_ID[] = {1, 3, 6, 1, 2, 1, 1, 2, 0};
static const uint32_t OID_SYS_UPTIME[]    = {1, 3, 6, 1, 2, 1, 1, 3, 0};
static const uint32_t OID_SYS_NAME[]      = {1, 3, 6, 1, 2, 1, 1, 5, 0};

static const uint32_t OID_WESPE_TEMPERATURE[]    = {1, 3, 6, 1, 4, 1, 99999, 2, 1, 0};
static const uint32_t OID_WESPE_RELAY_STATE[]    = {1, 3, 6, 1, 4, 1, 99999, 2, 2, 0};
static const uint32_t OID_WESPE_UPTIME_SECONDS[] = {1, 3, 6, 1, 4, 1, 99999, 2, 3, 0};

static mib_result_t get_sys_descr(snmp_varbind_t *vb)
{
    static const char s[] = "Wespe dev-agent (host build -- not real ESP32-S3 hardware)";
    vb->value_tag = BER_TAG_OCTET_STRING;
    vb->octets_len = sizeof(s) - 1;
    memcpy(vb->octets, s, vb->octets_len);
    return MIB_OK;
}

static mib_result_t get_sys_object_id(snmp_varbind_t *vb)
{
    static const uint32_t oid[] = {1, 3, 6, 1, 4, 1, 99999, 1, 1};
    vb->value_tag = BER_TAG_OID;
    vb->oid_value_len = sizeof(oid) / sizeof(oid[0]);
    memcpy(vb->oid_value, oid, sizeof(oid));
    return MIB_OK;
}

static mib_result_t get_sys_uptime(snmp_varbind_t *vb)
{
    vb->value_tag = SNMP_TAG_TIMETICKS;
    vb->int_value = (int32_t)((time(NULL) - s_boot_time) * 100);
    return MIB_OK;
}

static mib_result_t get_sys_name(snmp_varbind_t *vb)
{
    static const char s[] = "wespe-dev-agent";
    vb->value_tag = BER_TAG_OCTET_STRING;
    vb->octets_len = sizeof(s) - 1;
    memcpy(vb->octets, s, vb->octets_len);
    return MIB_OK;
}

static mib_result_t get_temperature(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = s_temperature_decidegrees;
    return MIB_OK;
}

static mib_result_t get_relay_state(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = s_relay_on;
    return MIB_OK;
}

static mib_result_t set_relay_state(const snmp_varbind_t *vb)
{
    if (vb->value_tag != BER_TAG_INTEGER) {
        return MIB_WRONG_TYPE;
    }
    if (vb->int_value != 0 && vb->int_value != 1) {
        return MIB_WRONG_VALUE;
    }
    s_relay_on = vb->int_value;
    fprintf(stderr, "[dev_agent] relay -> %s\n", s_relay_on ? "ON" : "OFF");
    return MIB_OK;
}

static mib_result_t get_wespe_uptime(snmp_varbind_t *vb)
{
    vb->value_tag = SNMP_TAG_GAUGE32;
    vb->int_value = (int32_t)(time(NULL) - s_boot_time);
    return MIB_OK;
}

static const mib_object_t s_mib_ii[] = {
    {OID_SYS_DESCR, 9, BER_TAG_OCTET_STRING, MIB_ACCESS_RO, get_sys_descr, NULL},
    {OID_SYS_OBJECT_ID, 9, BER_TAG_OID, MIB_ACCESS_RO, get_sys_object_id, NULL},
    {OID_SYS_UPTIME, 9, SNMP_TAG_TIMETICKS, MIB_ACCESS_RO, get_sys_uptime, NULL},
    {OID_SYS_NAME, 9, BER_TAG_OCTET_STRING, MIB_ACCESS_RO, get_sys_name, NULL},
};

static const mib_object_t s_mib_wespe[] = {
    {OID_WESPE_TEMPERATURE, 10, BER_TAG_INTEGER, MIB_ACCESS_RO, get_temperature, NULL},
    {OID_WESPE_RELAY_STATE, 10, BER_TAG_INTEGER, MIB_ACCESS_RW, get_relay_state, set_relay_state},
    {OID_WESPE_UPTIME_SECONDS, 10, SNMP_TAG_GAUGE32, MIB_ACCESS_RO, get_wespe_uptime, NULL},
};

/* ---------------------------------------------------------------------
 * ifTable / ifXTable mock (docs/PLAN-TABLES.md Phase 13a). Real firmware
 * (components/mib/mib_iftable.c) has exactly one row -- the WiFi station
 * -- and honestly reports 0 for the traffic counters pending real
 * hardware verification of lwIP's mib2 stats (see that file's header
 * comment). This mock is different on purpose: it's the whole point of
 * dev_agent.c to let real net-snmp tools exercise the table-walk/GETBULK/
 * Counter64 machinery against something with more than one row and
 * nonzero counters, no ESP32 required. Same standard OIDs and column
 * numbers as production, so `snmpwalk -m ALL` still renders it correctly.
 * ------------------------------------------------------------------- */

#define IF_COL_INDEX          1u
#define IF_COL_DESCR          2u
#define IF_COL_TYPE           3u
#define IF_COL_MTU             4u
#define IF_COL_SPEED           5u
#define IF_COL_PHYS_ADDRESS    6u
#define IF_COL_ADMIN_STATUS    7u
#define IF_COL_OPER_STATUS     8u
#define IF_COL_LAST_CHANGE     9u
#define IF_COL_IN_OCTETS      10u
#define IF_COL_OUT_OCTETS     16u
#define IFX_COL_NAME           1u
#define IFX_COL_HC_IN_OCTETS   6u
#define IFX_COL_HC_OUT_OCTETS 10u

typedef struct {
    uint32_t    index;
    const char *descr;
    const char *name;
    int32_t     if_type;
    uint8_t     mac[6];
    uint32_t    in_octets;
    uint32_t    out_octets;
} mock_if_row_t;

/* wlan0's counters climb on every poll (floor(uptime) scaled) so a script
 * doing two GETs a few seconds apart -- e.g. Phase 14's demo.sh -- can
 * show a Counter64 actually incrementing, the way a real interface would.
 * lo0 stays fixed, as a loopback's counters realistically would between
 * two SNMP polls a few seconds apart. */
static mock_if_row_t s_if_rows[] = {
    {1, "wlan0", "wlan0", 71 /* ieee80211 */, {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}, 0, 0},
    {2, "lo0", "lo0", 24 /* softwareLoopback */, {0, 0, 0, 0, 0, 0}, 100, 100},
};
#define IF_ROW_COUNT (sizeof(s_if_rows) / sizeof(s_if_rows[0]))

static mib_result_t get_if_number(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = (int32_t)IF_ROW_COUNT;
    return MIB_OK;
}
static const uint32_t OID_IF_NUMBER[] = {1, 3, 6, 1, 2, 1, 2, 1, 0};
static const mib_object_t s_mib_iftable_scalars[] = {
    {OID_IF_NUMBER, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, get_if_number, NULL},
};

static mock_if_row_t *find_if_row(uint32_t index)
{
    for (size_t i = 0; i < IF_ROW_COUNT; i++) {
        if (s_if_rows[i].index == index) {
            return &s_if_rows[i];
        }
    }
    return NULL;
}
static mib_result_t if_first_index(uint32_t *out_index)
{
    *out_index = s_if_rows[0].index;
    return MIB_OK;
}
static mib_result_t if_next_index(uint32_t current_index, uint32_t *out_index)
{
    for (size_t i = 0; i < IF_ROW_COUNT; i++) {
        if (s_if_rows[i].index > current_index) {
            *out_index = s_if_rows[i].index;
            return MIB_OK;
        }
    }
    return MIB_END_OF_VIEW;
}

/* wlan0's counters climb with uptime; see s_if_rows' comment. Called from
 * both iftable_get_cell() and ifxtable_get_cell() -- ifHCInOctets/
 * ifHCOutOctets read the same row->in_octets/out_octets fields ifTable's
 * plain counters do (just widened), so both tables need this refreshed
 * before reading them, not just whichever one happens to be walked
 * first. */
static void refresh_climbing_counters(mock_if_row_t *row)
{
    if (row->index != 1) {
        return;
    }
    uint32_t t = (uint32_t)(time(NULL) - s_boot_time);
    row->in_octets = t * 1500u + 2000u;
    row->out_octets = t * 900u + 500u;
}

static mib_result_t iftable_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    mock_if_row_t *row = find_if_row(index);
    if (row == NULL) {
        return MIB_NO_SUCH_INSTANCE;
    }
    refresh_climbing_counters(row);
    switch (column) {
        case IF_COL_INDEX:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = (int32_t)row->index;
            return MIB_OK;
        case IF_COL_DESCR:
            vb->value_tag = BER_TAG_OCTET_STRING;
            vb->octets_len = strlen(row->descr);
            memcpy(vb->octets, row->descr, vb->octets_len);
            return MIB_OK;
        case IF_COL_TYPE:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = row->if_type;
            return MIB_OK;
        case IF_COL_MTU:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = (row->index == 2) ? 65536 : 1500;
            return MIB_OK;
        case IF_COL_SPEED:
            vb->value_tag = SNMP_TAG_GAUGE32;
            vb->int_value = (row->index == 2) ? 10000000 : 72200000;
            return MIB_OK;
        case IF_COL_PHYS_ADDRESS:
            vb->value_tag = BER_TAG_OCTET_STRING;
            vb->octets_len = sizeof(row->mac);
            memcpy(vb->octets, row->mac, sizeof(row->mac));
            return MIB_OK;
        case IF_COL_ADMIN_STATUS:
        case IF_COL_OPER_STATUS:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = 1; /* up(1) -- both mock rows are always up */
            return MIB_OK;
        case IF_COL_LAST_CHANGE:
            vb->value_tag = SNMP_TAG_TIMETICKS;
            vb->int_value = 0; /* no transition since this mock started */
            return MIB_OK;
        case IF_COL_IN_OCTETS:
            vb->value_tag = SNMP_TAG_COUNTER32;
            vb->int_value = (int32_t)row->in_octets;
            return MIB_OK;
        case IF_COL_OUT_OCTETS:
            vb->value_tag = SNMP_TAG_COUNTER32;
            vb->int_value = (int32_t)row->out_octets;
            return MIB_OK;
        default:
            return MIB_GEN_ERR;
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
    .set_cell = NULL,
};

static mib_result_t ifxtable_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    mock_if_row_t *row = find_if_row(index);
    if (row == NULL) {
        return MIB_NO_SUCH_INSTANCE;
    }
    refresh_climbing_counters(row);
    switch (column) {
        case IFX_COL_NAME:
            vb->value_tag = BER_TAG_OCTET_STRING;
            vb->octets_len = strlen(row->name);
            memcpy(vb->octets, row->name, vb->octets_len);
            return MIB_OK;
        case IFX_COL_HC_IN_OCTETS:
            vb->value_tag = SNMP_TAG_COUNTER64;
            vb->counter64_value = row->in_octets; /* widened from the 32-bit source, same as production */
            return MIB_OK;
        case IFX_COL_HC_OUT_OCTETS:
            vb->value_tag = SNMP_TAG_COUNTER64;
            vb->counter64_value = row->out_octets;
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

/* ---------------------------------------------------------------------
 * wespeSensorTable mock (docs/PLAN-TABLES.md Phase 13b). Up to 2 rows so
 * a real multi-row walk/GETBULK/SET-through-a-cell has something to
 * exercise; wespeSensorLabel is genuinely mutable via SET here, same as
 * production. The row *count* cycles 1 <-> 2 on a fixed short clock
 * (wsensor_row_count() below) unconditionally -- unlike production's
 * opt-in CONFIG_WESPE_SENSOR_VOLATILE_ROWS (off by default, since real
 * hardware shouldn't lie about its sensor count by default), dev_agent's
 * whole purpose is giving tools something real to poke at, and "a row
 * disappearing mid-walk" is exactly the scenario tools/demo.sh exists to
 * show off without any ESP32 hardware.
 * ------------------------------------------------------------------- */

#define WSENSOR_COL_INDEX      1u
#define WSENSOR_COL_LABEL      2u
#define WSENSOR_COL_TEMP       3u
#define WSENSOR_COL_READ_COUNT 4u
#define WSENSOR_COL_STATUS     5u
#define WSENSOR_LABEL_MAX      32
#define WSENSOR_ROW_COUNT      2 /* max rows this mock ever has -- see wsensor_row_count() for the live count */

static int wsensor_row_count(void)
{
    /* 1 row for the first 4s of every 8s window, 2 for the second half --
     * short enough that a demo script doesn't need to wait long to
     * observe both states. */
    long t = (long)(time(NULL) - s_boot_time);
    return ((t / 4) % 2 == 0) ? 1 : 2;
}

typedef struct {
    uint32_t index;
    char     label[WSENSOR_LABEL_MAX];
    int32_t  decidegrees;
    uint64_t read_count;
} mock_sensor_row_t;

static mock_sensor_row_t s_sensor_rows[WSENSOR_ROW_COUNT] = {
    {1, "sensor1", 235, 0},
    {2, "sensor2", 198, 0},
};

static mock_sensor_row_t *find_sensor_row(uint32_t index)
{
    if (index < 1 || index > (uint32_t)wsensor_row_count()) {
        return NULL; /* row not present right now -- see wsensor_row_count() */
    }
    for (int i = 0; i < WSENSOR_ROW_COUNT; i++) {
        if (s_sensor_rows[i].index == index) {
            return &s_sensor_rows[i];
        }
    }
    return NULL;
}
static mib_result_t wsensor_first_index(uint32_t *out_index)
{
    *out_index = 1; /* wsensor_row_count() is always >= 1 */
    return MIB_OK;
}
static mib_result_t wsensor_next_index(uint32_t current_index, uint32_t *out_index)
{
    if (current_index < (uint32_t)wsensor_row_count()) {
        *out_index = current_index + 1;
        return MIB_OK;
    }
    return MIB_END_OF_VIEW;
}
static mib_result_t wsensor_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    mock_sensor_row_t *row = find_sensor_row(index);
    if (row == NULL) {
        return MIB_NO_SUCH_INSTANCE;
    }
    switch (column) {
        case WSENSOR_COL_INDEX:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = (int32_t)row->index;
            return MIB_OK;
        case WSENSOR_COL_LABEL:
            vb->value_tag = BER_TAG_OCTET_STRING;
            vb->octets_len = strlen(row->label);
            memcpy(vb->octets, row->label, vb->octets_len);
            return MIB_OK;
        case WSENSOR_COL_TEMP:
            row->read_count++;
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = row->decidegrees;
            return MIB_OK;
        case WSENSOR_COL_READ_COUNT:
            vb->value_tag = SNMP_TAG_COUNTER64;
            vb->counter64_value = row->read_count;
            return MIB_OK;
        case WSENSOR_COL_STATUS:
            vb->value_tag = BER_TAG_INTEGER;
            vb->int_value = 1; /* ok */
            return MIB_OK;
        default:
            return MIB_GEN_ERR;
    }
}
static mib_result_t wsensor_set_cell(uint32_t column, uint32_t index, const snmp_varbind_t *vb)
{
    mock_sensor_row_t *row = find_sensor_row(index);
    if (row == NULL) {
        return MIB_NO_SUCH_INSTANCE;
    }
    if (column != WSENSOR_COL_LABEL) {
        return MIB_NOT_WRITABLE;
    }
    if (vb->value_tag != BER_TAG_OCTET_STRING || vb->octets_len >= WSENSOR_LABEL_MAX) {
        return MIB_WRONG_VALUE;
    }
    memcpy(row->label, vb->octets, vb->octets_len);
    row->label[vb->octets_len] = '\0';
    return MIB_OK;
}

static const uint32_t WSENSOR_TABLE_ENTRY_OID[] = {1, 3, 6, 1, 4, 1, 99999, 2, 6, 1};
static const mib_column_t s_wsensor_columns[] = {
    {WSENSOR_COL_INDEX, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {WSENSOR_COL_LABEL, BER_TAG_OCTET_STRING, MIB_ACCESS_RW},
    {WSENSOR_COL_TEMP, BER_TAG_INTEGER, MIB_ACCESS_RO},
    {WSENSOR_COL_READ_COUNT, SNMP_TAG_COUNTER64, MIB_ACCESS_RO},
    {WSENSOR_COL_STATUS, BER_TAG_INTEGER, MIB_ACCESS_RO},
};
static const mib_table_t s_wsensor_table = {
    .entry_oid = WSENSOR_TABLE_ENTRY_OID,
    .entry_oid_len = 10,
    .columns = s_wsensor_columns,
    .column_count = sizeof(s_wsensor_columns) / sizeof(s_wsensor_columns[0]),
    .first_index = wsensor_first_index,
    .next_index = wsensor_next_index,
    .get_cell = wsensor_get_cell,
    .set_cell = wsensor_set_cell,
};

int main(int argc, char **argv)
{
    int port = DEV_AGENT_DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    s_boot_time = time(NULL);

    mib_registry_register_module(s_mib_ii, sizeof(s_mib_ii) / sizeof(s_mib_ii[0]));
    mib_registry_register_module(s_mib_wespe, sizeof(s_mib_wespe) / sizeof(s_mib_wespe[0]));
    mib_registry_register_module(s_mib_iftable_scalars, sizeof(s_mib_iftable_scalars) / sizeof(s_mib_iftable_scalars[0]));
    mib_registry_register_table(&s_iftable);
    mib_registry_register_table(&s_ifxtable);
    mib_registry_register_table(&s_wsensor_table);
    snmp_security_community_init("public", "private");
    snmp_security_usm_stub_init();

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }

    fprintf(stderr, "[dev_agent] listening on 127.0.0.1:%d (RO community 'public', RW community 'private')\n", port);
    fflush(stderr);

    uint8_t in_buf[MAX_PACKET_LEN];
    uint8_t out_buf[MAX_PACKET_LEN];
    for (;;) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(sock, in_buf, sizeof(in_buf), 0, (struct sockaddr *)&from, &from_len);
        if (n <= 0) {
            continue;
        }
        size_t out_len = snmp_message_process(in_buf, (size_t)n, out_buf, sizeof(out_buf));
        if (out_len == 0) {
            continue;
        }
        sendto(sock, out_buf, out_len, 0, (struct sockaddr *)&from, from_len);
    }
}
