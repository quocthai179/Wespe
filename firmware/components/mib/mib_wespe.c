/* Custom WESPE-MIB objects (1.3.6.1.4.1.99999 -- see mibs/WESPE-MIB.txt).
 * This is the seam between protocol code and real hardware: every getter/
 * setter here calls only into hal/ (sensor.h, relay.h, sysinfo.h), never
 * touches a GPIO/1-Wire/ADC register directly, so swapping
 * sensor_ds18b20.c for sensor_mock.c (Kconfig-selected) changes nothing
 * above this file. */
#include "mib_wespe.h"
#include "mib_tree.h"
#include "mib_types.h"
#include "ber_types.h"
#include "sensor.h"
#include "relay.h"
#include "sysinfo.h"

static const uint32_t OID_WESPE_TEMPERATURE[]    = {1, 3, 6, 1, 4, 1, 99999, 2, 1, 0};
static const uint32_t OID_WESPE_RELAY_STATE[]    = {1, 3, 6, 1, 4, 1, 99999, 2, 2, 0};
static const uint32_t OID_WESPE_UPTIME_SECONDS[] = {1, 3, 6, 1, 4, 1, 99999, 2, 3, 0};
static const uint32_t OID_WESPE_FREE_HEAP[]      = {1, 3, 6, 1, 4, 1, 99999, 2, 4, 0};
static const uint32_t OID_WESPE_WIFI_RSSI[]      = {1, 3, 6, 1, 4, 1, 99999, 2, 5, 0};

static mib_result_t get_temperature(snmp_varbind_t *vb)
{
    int32_t decidegrees = 0;
    if (sensor_read_temperature_decidegrees(&decidegrees) != 0) {
        return MIB_GEN_ERR; /* sensor unavailable -- never fabricate a value */
    }
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = decidegrees;
    return MIB_OK;
}

static mib_result_t get_relay_state(snmp_varbind_t *vb)
{
    bool on = false;
    if (relay_get_state(&on) != 0) {
        return MIB_GEN_ERR;
    }
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = on ? 1 : 0;
    return MIB_OK;
}

static mib_result_t set_relay_state(const snmp_varbind_t *vb)
{
    if (vb->value_tag != BER_TAG_INTEGER) {
        return MIB_WRONG_TYPE;
    }
    if (vb->int_value != 0 && vb->int_value != 1) {
        return MIB_WRONG_VALUE; /* only the off(0)/on(1) enum is legal */
    }
    if (relay_set_state(vb->int_value == 1) != 0) {
        return MIB_GEN_ERR;
    }
    return MIB_OK;
}

static mib_result_t get_uptime_seconds(snmp_varbind_t *vb)
{
    vb->value_tag = SNMP_TAG_GAUGE32;
    vb->int_value = (int32_t)(uint32_t)(sysinfo_uptime_ms() / 1000);
    return MIB_OK;
}

static mib_result_t get_free_heap(snmp_varbind_t *vb)
{
    vb->value_tag = SNMP_TAG_GAUGE32;
    vb->int_value = (int32_t)sysinfo_free_heap_bytes();
    return MIB_OK;
}

static mib_result_t get_wifi_rssi(snmp_varbind_t *vb)
{
    int32_t rssi = 0;
    if (sysinfo_wifi_rssi_dbm(&rssi) != 0) {
        return MIB_GEN_ERR;
    }
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = rssi;
    return MIB_OK;
}

static const mib_object_t s_mib_wespe_objects[] = {
    {OID_WESPE_TEMPERATURE, 10, BER_TAG_INTEGER, MIB_ACCESS_RO, get_temperature, NULL},
    {OID_WESPE_RELAY_STATE, 10, BER_TAG_INTEGER, MIB_ACCESS_RW, get_relay_state, set_relay_state},
    {OID_WESPE_UPTIME_SECONDS, 10, SNMP_TAG_GAUGE32, MIB_ACCESS_RO, get_uptime_seconds, NULL},
    {OID_WESPE_FREE_HEAP, 10, SNMP_TAG_GAUGE32, MIB_ACCESS_RO, get_free_heap, NULL},
    {OID_WESPE_WIFI_RSSI, 10, BER_TAG_INTEGER, MIB_ACCESS_RO, get_wifi_rssi, NULL},
};

void mib_wespe_register(void)
{
    mib_registry_register_module(s_mib_wespe_objects, sizeof(s_mib_wespe_objects) / sizeof(s_mib_wespe_objects[0]));
}
