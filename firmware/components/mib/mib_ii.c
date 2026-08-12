/* Standard MIB-II `system` group (1.3.6.1.2.1.1). Any generic SNMP tool
 * (snmpwalk, an NMS auto-discovery pass) looks here first, so implementing
 * it is what makes Wespe read as a real network device rather than just a
 * pile of custom OIDs. */
#include "mib_ii.h"
#include "mib_tree.h"
#include "mib_types.h"
#include "ber_types.h"
#include "sysinfo.h"
#include <string.h>

#define WESPE_STR_MAX 64

static const uint32_t OID_SYS_DESCR[]     = {1, 3, 6, 1, 2, 1, 1, 1, 0};
static const uint32_t OID_SYS_OBJECT_ID[] = {1, 3, 6, 1, 2, 1, 1, 2, 0};
static const uint32_t OID_SYS_UPTIME[]    = {1, 3, 6, 1, 2, 1, 1, 3, 0};
static const uint32_t OID_SYS_CONTACT[]   = {1, 3, 6, 1, 2, 1, 1, 4, 0};
static const uint32_t OID_SYS_NAME[]      = {1, 3, 6, 1, 2, 1, 1, 5, 0};
static const uint32_t OID_SYS_LOCATION[]  = {1, 3, 6, 1, 2, 1, 1, 6, 0};
static const uint32_t OID_SYS_SERVICES[]  = {1, 3, 6, 1, 2, 1, 1, 7, 0};

/* wespeAgent = wespeMIB.1 = 1.3.6.1.4.1.99999.1; sysObjectID points at
 * .1.1 as this agent's product identity within that subtree. See
 * mibs/WESPE-MIB.txt. */
static const uint32_t WESPE_SYS_OBJECT_ID[] = {1, 3, 6, 1, 4, 1, 99999, 1, 1};

static char s_sys_contact[WESPE_STR_MAX]  = "";
static char s_sys_name[WESPE_STR_MAX]     = "wespe-esp32s3";
static char s_sys_location[WESPE_STR_MAX] = "";

static mib_result_t set_string_field(char *field, size_t field_cap, const snmp_varbind_t *vb)
{
    if (vb->value_tag != BER_TAG_OCTET_STRING) {
        return MIB_WRONG_TYPE;
    }
    if (vb->octets_len >= field_cap) {
        return MIB_WRONG_VALUE;
    }
    memcpy(field, vb->octets, vb->octets_len);
    field[vb->octets_len] = '\0';
    return MIB_OK;
}

static mib_result_t get_sys_descr(snmp_varbind_t *vb)
{
    static const char descr[] = "Wespe ESP32-S3 SNMP Agent";
    vb->value_tag = BER_TAG_OCTET_STRING;
    vb->octets_len = sizeof(descr) - 1;
    memcpy(vb->octets, descr, vb->octets_len);
    return MIB_OK;
}

static mib_result_t get_sys_object_id(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_OID;
    vb->oid_value_len = sizeof(WESPE_SYS_OBJECT_ID) / sizeof(WESPE_SYS_OBJECT_ID[0]);
    memcpy(vb->oid_value, WESPE_SYS_OBJECT_ID, sizeof(WESPE_SYS_OBJECT_ID));
    return MIB_OK;
}

static mib_result_t get_sys_uptime(snmp_varbind_t *vb)
{
    /* TimeTicks = hundredths of a second since (re)boot (RFC1155 3.2.3.6). */
    uint64_t hundredths = sysinfo_uptime_ms() / 10;
    vb->value_tag = SNMP_TAG_TIMETICKS;
    vb->int_value = (int32_t)(uint32_t)hundredths; /* wraps like any TimeTicks counter */
    return MIB_OK;
}

static mib_result_t get_sys_contact(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_OCTET_STRING;
    vb->octets_len = strlen(s_sys_contact);
    memcpy(vb->octets, s_sys_contact, vb->octets_len);
    return MIB_OK;
}

static mib_result_t set_sys_contact(const snmp_varbind_t *vb)
{
    return set_string_field(s_sys_contact, sizeof(s_sys_contact), vb);
}

static mib_result_t get_sys_name(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_OCTET_STRING;
    vb->octets_len = strlen(s_sys_name);
    memcpy(vb->octets, s_sys_name, vb->octets_len);
    return MIB_OK;
}

static mib_result_t set_sys_name(const snmp_varbind_t *vb)
{
    return set_string_field(s_sys_name, sizeof(s_sys_name), vb);
}

static mib_result_t get_sys_location(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_OCTET_STRING;
    vb->octets_len = strlen(s_sys_location);
    memcpy(vb->octets, s_sys_location, vb->octets_len);
    return MIB_OK;
}

static mib_result_t set_sys_location(const snmp_varbind_t *vb)
{
    return set_string_field(s_sys_location, sizeof(s_sys_location), vb);
}

static mib_result_t get_sys_services(snmp_varbind_t *vb)
{
    /* 64 = layer 7 (applications), a static nominal value -- this device
     * doesn't implement OSI-layer forwarding semantics. */
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = 64;
    return MIB_OK;
}

static const mib_object_t s_mib_ii_objects[] = {
    {OID_SYS_DESCR, 9, BER_TAG_OCTET_STRING, MIB_ACCESS_RO, get_sys_descr, NULL},
    {OID_SYS_OBJECT_ID, 9, BER_TAG_OID, MIB_ACCESS_RO, get_sys_object_id, NULL},
    {OID_SYS_UPTIME, 9, SNMP_TAG_TIMETICKS, MIB_ACCESS_RO, get_sys_uptime, NULL},
    {OID_SYS_CONTACT, 9, BER_TAG_OCTET_STRING, MIB_ACCESS_RW, get_sys_contact, set_sys_contact},
    {OID_SYS_NAME, 9, BER_TAG_OCTET_STRING, MIB_ACCESS_RW, get_sys_name, set_sys_name},
    {OID_SYS_LOCATION, 9, BER_TAG_OCTET_STRING, MIB_ACCESS_RW, get_sys_location, set_sys_location},
    {OID_SYS_SERVICES, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, get_sys_services, NULL},
};

void mib_ii_register(void)
{
    mib_registry_register_module(s_mib_ii_objects, sizeof(s_mib_ii_objects) / sizeof(s_mib_ii_objects[0]));
}
