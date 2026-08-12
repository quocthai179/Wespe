/* Security-model registration table -- the mechanics of the SNMPv3-
 * readiness extension point described in snmp_security.h. Deliberately
 * tiny and version-agnostic: it has no idea community strings or USM
 * exist, it just maps an integer version to a registered vtable. */
#include "snmp_security.h"
#include <string.h>

#define SNMP_SECURITY_MAX_MODELS 4

typedef struct {
    int32_t                     version;
    const snmp_security_model_t *model;
} security_slot_t;

static security_slot_t s_slots[SNMP_SECURITY_MAX_MODELS];
static size_t s_slot_count = 0;

ber_status_t snmp_security_register(int32_t version, const snmp_security_model_t *model)
{
    for (size_t i = 0; i < s_slot_count; i++) {
        if (s_slots[i].version == version) {
            s_slots[i].model = model; /* re-registration overwrites, doesn't grow the table */
            return BER_OK;
        }
    }
    if (s_slot_count >= SNMP_SECURITY_MAX_MODELS) {
        return BER_ERR_OVERFLOW;
    }
    s_slots[s_slot_count].version = version;
    s_slots[s_slot_count].model = model;
    s_slot_count++;
    return BER_OK;
}

const snmp_security_model_t *snmp_security_lookup(int32_t version)
{
    for (size_t i = 0; i < s_slot_count; i++) {
        if (s_slots[i].version == version) {
            return s_slots[i].model;
        }
    }
    return NULL;
}

void snmp_security_reset(void)
{
    s_slot_count = 0;
    memset(s_slots, 0, sizeof(s_slots));
}
