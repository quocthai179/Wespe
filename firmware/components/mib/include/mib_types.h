#ifndef WESPE_MIB_TYPES_H
#define WESPE_MIB_TYPES_H

#include "ber_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SNMP_MAX_OCTETS_LEN 128

/* Version-neutral MIB lookup/apply outcome. snmp_core's snmp_error module
 * translates this into whatever the negotiated SNMP version's wire format
 * wants (v1 PDU-level error-status/error-index vs. v2c per-varbind
 * exception values) -- this enum itself never encodes version-specific
 * behavior. */
typedef enum {
    MIB_OK               = 0,
    MIB_NO_SUCH_OBJECT   = 1,
    MIB_NO_SUCH_INSTANCE = 2,
    MIB_END_OF_VIEW      = 3,
    MIB_WRONG_TYPE       = 4,
    MIB_WRONG_VALUE      = 5,
    MIB_NOT_WRITABLE     = 6,
    MIB_GEN_ERR          = 7,
} mib_result_t;

/* A single varbind's value. Deliberately not a real C union (no tag-vs-
 * storage aliasing surprises, easy to assert against in tests) -- the
 * extra bytes are cheap at this object count. `value_tag` selects which of
 * int_value/octets/oid_value is meaningful. */
typedef struct {
    uint32_t oid[BER_MAX_OID_LEN];
    size_t   oid_len;

    uint8_t  value_tag; /* BER_TAG_*, SNMP_TAG_*, or an exception tag */

    int32_t  int_value;                  /* INTEGER, Counter32/Gauge32/TimeTicks (unsigned reinterpreted) */
    uint8_t  octets[SNMP_MAX_OCTETS_LEN]; /* OCTET STRING content */
    size_t   octets_len;
    uint32_t oid_value[BER_MAX_OID_LEN];  /* OBJECT IDENTIFIER content, e.g. sysObjectID */
    size_t   oid_value_len;
} snmp_varbind_t;

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_TYPES_H */
