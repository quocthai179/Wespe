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

/* A single varbind's value. `value_tag` selects which member of the
 * union below is meaningful -- exactly one of them ever holds live data
 * for a given varbind, so a real union is a straightforward win here
 * (this used to be four separate fields; that cost ~180 bytes per
 * varbind out of a struct that's repeated SNMP_MAX_VARBINDS times inside
 * snmp_pdu_ctx_t -- see snmp_pdu.h's size budget assertion). The nested
 * struct members are anonymous specifically so call sites are unaffected
 * by this layout change: `vb->octets`, `vb->octets_len`, `vb->oid_value`,
 * etc. still work exactly as before (C11 6.7.2.1p13 hoists anonymous
 * struct/union members into the enclosing struct's namespace). */
typedef struct {
    uint32_t oid[BER_MAX_OID_LEN];
    size_t   oid_len;

    uint8_t  value_tag; /* BER_TAG_*, SNMP_TAG_*, or an exception tag */

    union {
        int32_t  int_value;      /* INTEGER, Counter32/Gauge32/TimeTicks (unsigned reinterpreted) */
        uint64_t counter64_value; /* Counter64 -- see docs/PLAN-TABLES.md Phase 12 */
        struct {
            uint8_t octets[SNMP_MAX_OCTETS_LEN]; /* OCTET STRING content */
            size_t  octets_len;
        };
        struct {
            uint32_t oid_value[BER_MAX_OID_LEN]; /* OBJECT IDENTIFIER content, e.g. sysObjectID */
            size_t   oid_value_len;
        };
    };
} snmp_varbind_t;

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_TYPES_H */
