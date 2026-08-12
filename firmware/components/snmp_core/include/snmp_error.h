#ifndef WESPE_SNMP_ERROR_H
#define WESPE_SNMP_ERROR_H

#include "snmp_pdu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* v1 PDU-level error-status codes (RFC1157 4.1.2); SetRequest responses
 * under v2c reuse these too (RFC3416 4.2.5 -- SET has no per-varbind
 * exception values in any version). */
typedef enum {
    SNMP_V1_ERR_NO_ERROR     = 0,
    SNMP_V1_ERR_TOO_BIG      = 1,
    SNMP_V1_ERR_NO_SUCH_NAME = 2,
    SNMP_V1_ERR_BAD_VALUE    = 3,
    SNMP_V1_ERR_READ_ONLY    = 4,
    SNMP_V1_ERR_GEN_ERR      = 5,
} snmp_v1_error_status_t;

typedef struct {
    int      pdu_level_abort;   /* nonzero if the whole PDU must abort with a PDU-level error-status */
    int32_t  v1_error_status;   /* meaningful when pdu_level_abort is set */
    uint8_t  v2c_exception_tag; /* meaningful for v2c GET-family lookups; 0 = "no exception, use the real value" */
} snmp_error_translation_t;

/* Translates a version-neutral MIB-layer mib_result_t into the wire
 * representation the negotiated PDU version wants -- see snmp_error.c for
 * the v1-vs-v2c rationale. This is the single place version-specific error
 * semantics live; PDU handlers and the MIB layer never branch on version
 * themselves. */
snmp_error_translation_t snmp_error_translate(snmp_version_t version, mib_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_ERROR_H */
