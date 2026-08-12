#ifndef WESPE_SNMP_PDU_H
#define WESPE_SNMP_PDU_H

#include "ber_types.h"
#include "mib_types.h" /* snmp_varbind_t, mib_result_t */

#ifdef __cplusplus
extern "C" {
#endif

#define SNMP_MAX_VARBINDS      24
#define SNMP_MAX_PRINCIPAL_LEN 32

typedef enum {
    SNMP_VERSION_V1  = 0,
    SNMP_VERSION_V2C = 1,
    SNMP_VERSION_V3  = 3,
} snmp_version_t;

typedef enum {
    SNMP_ACCESS_NONE      = 0,
    SNMP_ACCESS_READ      = 1,
    SNMP_ACCESS_READWRITE = 2,
} snmp_access_mode_t;

/* Version-neutral parsed request/response, produced by a security model's
 * process_incoming() and consumed by the PDU handlers / MIB layer -- see
 * snmp_security.h. Neither of those ever sees a raw community string or
 * (once implemented) raw USM security parameters, only access_mode /
 * principal. This is the SNMPv3-readiness extension point in practice. */
typedef struct {
    snmp_version_t     version;
    uint8_t             pdu_tag; /* SNMP_PDU_* */
    int32_t             request_id;

    /* v1: PDU-level error-status/error-index.
     * v2c GetBulkRequest: reused as non-repeaters/max-repetitions. */
    int32_t             error_status;
    int32_t             error_index;

    snmp_varbind_t       varbinds[SNMP_MAX_VARBINDS];
    size_t               varbind_count;

    snmp_access_mode_t    access_mode;
    char                  principal[SNMP_MAX_PRINCIPAL_LEN]; /* community name for v1/v2c */
} snmp_pdu_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_PDU_H */
