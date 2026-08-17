#ifndef WESPE_SNMP_PDU_H
#define WESPE_SNMP_PDU_H

#include "ber_types.h"
#include "mib_types.h" /* snmp_varbind_t, mib_result_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Max varbinds in one request/response PDU. Sized for a useful GETBULK
 * slice across a table (a walk of a handful of columns over a modest
 * number of rows) -- raised from an earlier 24 once Phase 10 made
 * snmp_pdu_ctx_t below a `static` (BSS), not a stack-allocated, cost; see
 * the _Static_assert at the bottom of this file for the actual budget
 * enforcement. Bumping this is safe from a stack standpoint but grows
 * static RAM linearly -- re-check that assert if you do. */
#define SNMP_MAX_VARBINDS      50
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

/* Memory-budget regression gate (Phase 10, docs/PLAN-TABLES.md): the
 * agent's single request/response context was found allocated on an
 * 8 KB FreeRTOS task stack while itself measuring >10 KB -- the first
 * real request would have overflowed it. snmp_message.c now holds this
 * in a `static` (BSS) instance instead of on the stack, which is what
 * makes a budget this size safe to carry at all, but BSS on an ESP32-S3
 * is still a finite, shared resource -- this assert exists so that
 * raising SNMP_MAX_VARBINDS, BER_MAX_OID_LEN, or SNMP_MAX_OCTETS_LEN
 * without thinking about the product of all three fails the build
 * instead of silently eating RAM. Adjust the budget deliberately if a
 * real feature needs more; don't just raise it to make this pass. */
#define WESPE_PDU_CTX_BUDGET_BYTES 16384
#ifdef __cplusplus
static_assert(sizeof(snmp_pdu_ctx_t) <= WESPE_PDU_CTX_BUDGET_BYTES,
              "snmp_pdu_ctx_t exceeds its static memory budget -- see WESPE_PDU_CTX_BUDGET_BYTES");
#else
_Static_assert(sizeof(snmp_pdu_ctx_t) <= WESPE_PDU_CTX_BUDGET_BYTES,
               "snmp_pdu_ctx_t exceeds its static memory budget -- see WESPE_PDU_CTX_BUDGET_BYTES");
#endif

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_PDU_H */
