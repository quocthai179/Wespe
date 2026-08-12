#ifndef WESPE_SNMP_SECURITY_H
#define WESPE_SNMP_SECURITY_H

#include "ber_types.h"
#include "snmp_pdu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The SNMPv3-readiness extension point (docs/v3-readiness.md).
 *
 * snmp_message_parse_header() (snmp_message.c) decodes only the outer
 * SEQUENCE + msgVersion generically -- that's the one field v1/v2c and v3
 * messages are guaranteed to share -- then dispatches to whichever
 * security_model is registered for that version. Everything version-
 * specific about the wire format from that point on (community string vs.
 * msgGlobalData+msgSecurityParameters, USM auth/priv) lives inside the
 * model implementation, never in the PDU handlers or MIB layer: those only
 * ever see the neutral snmp_pdu_ctx_t this interface produces.
 *
 * Adding real SNMPv3/USM later means writing one new implementation of
 * this interface (snmp_security_usm.c, superseding today's
 * snmp_security_usm_stub.c) and registering it for version 3 -- zero
 * changes required in snmp_pdu_get.c / snmp_pdu_set.c / mib_registry.c /
 * etc. */
typedef struct {
    /* Parse everything after the outer SEQUENCE+version that this
     * model defines (community string for v1/v2c; msgGlobalData +
     * msgSecurityParameters for v3), decode the inner PDU, and populate
     * `out_ctx` -- including out_ctx->access_mode, derived from whatever
     * authorization concept this model uses (community string lookup for
     * v1/v2c; USM group/view membership for v3). `depth` is the current
     * BER nesting depth, threaded through so recursion-depth limits stay
     * consistent with the rest of the codec. */
    ber_status_t (*process_incoming)(const uint8_t *msg, size_t len, unsigned depth, snmp_pdu_ctx_t *out_ctx);

    /* Encode a response/trap described by `ctx` back into wire format,
     * including whatever security envelope this model requires. Writes at
     * most `cap` bytes to `out` and reports the actual length in
     * `*out_len`. */
    ber_status_t (*prepare_outgoing)(const snmp_pdu_ctx_t *ctx, uint8_t *out, size_t cap, size_t *out_len);
} snmp_security_model_t;

/* Register the handler for a given msgVersion value (SNMP_VERSION_*).
 * Returns BER_OK, or BER_ERR_OVERFLOW if the registration table is full. */
ber_status_t snmp_security_register(int32_t version, const snmp_security_model_t *model);

/* Look up a previously registered model, or NULL if none is registered for
 * this version -- the dispatcher silently drops the datagram in that case,
 * per SNMP convention for unsupported versions (RFC3411 7.2 step 4: a
 * response would leak which versions/credentials are "closer" to valid). */
const snmp_security_model_t *snmp_security_lookup(int32_t version);

/* Test-only: drop all registered models. */
void snmp_security_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_SECURITY_H */
