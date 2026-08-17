/* SetRequest handler. Unlike GET/GETNEXT, SET is genuinely all-or-nothing
 * in *every* SNMP version (RFC3416 4.2.5 -- there's no v2c exception-value
 * concept for SET), and is the one place write access control matters. */
#include "snmp_dispatch.h"
#include "snmp_error.h"
#include "mib_tree.h"

ber_status_t snmp_pdu_handle_set(snmp_pdu_ctx_t *ctx)
{
    if (ctx->access_mode != SNMP_ACCESS_READWRITE) {
        /* Not authorized to write. Per SNMP convention this is treated
         * like an unrecognized community -- dropped silently rather than
         * answered with an error, so a probing client can't distinguish
         * "wrong community" from "right community, no write access" by
         * timing/response alone. The caller (snmp_dispatch_pdu ->
         * snmp_message_process) turns any non-BER_OK return into "send no
         * response". */
        return BER_ERR_BAD_ARGS;
    }

    /* Pass 1: validate every varbind (object/cell exists, is writable,
     * and the incoming value's tag matches what it expects) without
     * calling a single setter. This is what makes the eventual commit
     * pass all-or-nothing at the protocol level -- see the pass 2 comment
     * below for the one case (a setter itself failing) this can't cover.
     *
     * Unlike GET's lookup_and_fetch(), no resolved-object cache is kept
     * between pass 1 and pass 2 (via mib_resolved_t, or a table cell's
     * table/column/index) -- mib_registry_resolve() is cheap (small
     * linear scans, no table/registry mutation happens mid-request in
     * this single-threaded agent), so pass 2 just re-resolves each
     * varbind instead of spending SNMP_MAX_VARBINDS * sizeof(mib_resolved_t)
     * of stack keeping the pass-1 results around. */
    for (size_t i = 0; i < ctx->varbind_count; i++) {
        mib_resolved_t resolved;
        mib_result_t res = mib_registry_resolve(ctx->varbinds[i].oid, ctx->varbinds[i].oid_len, &resolved);
        if (res == MIB_OK) {
            if (resolved.access != MIB_ACCESS_RW) {
                res = MIB_NOT_WRITABLE;
            } else if (ctx->varbinds[i].value_tag != resolved.value_tag) {
                res = MIB_WRONG_TYPE;
            }
        }

        if (res != MIB_OK) {
            /* SET always uses v1-style PDU-level error semantics,
             * regardless of the negotiated version -- force that
             * translation rather than snmp_error_translate(ctx->version,
             * ...), which would otherwise hand back v2c exception tags
             * that don't apply here. (MIB_NO_SUCH_INSTANCE, possible now
             * that table cells can be resolved, maps to the same
             * noSuchName as MIB_NO_SUCH_OBJECT in v1 -- see
             * snmp_error.c -- so no special-casing needed here.) */
            snmp_error_translation_t tr = snmp_error_translate(SNMP_VERSION_V1, res);
            ctx->pdu_tag = SNMP_PDU_GET_RESPONSE;
            ctx->error_status = tr.v1_error_status;
            ctx->error_index = (int32_t)(i + 1);
            /* ctx->varbinds are left exactly as received -- RFC1157 4.1.5:
             * an error response echoes the request's VarBindList. */
            return BER_OK;
        }
    }

    /* Pass 2 (commit): every varbind passed validation, so apply them
     * all. A setter can still fail here for a reason validation can't
     * catch (e.g. a GPIO write error) -- that's reported as genErr, but
     * note it is NOT rolled back if an *earlier* varbind's setter already
     * took effect: undoing an arbitrary physical side effect (a relay
     * that already clicked, a table row already renamed) isn't something
     * this layer can promise in general. Documented limitation; see
     * docs/architecture.md. */
    for (size_t i = 0; i < ctx->varbind_count; i++) {
        mib_resolved_t resolved;
        mib_result_t res = mib_registry_resolve(ctx->varbinds[i].oid, ctx->varbinds[i].oid_len, &resolved);
        if (res == MIB_OK) {
            res = mib_resolved_set(&resolved, &ctx->varbinds[i]);
        }
        if (res != MIB_OK) {
            ctx->pdu_tag = SNMP_PDU_GET_RESPONSE;
            ctx->error_status = SNMP_V1_ERR_GEN_ERR;
            ctx->error_index = (int32_t)(i + 1);
            return BER_OK;
        }
    }

    /* Success: RFC1157 4.1.5 -- the response VarBindList equals the
     * request's, which ctx->varbinds already is. */
    ctx->pdu_tag = SNMP_PDU_GET_RESPONSE;
    ctx->error_status = SNMP_V1_ERR_NO_ERROR;
    ctx->error_index = 0;
    return BER_OK;
}
