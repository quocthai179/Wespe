/* GetRequest and GetNextRequest handlers. Both are "read the object at (or
 * lexicographically after) this OID" -- they share every bit of control
 * flow except which mib_registry_* lookup function is used and whether the
 * response varbind's OID equals the request's (Get) or the found object's
 * (GetNext, which is how a manager walks the whole MIB). */
#include "snmp_dispatch.h"
#include "snmp_codec.h"
#include "snmp_error.h"
#include "mib_tree.h"
#include <string.h>

typedef enum {
    LOOKUP_EXACT,
    LOOKUP_NEXT,
} lookup_mode_t;

/* Looks up `request_vb`'s OID (exact match for GET, lower-bound successor
 * for GETNEXT) and, on success, fills `out_vb` starting from the *found
 * object's* OID (identical to the request's OID for GET; the walked-to
 * OID for GETNEXT) and then its value. Does not touch `request_vb`. */
static mib_result_t lookup_and_fetch(lookup_mode_t mode, const snmp_varbind_t *request_vb, snmp_varbind_t *out_vb)
{
    const mib_object_t *obj = (mode == LOOKUP_EXACT) ? mib_registry_find(request_vb->oid, request_vb->oid_len)
                                                       : mib_registry_find_next(request_vb->oid, request_vb->oid_len);
    if (obj == NULL) {
        return (mode == LOOKUP_EXACT) ? MIB_NO_SUCH_OBJECT : MIB_END_OF_VIEW;
    }
    out_vb->oid_len = obj->oid_len;
    memcpy(out_vb->oid, obj->oid, (size_t)obj->oid_len * sizeof(uint32_t));
    return obj->getter(out_vb);
}

static ber_status_t process_read_pdu(snmp_pdu_ctx_t *ctx, lookup_mode_t mode)
{
    if (ctx->version == SNMP_VERSION_V1) {
        /* Pass 1 (validate only): probe every varbind into a throwaway
         * single scratch struct -- O(1) extra stack, not O(varbind_count)
         * -- so a mid-list failure can revert to the untouched original
         * request varbinds, per RFC1157's all-or-nothing GetResponse
         * semantics. */
        for (size_t i = 0; i < ctx->varbind_count; i++) {
            snmp_varbind_t scratch;
            memset(&scratch, 0, sizeof(scratch));
            mib_result_t res = lookup_and_fetch(mode, &ctx->varbinds[i], &scratch);
            snmp_error_translation_t tr = snmp_error_translate(ctx->version, res);
            if (tr.pdu_level_abort) {
                ctx->pdu_tag = SNMP_PDU_GET_RESPONSE;
                ctx->error_status = tr.v1_error_status;
                ctx->error_index = (int32_t)(i + 1);
                return BER_OK; /* ctx->varbinds intentionally left as the original request */
            }
        }
        /* Pass 2 (commit): re-run each lookup, this time writing straight
         * into ctx->varbinds -- pass 1 already guarantees every one
         * succeeds. */
        for (size_t i = 0; i < ctx->varbind_count; i++) {
            (void)lookup_and_fetch(mode, &ctx->varbinds[i], &ctx->varbinds[i]);
        }
        ctx->pdu_tag = SNMP_PDU_GET_RESPONSE;
        ctx->error_status = SNMP_V1_ERR_NO_ERROR;
        ctx->error_index = 0;
        return BER_OK;
    }

    /* v2c: single pass, per-varbind exception values, no wholesale abort
     * except the rare "getter itself failed" fallback. */
    for (size_t i = 0; i < ctx->varbind_count; i++) {
        snmp_varbind_t scratch;
        memset(&scratch, 0, sizeof(scratch));
        mib_result_t res = lookup_and_fetch(mode, &ctx->varbinds[i], &scratch);
        snmp_error_translation_t tr = snmp_error_translate(ctx->version, res);
        if (tr.pdu_level_abort) {
            ctx->pdu_tag = SNMP_PDU_GET_RESPONSE;
            ctx->error_status = tr.v1_error_status;
            ctx->error_index = (int32_t)(i + 1);
            return BER_OK;
        }
        if (tr.v2c_exception_tag != 0) {
            /* Leave ctx->varbinds[i].oid as the original request OID
             * (correct for both noSuchObject/noSuchInstance on GET and
             * endOfMibView on GETNEXT, where there is no "next" OID to
             * report anyway); only the value becomes the exception. */
            ctx->varbinds[i].value_tag = tr.v2c_exception_tag;
            ctx->varbinds[i].octets_len = 0;
        } else {
            ctx->varbinds[i] = scratch;
        }
    }
    ctx->pdu_tag = SNMP_PDU_GET_RESPONSE;
    ctx->error_status = 0;
    ctx->error_index = 0;
    return BER_OK;
}

ber_status_t snmp_pdu_handle_get(snmp_pdu_ctx_t *ctx)
{
    return process_read_pdu(ctx, LOOKUP_EXACT);
}

ber_status_t snmp_pdu_handle_getnext(snmp_pdu_ctx_t *ctx)
{
    return process_read_pdu(ctx, LOOKUP_NEXT);
}
