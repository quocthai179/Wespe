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

/* Safety net for the v1-Counter64-skip loop below: a real MIB never has
 * anywhere near this many consecutive Counter64 columns/rows, so hitting
 * this guard means something is misconfigured, not that the walk is
 * legitimately still in progress. Bounds the loop instead of ever spinning
 * on a (theoretically impossible, but not worth trusting blindly) cycle. */
#define SNMP_V1_COUNTER64_SKIP_GUARD 64

/* Resolves `request_vb`'s OID (exact match for GET, lower-bound successor
 * for GETNEXT) -- against scalars *and* table cells alike, via
 * mib_registry_resolve*() (docs/PLAN-TABLES.md Phase 11) -- and, on
 * success, fills `out_vb` starting from the *resolved instance's* OID
 * (identical to the request's OID for GET; the walked-to OID for
 * GETNEXT, which for a table cell includes the row index) and then its
 * value. Does not touch `request_vb`.
 *
 * Counter64 (SNMP_TAG_COUNTER64) does not exist in SNMPv1 (RFC2089 /
 * RFC3584): a v1 GET of one must answer noSuchName, and a v1 GETNEXT/walk
 * must silently step past it as though it weren't registered at all. Both
 * are enforced here, the one place every read path funnels through, so
 * GETBULK (which already rejects non-v2c requests outright in
 * snmp_pdu_getbulk.c) is the only read path that doesn't need this check. */
static mib_result_t lookup_and_fetch(snmp_version_t version, lookup_mode_t mode, const snmp_varbind_t *request_vb, snmp_varbind_t *out_vb)
{
    snmp_varbind_t current = *request_vb;

    for (int guard = 0; guard < SNMP_V1_COUNTER64_SKIP_GUARD; guard++) {
        mib_resolved_t resolved;
        mib_result_t r = (mode == LOOKUP_EXACT) ? mib_registry_resolve(current.oid, current.oid_len, &resolved)
                                                  : mib_registry_resolve_next(current.oid, current.oid_len, &resolved);
        if (r != MIB_OK) {
            return r; /* NO_SUCH_OBJECT / NO_SUCH_INSTANCE / END_OF_VIEW, as appropriate */
        }

        if (version == SNMP_VERSION_V1 && resolved.value_tag == SNMP_TAG_COUNTER64) {
            if (mode == LOOKUP_EXACT) {
                return MIB_NO_SUCH_OBJECT; /* -> v1 noSuchName, per RFC2089/RFC3584 */
            }
            /* GETNEXT: treat this instance as invisible and keep walking
             * from where it left off. */
            memcpy(current.oid, resolved.oid, (size_t)resolved.oid_len * sizeof(uint32_t));
            current.oid_len = resolved.oid_len;
            continue;
        }

        out_vb->oid_len = resolved.oid_len;
        memcpy(out_vb->oid, resolved.oid, (size_t)resolved.oid_len * sizeof(uint32_t));
        return mib_resolved_get(&resolved, out_vb);
    }
    return MIB_GEN_ERR; /* guard exhausted -- see comment above */
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
            mib_result_t res = lookup_and_fetch(ctx->version, mode, &ctx->varbinds[i], &scratch);
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
            (void)lookup_and_fetch(ctx->version, mode, &ctx->varbinds[i], &ctx->varbinds[i]);
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
        mib_result_t res = lookup_and_fetch(ctx->version, mode, &ctx->varbinds[i], &scratch);
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
