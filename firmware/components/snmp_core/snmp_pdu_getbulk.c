/* GetBulkRequest (v2c only, RFC3416 4.2.3). Wire-compatible with a
 * GetRequest PDU, but the second/third INTEGER fields mean non-repeaters
 * (N) / max-repetitions (M) instead of error-status/error-index -- already
 * decoded generically into ctx->error_status/error_index by
 * snmp_decode_request_pdu(); this handler just reinterprets them.
 *
 * Response shape: the first N request varbinds each get one GetNext (like
 * a non-repeating GetNextRequest); the remaining R = varbind_count - N
 * "repeating" varbinds each get GetNext applied up to M times, with the
 * response grouped by repetition (rep 1 of every repeater, then rep 2 of
 * every repeater, ...) per RFC3416, not grouped by variable. */
#include "snmp_dispatch.h"
#include "snmp_codec.h"
#include "snmp_error.h"
#include "mib_tree.h"
#include <string.h>

static mib_result_t getnext_into(const snmp_varbind_t *current, snmp_varbind_t *out_vb)
{
    const mib_object_t *obj = mib_registry_find_next(current->oid, current->oid_len);
    if (obj == NULL) {
        return MIB_END_OF_VIEW;
    }
    out_vb->oid_len = obj->oid_len;
    memcpy(out_vb->oid, obj->oid, (size_t)obj->oid_len * sizeof(uint32_t));
    return obj->getter(out_vb);
}

/* Appends one varbind to the in-progress response, translating a MIB
 * result into either a real value or a v2c exception tag. Returns 0 and
 * leaves `resp_count` unchanged if the response is already at capacity
 * (the size-bounded-truncation behavior Phase 8 exercises) or if the
 * getter itself failed outright; returns 1 on a normal append. */
static int append_result(snmp_varbind_t *resp, size_t *resp_count, size_t cap,
                          const snmp_varbind_t *current, mib_result_t res, const snmp_varbind_t *fetched)
{
    if (*resp_count >= cap) {
        return 0;
    }
    snmp_error_translation_t tr = snmp_error_translate(SNMP_VERSION_V2C, res);
    if (tr.pdu_level_abort) {
        /* A getter failing outright inside a GetBulk walk is rare and has
         * no clean per-varbind representation in this PDU type; report it
         * as endOfMibView for this slot rather than aborting the whole
         * (potentially large, already-partially-built) response. */
        resp[*resp_count] = *current;
        resp[*resp_count].value_tag = SNMP_TAG_END_OF_MIB_VIEW;
        resp[*resp_count].octets_len = 0;
        (*resp_count)++;
        return 1;
    }
    if (tr.v2c_exception_tag != 0) {
        resp[*resp_count] = *current;
        resp[*resp_count].value_tag = tr.v2c_exception_tag;
        resp[*resp_count].octets_len = 0;
    } else {
        resp[*resp_count] = *fetched;
    }
    (*resp_count)++;
    return 1;
}

ber_status_t snmp_pdu_handle_getbulk(snmp_pdu_ctx_t *ctx)
{
    if (ctx->version != SNMP_VERSION_V2C) {
        /* GetBulkRequest doesn't exist in SNMPv1; a v1 message somehow
         * carrying this PDU tag is malformed traffic, not a request we
         * can meaningfully answer. */
        return BER_ERR_BAD_TAG;
    }

    size_t total = ctx->varbind_count;
    size_t non_repeaters = ctx->error_status < 0 ? 0 : (size_t)ctx->error_status;
    if (non_repeaters > total) {
        non_repeaters = total;
    }
    size_t max_repetitions = ctx->error_index < 0 ? 0 : (size_t)ctx->error_index;
    size_t repeaters = total - non_repeaters;

    snmp_varbind_t response[SNMP_MAX_VARBINDS];
    size_t resp_count = 0;

    /* Non-repeating varbinds: exactly one GetNext each. */
    for (size_t i = 0; i < non_repeaters; i++) {
        snmp_varbind_t fetched;
        memset(&fetched, 0, sizeof(fetched));
        mib_result_t res = getnext_into(&ctx->varbinds[i], &fetched);
        if (!append_result(response, &resp_count, SNMP_MAX_VARBINDS, &ctx->varbinds[i], res, &fetched)) {
            goto done; /* response buffer full -- truncate cleanly rather than overflow */
        }
    }

    /* Repeating varbinds: walk each one forward, up to max_repetitions
     * times, grouped by repetition round. `cursor[]` tracks each
     * repeater's current position; `exhausted[]` short-circuits further
     * lookups once a repeater has already hit endOfMibView (still emits
     * the exception each remaining round, per RFC3416, but skips the
     * wasted registry search). */
    if (repeaters > 0 && max_repetitions > 0) {
        snmp_varbind_t cursor[SNMP_MAX_VARBINDS];
        int exhausted[SNMP_MAX_VARBINDS] = {0};
        for (size_t r = 0; r < repeaters; r++) {
            cursor[r] = ctx->varbinds[non_repeaters + r];
        }

        for (size_t rep = 0; rep < max_repetitions; rep++) {
            int any_active = 0;
            for (size_t r = 0; r < repeaters; r++) {
                mib_result_t res;
                snmp_varbind_t fetched;
                memset(&fetched, 0, sizeof(fetched));
                if (exhausted[r]) {
                    res = MIB_END_OF_VIEW;
                } else {
                    res = getnext_into(&cursor[r], &fetched);
                    if (res == MIB_OK) {
                        cursor[r] = fetched;
                        any_active = 1;
                    } else {
                        exhausted[r] = 1;
                    }
                }
                if (!append_result(response, &resp_count, SNMP_MAX_VARBINDS, &cursor[r], res, &fetched)) {
                    goto done;
                }
            }
            if (!any_active) {
                break; /* every repeater hit endOfMibView -- stop early rather than pad with more exceptions */
            }
        }
    }

done:
    memcpy(ctx->varbinds, response, resp_count * sizeof(snmp_varbind_t));
    ctx->varbind_count = resp_count;
    ctx->pdu_tag = SNMP_PDU_GET_RESPONSE;
    ctx->error_status = 0;
    ctx->error_index = 0;
    return BER_OK;
}
