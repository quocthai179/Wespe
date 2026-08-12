/* Top-level entry point: the only piece of this codec that knows about
 * "a whole incoming datagram" and "a whole outgoing datagram". Everything
 * it does is either generic BER (decode the outer SEQUENCE+version) or a
 * one-line delegation to whichever component owns the next step -- it
 * doesn't itself contain any version-specific or PDU-specific logic. */
#include "snmp_message.h"
#include "snmp_security.h"
#include "snmp_dispatch.h"
#include "ber_codec.h"
#include "snmp_pdu.h"
#include <string.h>

size_t snmp_message_process(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap)
{
    if (in == NULL || out == NULL || in_len == 0 || out_cap == 0) {
        return 0;
    }

    /* Sniff only the outer SEQUENCE + msgVersion -- the one field every
     * SNMP message version is guaranteed to share in the same place
     * (RFC3412 6.2 defines even SNMPv3's outer shape to start this way).
     * Every other structural difference between v1/v2c and v3 lives
     * inside the per-version security model from here on -- see
     * snmp_security.h for why that split is the point. */
    ber_tlv_t top;
    ber_status_t st = ber_decode_tlv(in, in_len, 0, &top);
    if (st != BER_OK || top.tag != BER_TAG_SEQUENCE) {
        return 0;
    }
    ber_tlv_t version_tlv;
    st = ber_expect_tag(top.value, top.length, 1, BER_TAG_INTEGER, &version_tlv);
    if (st != BER_OK) {
        return 0;
    }
    int32_t version = 0;
    st = ber_decode_integer(&version_tlv, &version);
    if (st != BER_OK) {
        return 0;
    }

    const snmp_security_model_t *model = snmp_security_lookup(version);
    if (model == NULL) {
        return 0; /* unsupported version -- drop, don't guess at an error response */
    }

    snmp_pdu_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    st = model->process_incoming(in, in_len, 0, &ctx);
    if (st != BER_OK) {
        return 0; /* bad community / malformed PDU / v3 decline -- drop */
    }

    st = snmp_dispatch_pdu(&ctx);
    if (st != BER_OK) {
        return 0; /* e.g. SetRequest without write access, or an unanswerable PDU type -- drop */
    }

    size_t out_len = 0;
    st = model->prepare_outgoing(&ctx, out, out_cap, &out_len);
    if (st != BER_OK) {
        return 0; /* e.g. response doesn't fit in out_cap -- fail safe, never send a truncated packet */
    }

    return out_len;
}
