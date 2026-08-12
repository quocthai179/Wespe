/* SNMPv3-readiness proof, not an implementation -- see
 * include/snmp_security_usm_stub.h and docs/v3-readiness.md. */
#include "snmp_security_usm_stub.h"
#include "snmp_security.h"
#include "ber_codec.h"
#include <string.h>

static ber_status_t process_incoming(const uint8_t *msg, size_t len, unsigned depth, snmp_pdu_ctx_t *out_ctx)
{
    /* Confirm the message is at least well-formed SNMPv3 shape -- outer
     * SEQUENCE, msgVersion INTEGER, then a msgGlobalData SEQUENCE (msgID,
     * msgMaxSize, msgFlags, msgSecurityModel) -- without attempting to
     * decode msgSecurityParameters or msgData, since no USM auth/privacy
     * is implemented. This is exactly the seam a real snmp_security_usm.c
     * would extend from: same signature, same out_ctx to populate, this
     * file just stops short of the cryptographic work. */
    ber_tlv_t top;
    ber_status_t st = ber_expect_tag(msg, len, depth, BER_TAG_SEQUENCE, &top);
    if (st != BER_OK) {
        return st;
    }

    const uint8_t *p = top.value;
    size_t remaining = top.length;

    ber_tlv_t version_tlv;
    st = ber_expect_tag(p, remaining, depth + 1, BER_TAG_INTEGER, &version_tlv);
    if (st != BER_OK) {
        return st;
    }
    remaining -= (size_t)(version_tlv.next - p);
    p = version_tlv.next;

    ber_tlv_t global_data_tlv;
    st = ber_expect_tag(p, remaining, depth + 1, BER_TAG_SEQUENCE, &global_data_tlv);
    if (st != BER_OK) {
        return st;
    }

    out_ctx->version = SNMP_VERSION_V3;
    out_ctx->access_mode = SNMP_ACCESS_NONE;
    memset(out_ctx->principal, 0, sizeof(out_ctx->principal));

    /* Decline rather than guess at a response. snmp_message_process()
     * treats any non-BER_OK process_incoming() result as "send no
     * response" -- the same graceful drop used for an unrecognized
     * v1/v2c community, which is what makes `snmpget -v3` against this
     * agent time out cleanly instead of hanging or crashing it. */
    return BER_ERR_BAD_ARGS;
}

static ber_status_t prepare_outgoing(const snmp_pdu_ctx_t *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    /* Never reached in practice: process_incoming() above always fails
     * first, so snmp_message_process() never calls this for v3. Kept as
     * an explicit "not implemented" (rather than a null function pointer)
     * so any future caller that does reach it fails loudly instead of
     * crashing. */
    (void)ctx;
    (void)out;
    (void)cap;
    *out_len = 0;
    return BER_ERR_BAD_ARGS;
}

static const snmp_security_model_t s_usm_stub_model = {
    .process_incoming = process_incoming,
    .prepare_outgoing = prepare_outgoing,
};

void snmp_security_usm_stub_init(void)
{
    snmp_security_register(SNMP_VERSION_V3, &s_usm_stub_model);
}
