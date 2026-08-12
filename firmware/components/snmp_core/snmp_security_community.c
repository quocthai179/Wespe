/* The v1/v2c community-based security model -- today's only registered
 * implementation of the snmp_security.h interface. Everything here is
 * private to this file: the PDU handlers and MIB layer never see a raw
 * community string, only the snmp_pdu_ctx_t::access_mode/principal this
 * produces. That boundary is what a future snmp_security_usm.c would slot
 * in alongside without touching anything outside this file. */
#include "snmp_security_community.h"
#include "snmp_security.h"
#include "snmp_codec.h"
#include <string.h>

#define COMMUNITY_MAX SNMP_MAX_PRINCIPAL_LEN

static char s_ro_community[COMMUNITY_MAX] = "public";
static char s_rw_community[COMMUNITY_MAX] = "private";

static ber_status_t process_incoming(const uint8_t *msg, size_t len, unsigned depth, snmp_pdu_ctx_t *out_ctx)
{
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
    int32_t version_raw = 0;
    st = ber_decode_integer(&version_tlv, &version_raw);
    if (st != BER_OK) {
        return st;
    }
    remaining -= (size_t)(version_tlv.next - p);
    p = version_tlv.next;

    ber_tlv_t community_tlv;
    st = ber_expect_tag(p, remaining, depth + 1, BER_TAG_OCTET_STRING, &community_tlv);
    if (st != BER_OK) {
        return st;
    }
    uint8_t community_buf[COMMUNITY_MAX];
    size_t community_len = 0;
    /* Reserve one byte for the NUL terminator; an over-length community
     * string (accidental or adversarial) is rejected here rather than
     * truncated-and-accepted. */
    st = ber_decode_octet_string(&community_tlv, community_buf, sizeof(community_buf) - 1, &community_len);
    if (st != BER_OK) {
        return st;
    }
    community_buf[community_len] = '\0';
    remaining -= (size_t)(community_tlv.next - p);
    p = community_tlv.next;

    out_ctx->version = (version_raw == (int32_t)SNMP_VERSION_V2C) ? SNMP_VERSION_V2C : SNMP_VERSION_V1;
    memcpy(out_ctx->principal, community_buf, community_len + 1);

    if (strcmp((const char *)community_buf, s_rw_community) == 0) {
        out_ctx->access_mode = SNMP_ACCESS_READWRITE;
    } else if (strcmp((const char *)community_buf, s_ro_community) == 0) {
        out_ctx->access_mode = SNMP_ACCESS_READ;
    } else {
        /* Unrecognized community: drop silently rather than answer with
         * an error, per SNMP convention -- an error response would
         * confirm to a prober which credentials are "close" to valid. */
        out_ctx->access_mode = SNMP_ACCESS_NONE;
        return BER_ERR_BAD_ARGS;
    }

    return snmp_decode_request_pdu(p, remaining, depth + 1, out_ctx);
}

static ber_status_t prepare_outgoing(const snmp_pdu_ctx_t *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t cursor = cap;
    ber_status_t st = snmp_encode_response_shaped_pdu(out, cap, &cursor, ctx->pdu_tag, ctx->request_id,
                                                        ctx->error_status, ctx->error_index, ctx->varbinds,
                                                        ctx->varbind_count);
    if (st != BER_OK) {
        return st;
    }

    size_t community_len = strlen(ctx->principal);
    st = ber_encode_octet_string(out, cap, &cursor, (const uint8_t *)ctx->principal, community_len);
    if (st != BER_OK) {
        return st;
    }

    st = ber_encode_integer(out, cap, &cursor, (int32_t)ctx->version);
    if (st != BER_OK) {
        return st;
    }

    size_t content_len = cap - cursor;
    st = ber_encode_container_header(out, cap, &cursor, BER_TAG_SEQUENCE, content_len);
    if (st != BER_OK) {
        return st;
    }

    /* The encoder built the message right-aligned in `out`; shift it down
     * to start at offset 0 so the caller gets a normal [out, out+*out_len)
     * buffer. */
    memmove(out, out + cursor, cap - cursor);
    *out_len = cap - cursor;
    return BER_OK;
}

static const snmp_security_model_t s_community_model = {
    .process_incoming = process_incoming,
    .prepare_outgoing = prepare_outgoing,
};

void snmp_security_community_init(const char *ro_community, const char *rw_community)
{
    strncpy(s_ro_community, ro_community, sizeof(s_ro_community) - 1);
    s_ro_community[sizeof(s_ro_community) - 1] = '\0';
    strncpy(s_rw_community, rw_community, sizeof(s_rw_community) - 1);
    s_rw_community[sizeof(s_rw_community) - 1] = '\0';

    snmp_security_register(SNMP_VERSION_V1, &s_community_model);
    snmp_security_register(SNMP_VERSION_V2C, &s_community_model);
}
