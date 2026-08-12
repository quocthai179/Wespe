/* Phase 8 hardening: a corpus of malformed/truncated/oversized/adversarial
 * inputs run through the full snmp_message_process() pipeline. The only
 * contract under test is "never misbehaves" -- no crash, no out-of-bounds
 * read/write (this binary is built with -fsanitize=address,undefined, see
 * CMakeLists.txt, so a real memory-safety bug aborts the process rather
 * than silently passing), and never a response larger than the caller's
 * buffer. There is no "expected" output shape for garbage input. */
#include "unity_mini.h"
#include "snmp_message.h"
#include "snmp_security.h"
#include "snmp_security_community.h"
#include "snmp_security_usm_stub.h"
#include "mib_tree.h"
#include "ber_codec.h"
#include <string.h>

static mib_result_t get_x(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = 1;
    return MIB_OK;
}
static const uint32_t OID_X[] = {1, 3, 6, 1, 4, 1, 99999, 1, 0};
static const mib_object_t s_objects[] = {
    {OID_X, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, get_x, NULL},
};

static void setup(void)
{
    mib_registry_reset();
    snmp_security_reset();
    mib_registry_register_module(s_objects, 1);
    snmp_security_community_init("public", "private");
    snmp_security_usm_stub_init();
}

static snmp_varbind_t make_null_varbind(const uint32_t *oid, size_t oid_len)
{
    snmp_varbind_t vb;
    memset(&vb, 0, sizeof(vb));
    memcpy(vb.oid, oid, oid_len * sizeof(uint32_t));
    vb.oid_len = oid_len;
    vb.value_tag = BER_TAG_NULL;
    return vb;
}

/* Same technique as test_snmp_message.c: build a legitimate request by
 * reusing the community model's prepare_outgoing() (generic over
 * pdu_tag), so a test can start from known-good wire bytes and corrupt
 * exactly one thing, rather than hand-computing an entire BER byte array
 * (error-prone and not the point of this file). */
static size_t build_request(snmp_version_t version, uint8_t pdu_tag, const char *community, int32_t request_id,
                             int32_t field2, int32_t field3, const snmp_varbind_t *varbinds, size_t count,
                             uint8_t *out, size_t cap)
{
    const snmp_security_model_t *model = snmp_security_lookup((int32_t)version);
    if (model == NULL) {
        return 0;
    }
    snmp_pdu_ctx_t req;
    memset(&req, 0, sizeof(req));
    req.version = version;
    req.pdu_tag = pdu_tag;
    req.request_id = request_id;
    req.error_status = field2;
    req.error_index = field3;
    strncpy(req.principal, community, sizeof(req.principal) - 1);
    req.varbind_count = count;
    for (size_t i = 0; i < count; i++) {
        req.varbinds[i] = varbinds[i];
    }
    size_t out_len = 0;
    ber_status_t st = model->prepare_outgoing(&req, out, cap, &out_len);
    return (st == BER_OK) ? out_len : 0;
}

static void assert_handles_safely(const uint8_t *packet, size_t len)
{
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, len, response, sizeof(response));
    UM_CHECK(response_len <= sizeof(response));
}

UM_TEST(test_empty_buffer)
{
    setup();
    assert_handles_safely(NULL, 0);
}

UM_TEST(test_single_byte)
{
    setup();
    uint8_t packet[] = {0x30};
    assert_handles_safely(packet, sizeof(packet));
}

UM_TEST(test_truncated_length)
{
    setup();
    uint8_t packet[] = {0x30, 0x81}; /* claims a long-form length byte that isn't present */
    assert_handles_safely(packet, sizeof(packet));
}

UM_TEST(test_indefinite_length_rejected)
{
    setup();
    /* SNMP never uses indefinite-length BER -- 0x80 alone must be rejected. */
    uint8_t packet[] = {0x30, 0x80, 0x00, 0x00};
    assert_handles_safely(packet, sizeof(packet));
}

UM_TEST(test_length_claims_more_than_buffer_has)
{
    setup();
    uint8_t packet[] = {0x30, 0x7F, 0x02, 0x01, 0x00}; /* claims 127 content bytes, only 3 present */
    assert_handles_safely(packet, sizeof(packet));
}

UM_TEST(test_random_noise)
{
    setup();
    /* Fixed pseudo-random bytes (deterministic, not real randomness),
     * covering the full byte range. */
    uint8_t packet[64];
    uint32_t state = 0xC0FFEEu;
    for (size_t i = 0; i < sizeof(packet); i++) {
        state = state * 1103515245u + 12345u;
        packet[i] = (uint8_t)(state >> 16);
    }
    assert_handles_safely(packet, sizeof(packet));
}

UM_TEST(test_truncated_valid_request_at_every_prefix_length)
{
    setup();
    /* Take a genuinely well-formed request and feed every possible
     * truncation of it (1 byte, 2 bytes, ..., full length) through the
     * pipeline -- a classic, cheap way to hit a huge range of "looked
     * fine until it suddenly wasn't" truncation states without hand-
     * crafting each one. */
    snmp_varbind_t req_vb = make_null_varbind(OID_X, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 1, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    for (size_t n = 0; n < packet_len; n++) {
        assert_handles_safely(packet, n);
    }
}

UM_TEST(test_oid_with_unterminated_continuation_in_varbind)
{
    setup();
    snmp_varbind_t req_vb = make_null_varbind(OID_X, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 1, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 2);

    /* The varbind (SEQUENCE { OID, NULL }) is the last thing encoded, so
     * the packet's tail is [...][OID content][NULL tag=0x05][NULL len=0x00].
     * OR-ing the continuation bit onto the OID's last content byte turns a
     * well-formed OID into one that claims "more bytes follow" right up
     * to the buffer's actual end. */
    packet[packet_len - 3] |= 0x80;
    assert_handles_safely(packet, packet_len);
}

UM_TEST(test_negative_getbulk_repetitions_clamped)
{
    setup();
    snmp_varbind_t req_vb = make_null_varbind(OID_X, 9);
    uint8_t packet[512];
    /* Protocol-invalid but perfectly well-formed BER: negative non-
     * repeaters and max-repetitions. Must clamp to 0 rather than
     * underflow a size_t computation in snmp_pdu_getbulk.c. */
    size_t packet_len =
        build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_BULK_REQUEST, "public", 1, -1, -1, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    assert_handles_safely(packet, packet_len);
}

UM_TEST(test_huge_max_repetitions_truncates_cleanly)
{
    setup();
    snmp_varbind_t req_vb = make_null_varbind(OID_X, 9);
    uint8_t packet[512];
    /* A max-repetitions large enough that, if unbounded, would produce a
     * response far larger than any UDP-safe buffer. snmp_pdu_getbulk.c
     * must stop at SNMP_MAX_VARBINDS rather than overflow the fixed
     * response[] array or the output buffer. */
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_BULK_REQUEST, "public", 1, 0, 1000000, &req_vb, 1,
                                       packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    assert_handles_safely(packet, packet_len);
}

UM_TEST(test_oversized_community_string_rejected)
{
    setup();
    /* Community string longer than SNMP_MAX_PRINCIPAL_LEN, built directly
     * with the low-level encoder (prepare_outgoing's principal field is
     * itself bounded, so build_request() can't produce this on its own).
     * Must be rejected by process_incoming's bounded octet-string decode,
     * not overflow out_ctx->principal. */
    uint8_t packet[128];
    size_t cursor = sizeof(packet);
    uint8_t huge_community[80];
    memset(huge_community, 'A', sizeof(huge_community));

    size_t pdu_start = cursor;
    ber_status_t st = ber_encode_container_header(packet, sizeof(packet), &cursor, BER_TAG_SEQUENCE, 0); /* empty varbind-list */
    UM_CHECK_EQ_INT(st, BER_OK);
    st = ber_encode_integer(packet, sizeof(packet), &cursor, 0);
    UM_CHECK_EQ_INT(st, BER_OK);
    st = ber_encode_integer(packet, sizeof(packet), &cursor, 0);
    UM_CHECK_EQ_INT(st, BER_OK);
    st = ber_encode_integer(packet, sizeof(packet), &cursor, 1);
    UM_CHECK_EQ_INT(st, BER_OK);
    size_t pdu_len = pdu_start - cursor;
    st = ber_encode_container_header(packet, sizeof(packet), &cursor, SNMP_PDU_GET_REQUEST, pdu_len);
    UM_CHECK_EQ_INT(st, BER_OK);
    st = ber_encode_octet_string(packet, sizeof(packet), &cursor, huge_community, sizeof(huge_community));
    UM_CHECK_EQ_INT(st, BER_OK);
    st = ber_encode_integer(packet, sizeof(packet), &cursor, 1);
    UM_CHECK_EQ_INT(st, BER_OK);
    size_t content_len = sizeof(packet) - cursor;
    st = ber_encode_container_header(packet, sizeof(packet), &cursor, BER_TAG_SEQUENCE, content_len);
    UM_CHECK_EQ_INT(st, BER_OK);

    memmove(packet, packet + cursor, sizeof(packet) - cursor);
    assert_handles_safely(packet, sizeof(packet) - cursor);
}

UM_TEST(test_max_varbinds_request_does_not_overflow)
{
    setup();
    /* A GetRequest carrying exactly SNMP_MAX_VARBINDS varbinds (the most
     * this codec accepts) -- confirms the boundary itself is handled, not
     * just comfortably-under or comfortably-over counts. */
    snmp_varbind_t varbinds[SNMP_MAX_VARBINDS];
    for (size_t i = 0; i < SNMP_MAX_VARBINDS; i++) {
        varbinds[i] = make_null_varbind(OID_X, 9);
    }
    uint8_t packet[2048];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 1, 0, 0, varbinds,
                                       SNMP_MAX_VARBINDS, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    assert_handles_safely(packet, packet_len);
}

int main(void)
{
    UM_RUN(test_empty_buffer);
    UM_RUN(test_single_byte);
    UM_RUN(test_truncated_length);
    UM_RUN(test_indefinite_length_rejected);
    UM_RUN(test_length_claims_more_than_buffer_has);
    UM_RUN(test_random_noise);
    UM_RUN(test_truncated_valid_request_at_every_prefix_length);
    UM_RUN(test_oid_with_unterminated_continuation_in_varbind);
    UM_RUN(test_negative_getbulk_repetitions_clamped);
    UM_RUN(test_huge_max_repetitions_truncates_cleanly);
    UM_RUN(test_oversized_community_string_rejected);
    UM_RUN(test_max_varbinds_request_does_not_overflow);
    return um_summary();
}
