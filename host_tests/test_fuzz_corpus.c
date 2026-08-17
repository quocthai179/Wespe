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

/* A small mock table (docs/PLAN-TABLES.md Phase 14), for the
 * table-shaped hostile-input cases below -- absurd/oversized row
 * indices, truncated cell OIDs, GETBULK over-repetition -- none of which
 * the scalar-only s_objects module above can exercise. Only 2 rows: the
 * point of this file is safety under adversarial input, not table-walk
 * correctness (that's test_mib_table.c's/test_snmp_message.c's job). */
static mib_result_t table_first_index(uint32_t *out)
{
    *out = 1;
    return MIB_OK;
}
static mib_result_t table_next_index(uint32_t cur, uint32_t *out)
{
    if (cur < 2) {
        *out = 2;
        return MIB_OK;
    }
    return MIB_END_OF_VIEW;
}
static mib_result_t table_get_cell(uint32_t column, uint32_t index, snmp_varbind_t *vb)
{
    (void)column;
    (void)index;
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = 42;
    return MIB_OK;
}
static const uint32_t TABLE_ENTRY[] = {1, 3, 6, 1, 4, 1, 99999, 2, 1};
static const mib_column_t s_table_columns[] = {{1, BER_TAG_INTEGER, MIB_ACCESS_RO}};
static const mib_table_t s_mock_table = {
    .entry_oid = TABLE_ENTRY,
    .entry_oid_len = 9,
    .columns = s_table_columns,
    .column_count = 1,
    .first_index = table_first_index,
    .next_index = table_next_index,
    .get_cell = table_get_cell,
    .set_cell = NULL,
};

static void setup(void)
{
    mib_registry_reset();
    snmp_security_reset();
    mib_registry_register_module(s_objects, 1);
    mib_registry_register_table(&s_mock_table);
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

/* ---- Table-shaped hostile input (docs/PLAN-TABLES.md Phase 14) ---- */

static uint32_t s_cell_oid[16];
static size_t build_cell_oid(uint32_t column, uint32_t index)
{
    memcpy(s_cell_oid, TABLE_ENTRY, 9 * sizeof(uint32_t));
    s_cell_oid[9] = column;
    s_cell_oid[10] = index;
    return 11;
}

UM_TEST(test_table_cell_with_max_uint32_index)
{
    setup();
    /* The largest index a single sub-identifier can hold. Must resolve
     * to "no such row" safely, not be mistaken for a real one or
     * mishandled by whatever row-iteration bound check exists. */
    size_t len = build_cell_oid(1, 0xFFFFFFFFu);
    snmp_varbind_t req_vb = make_null_varbind(s_cell_oid, len);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 1, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    assert_handles_safely(packet, packet_len);
}

UM_TEST(test_oid_arc_exceeding_uint32_is_rejected_cleanly)
{
    setup();
    /* A base-128 VLQ arc needing more than 5 continuation-tagged bytes
     * encodes a value ber_decode_oid() can't represent in a uint32_t --
     * it must reject this with BER_ERR_OVERFLOW during decode (see
     * ber_decode.c's `arc > (UINT32_MAX >> 7)` guard) rather than wrap,
     * truncate, or read out of bounds. Hand-built raw packet (not
     * build_request(), which can't produce an unrepresentable OID) using
     * the same "wespe table entry + a hostile last arc" shape as the
     * other table-cell cases here: SEQUENCE { version=v2c,
     * community="public", GetRequest { ...varbind { OID, NULL } } } with
     * the OID's last sub-identifier's continuation bits set on 6 bytes. */
    uint8_t packet[] = {
        0x30, 0x25,                                     /* outer SEQUENCE, len=37 */
        0x02, 0x01, 0x01,                               /* version = v2c */
        0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',        /* community */
        0xA0, 0x18,                                      /* GetRequest, len=24 */
        0x02, 0x01, 0x01,                               /* request-id */
        0x02, 0x01, 0x00,                               /* error-status */
        0x02, 0x01, 0x00,                               /* error-index */
        0x30, 0x0D,                                      /* varbind-list, len=13 */
        0x30, 0x0B,                                      /* varbind, len=11 */
        0x06, 0x07, 0x2B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, /* OID: valid 2-arc first byte, then one arc spanning 6 continuation bytes -- overflows uint32 */
        0x05, 0x00,                                      /* NULL */
    };
    assert_handles_safely(packet, sizeof(packet));
}

UM_TEST(test_table_entry_with_no_column_or_index)
{
    setup();
    /* Table entry OID with nothing appended -- no column, no index.
     * Exact-match must be a clean MIB_NO_SUCH_OBJECT (test_mib_table.c
     * covers this at the registry level already); this confirms it
     * survives the full wire pipeline too. */
    snmp_varbind_t req_vb = make_null_varbind(TABLE_ENTRY, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 1, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    assert_handles_safely(packet, packet_len);
}

UM_TEST(test_table_column_with_no_index)
{
    setup();
    uint32_t oid[10];
    memcpy(oid, TABLE_ENTRY, 9 * sizeof(uint32_t));
    oid[9] = 1; /* column, no row index appended at all */
    snmp_varbind_t req_vb = make_null_varbind(oid, 10);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 1, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    assert_handles_safely(packet, packet_len);
}

UM_TEST(test_table_cell_with_extra_trailing_index_components)
{
    setup();
    /* A cell OID with more sub-identifiers than this table's single-
     * uint32_t index scheme expects (docs/PLAN-TABLES.md's documented
     * "multi-part indices not supported" limit) -- must be handled as
     * cleanly as any other unrecognized OID, not misread the extra
     * components as part of the index. */
    uint32_t oid[16];
    memcpy(oid, TABLE_ENTRY, 9 * sizeof(uint32_t));
    oid[9] = 1;
    oid[10] = 1;
    oid[11] = 1;
    oid[12] = 1;
    snmp_varbind_t req_vb = make_null_varbind(oid, 13);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 1, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    assert_handles_safely(packet, packet_len);
}

UM_TEST(test_getbulk_huge_max_repetitions_over_table)
{
    setup();
    /* Same idea as test_huge_max_repetitions_truncates_cleanly, but
     * starting the walk right at a real (if tiny, 2-row) table instead
     * of a lone scalar -- confirms SNMP_MAX_VARBINDS's cap holds for a
     * table-driven walk too, not just the scalar-only end-of-view path
     * that test already covers. */
    snmp_varbind_t req_vb = make_null_varbind(TABLE_ENTRY, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_BULK_REQUEST, "public", 1, 0, 1000000, &req_vb, 1,
                                       packet, sizeof(packet));
    UM_CHECK(packet_len > 0);
    assert_handles_safely(packet, packet_len);
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
    UM_RUN(test_table_cell_with_max_uint32_index);
    UM_RUN(test_oid_arc_exceeding_uint32_is_rejected_cleanly);
    UM_RUN(test_table_entry_with_no_column_or_index);
    UM_RUN(test_table_column_with_no_index);
    UM_RUN(test_table_cell_with_extra_trailing_index_components);
    UM_RUN(test_getbulk_huge_max_repetitions_over_table);
    UM_RUN(test_max_varbinds_request_does_not_overflow);
    return um_summary();
}
