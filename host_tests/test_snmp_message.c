/* End-to-end tests of the whole request -> snmp_message_process ->
 * response path, against a small mocked MIB module (independent of
 * mib_ii.c/mib_wespe.c and therefore of hal/, same spirit as
 * test_mib_registry.c). This is the primary evidence that the from-
 * scratch codec, security-model dispatch, and PDU handlers are wire-
 * compatible with each other end to end -- not just unit-correct in
 * isolation. */
#include "unity_mini.h"
#include "snmp_message.h"
#include "snmp_security.h"
#include "snmp_security_community.h"
#include "snmp_security_usm_stub.h"
#include "snmp_trap.h"
#include "snmp_error.h"
#include "snmp_codec.h"
#include "mib_tree.h"
#include <string.h>

static int32_t s_mock_b_value = 0;

static mib_result_t get_a(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = 100;
    return MIB_OK;
}
static mib_result_t get_b(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = s_mock_b_value;
    return MIB_OK;
}
static mib_result_t set_b(const snmp_varbind_t *vb)
{
    s_mock_b_value = vb->int_value;
    return MIB_OK;
}
static mib_result_t get_c(snmp_varbind_t *vb)
{
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = 300;
    return MIB_OK;
}

static const uint32_t OID_A[] = {1, 3, 6, 1, 4, 1, 11111, 1, 0};
static const uint32_t OID_B[] = {1, 3, 6, 1, 4, 1, 11111, 2, 0};
static const uint32_t OID_C[] = {1, 3, 6, 1, 4, 1, 11111, 3, 0};

static const mib_object_t s_mock_objects[] = {
    {OID_A, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, get_a, NULL},
    {OID_B, 9, BER_TAG_INTEGER, MIB_ACCESS_RW, get_b, set_b},
    {OID_C, 9, BER_TAG_INTEGER, MIB_ACCESS_RO, get_c, NULL},
};

/* A tiny mock table (2 rows, 1 writable column), registered right after
 * OID_C in OID space, so GETNEXT off the end of the scalars naturally
 * walks into it -- full-pipeline (BER + PDU handling + resolve)
 * integration coverage on top of test_mib_table.c's registry-level
 * coverage of the same table-walk logic. */
static int32_t s_table_row1_value = 10;
static int32_t s_table_row2_value = 20;

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
    vb->value_tag = BER_TAG_INTEGER;
    vb->int_value = (index == 1) ? s_table_row1_value : s_table_row2_value;
    return MIB_OK;
}
static mib_result_t table_set_cell(uint32_t column, uint32_t index, const snmp_varbind_t *vb)
{
    (void)column;
    if (vb->value_tag != BER_TAG_INTEGER) {
        return MIB_WRONG_TYPE;
    }
    if (index == 1) {
        s_table_row1_value = vb->int_value;
    } else {
        s_table_row2_value = vb->int_value;
    }
    return MIB_OK;
}

static const uint32_t TABLE_ENTRY[] = {1, 3, 6, 1, 4, 1, 11111, 4, 1};
static const mib_column_t s_table_columns[] = {{1, BER_TAG_INTEGER, MIB_ACCESS_RW}};
static const mib_table_t s_mock_table = {
    .entry_oid = TABLE_ENTRY,
    .entry_oid_len = 9,
    .columns = s_table_columns,
    .column_count = 1,
    .first_index = table_first_index,
    .next_index = table_next_index,
    .get_cell = table_get_cell,
    .set_cell = table_set_cell,
};

static void setup(void)
{
    mib_registry_reset();
    snmp_security_reset();
    mib_registry_register_module(s_mock_objects, 3);
    snmp_security_community_init("public", "private");
    snmp_security_usm_stub_init();
    s_mock_b_value = 0;
}

/* Same as setup(), plus the mock table -- kept separate (rather than
 * folded into setup() itself) specifically so it doesn't shift the
 * "end of MIB view" boundary that the plain-scalar tests above already
 * pin exact varbind counts against. */
static void setup_with_table(void)
{
    setup();
    mib_registry_register_table(&s_mock_table);
    s_table_row1_value = 10;
    s_table_row2_value = 20;
}

/* A Counter64-valued scalar (docs/PLAN-TABLES.md Phase 12), registered as
 * its own module right after OID_C in OID space -- registered separately
 * from setup()/setup_with_table() for the same "don't shift an existing
 * end-of-view boundary" reason. Value exceeds 32 bits so a truncating bug
 * (e.g. accidentally routing it through the 32-bit unsigned path) would be
 * caught by a value mismatch, not just a tag mismatch. */
static uint64_t s_mock_d_value = 0x1FFFFFFFFULL; /* > UINT32_MAX */

static mib_result_t get_d(snmp_varbind_t *vb)
{
    vb->value_tag = SNMP_TAG_COUNTER64;
    vb->counter64_value = s_mock_d_value;
    return MIB_OK;
}

static const uint32_t OID_D[] = {1, 3, 6, 1, 4, 1, 11111, 5, 0};
static const mib_object_t s_mock_counter64_objects[] = {
    {OID_D, 9, SNMP_TAG_COUNTER64, MIB_ACCESS_RO, get_d, NULL},
};

static void setup_with_counter64(void)
{
    setup();
    mib_registry_register_module(s_mock_counter64_objects, 1);
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

static snmp_varbind_t make_int_varbind(const uint32_t *oid, size_t oid_len, int32_t value)
{
    snmp_varbind_t vb = make_null_varbind(oid, oid_len);
    vb.value_tag = BER_TAG_INTEGER;
    vb.int_value = value;
    return vb;
}

/* Builds a legitimate wire-format request by reusing the community
 * model's prepare_outgoing() -- it's generic over pdu_tag, so it happily
 * encodes a *request*-shaped ctx too. This exercises the same encoder
 * production code uses, while snmp_message_process() on the receiving
 * end independently decodes it via process_incoming(), so the test still
 * validates real wire compatibility, not a tautology. */
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

/* Test-only decoder that accepts *any* PDU tag (unlike production's
 * snmp_decode_request_pdu, which deliberately only accepts request tags)
 * so tests can introspect a GetResponse/Trap. Not part of the shipped
 * codec. */
static int decode_message_any_tag(const uint8_t *buf, size_t len, snmp_pdu_ctx_t *out_ctx)
{
    memset(out_ctx, 0, sizeof(*out_ctx));
    ber_tlv_t top;
    if (ber_expect_tag(buf, len, 0, BER_TAG_SEQUENCE, &top) != BER_OK) {
        return 0;
    }
    const uint8_t *p = top.value;
    size_t remaining = top.length;

    ber_tlv_t version_tlv;
    if (ber_expect_tag(p, remaining, 1, BER_TAG_INTEGER, &version_tlv) != BER_OK) {
        return 0;
    }
    int32_t version_raw = 0;
    if (ber_decode_integer(&version_tlv, &version_raw) != BER_OK) {
        return 0;
    }
    out_ctx->version = (snmp_version_t)version_raw;
    remaining -= (size_t)(version_tlv.next - p);
    p = version_tlv.next;

    ber_tlv_t community_tlv;
    if (ber_expect_tag(p, remaining, 1, BER_TAG_OCTET_STRING, &community_tlv) != BER_OK) {
        return 0;
    }
    uint8_t community_buf[SNMP_MAX_PRINCIPAL_LEN];
    size_t community_len = 0;
    if (ber_decode_octet_string(&community_tlv, community_buf, sizeof(community_buf) - 1, &community_len) != BER_OK) {
        return 0;
    }
    community_buf[community_len] = '\0';
    memcpy(out_ctx->principal, community_buf, community_len + 1);
    remaining -= (size_t)(community_tlv.next - p);
    p = community_tlv.next;

    ber_tlv_t pdu;
    if (ber_decode_tlv(p, remaining, 1, &pdu) != BER_OK) {
        return 0;
    }
    out_ctx->pdu_tag = pdu.tag;

    const uint8_t *pp = pdu.value;
    size_t prem = pdu.length;
    ber_tlv_t f1, f2, f3;
    if (ber_expect_tag(pp, prem, 2, BER_TAG_INTEGER, &f1) != BER_OK) return 0;
    ber_decode_integer(&f1, &out_ctx->request_id);
    prem -= (size_t)(f1.next - pp);
    pp = f1.next;
    if (ber_expect_tag(pp, prem, 2, BER_TAG_INTEGER, &f2) != BER_OK) return 0;
    ber_decode_integer(&f2, &out_ctx->error_status);
    prem -= (size_t)(f2.next - pp);
    pp = f2.next;
    if (ber_expect_tag(pp, prem, 2, BER_TAG_INTEGER, &f3) != BER_OK) return 0;
    ber_decode_integer(&f3, &out_ctx->error_index);
    prem -= (size_t)(f3.next - pp);
    pp = f3.next;

    return snmp_decode_varbind_list(pp, prem, 2, out_ctx->varbinds, SNMP_MAX_VARBINDS, &out_ctx->varbind_count) == BER_OK;
}

UM_TEST(test_get_request_success)
{
    setup();
    snmp_varbind_t req_vb = make_null_varbind(OID_A, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 1, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);

    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.pdu_tag, SNMP_PDU_GET_RESPONSE);
    UM_CHECK_EQ_INT(resp.error_status, 0);
    UM_CHECK_EQ_INT(resp.varbind_count, 1);
    UM_CHECK_EQ_INT(resp.varbinds[0].value_tag, BER_TAG_INTEGER);
    UM_CHECK_EQ_INT(resp.varbinds[0].int_value, 100);
}

UM_TEST(test_get_request_v1_no_such_name)
{
    setup();
    uint32_t missing[] = {1, 3, 6, 1, 4, 1, 11111, 9, 0};
    snmp_varbind_t req_vb = make_null_varbind(missing, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V1, SNMP_PDU_GET_REQUEST, "public", 7, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);

    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, SNMP_V1_ERR_NO_SUCH_NAME);
    UM_CHECK_EQ_INT(resp.error_index, 1);
    UM_CHECK_EQ_INT(resp.varbinds[0].value_tag, BER_TAG_NULL); /* echoed original request */
}

UM_TEST(test_get_request_v2c_no_such_object)
{
    setup();
    uint32_t missing[] = {1, 3, 6, 1, 4, 1, 11111, 9, 0};
    snmp_varbind_t req_vb = make_null_varbind(missing, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 8, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, 0);
    UM_CHECK_EQ_INT(resp.varbinds[0].value_tag, SNMP_TAG_NO_SUCH_OBJECT);
}

UM_TEST(test_get_next_request_walks_to_first_object)
{
    setup();
    uint32_t before_all[] = {1, 3, 6, 1, 4, 1, 11111, 0};
    snmp_varbind_t req_vb = make_null_varbind(before_all, 8);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_NEXT_REQUEST, "public", 2, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.varbinds[0].oid_len, 9);
    for (int i = 0; i < 9; i++) {
        UM_CHECK_EQ_INT(resp.varbinds[0].oid[i], OID_A[i]);
    }
    UM_CHECK_EQ_INT(resp.varbinds[0].int_value, 100);
}

UM_TEST(test_v2c_get_counter64_returns_value)
{
    /* No skip/exception treatment under v2c -- Counter64 is a completely
     * normal object there. */
    setup_with_counter64();
    snmp_varbind_t req_vb = make_null_varbind(OID_D, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 30, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);

    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, 0);
    UM_CHECK_EQ_INT(resp.varbinds[0].value_tag, SNMP_TAG_COUNTER64);
    UM_CHECK(resp.varbinds[0].counter64_value == s_mock_d_value);
}

UM_TEST(test_v1_get_counter64_returns_no_such_name)
{
    /* RFC2089/RFC3584: a v1 GET of a Counter64 object must be answered
     * noSuchName, exactly like the object didn't exist at all. */
    setup_with_counter64();
    snmp_varbind_t req_vb = make_null_varbind(OID_D, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V1, SNMP_PDU_GET_REQUEST, "public", 31, 0, 0, &req_vb, 1, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);

    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, SNMP_V1_ERR_NO_SUCH_NAME);
    UM_CHECK_EQ_INT(resp.error_index, 1);
    UM_CHECK_EQ_INT(resp.varbinds[0].value_tag, BER_TAG_NULL); /* echoed original request */
}

UM_TEST(test_v2c_getnext_reaches_counter64)
{
    setup_with_counter64();
    snmp_varbind_t req_vb = make_null_varbind(OID_C, 9); /* last plain-INTEGER scalar */
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_NEXT_REQUEST, "public", 32, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.varbinds[0].oid_len, 9);
    for (int i = 0; i < 9; i++) {
        UM_CHECK_EQ_INT(resp.varbinds[0].oid[i], OID_D[i]);
    }
    UM_CHECK_EQ_INT(resp.varbinds[0].value_tag, SNMP_TAG_COUNTER64);
    UM_CHECK(resp.varbinds[0].counter64_value == s_mock_d_value);
}

UM_TEST(test_v1_getnext_walks_past_counter64_to_end_of_view)
{
    /* OID_D is the last registered object in this fixture; a v1 walk
     * starting right before it must not stop *on* it (it's invisible to
     * v1), and since nothing follows it either, the walk falls straight
     * through to noSuchName (v1's spelling of end-of-MIB-view) rather than
     * ever exposing the Counter64 value on the wire. */
    setup_with_counter64();
    snmp_varbind_t req_vb = make_null_varbind(OID_C, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V1, SNMP_PDU_GET_NEXT_REQUEST, "public", 33, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, SNMP_V1_ERR_NO_SUCH_NAME);
    UM_CHECK_EQ_INT(resp.error_index, 1);
    for (int i = 0; i < 9; i++) {
        UM_CHECK_EQ_INT(resp.varbinds[0].oid[i], OID_C[i]); /* echoed original request */
    }
}

UM_TEST(test_getbulk_walks_through_counter64_v2c)
{
    /* GETBULK is v2c/v3-only (rejected outright for v1 elsewhere), so it
     * never needs the skip logic -- this just confirms Counter64 flows
     * through the bulk path like any other value. */
    setup_with_counter64();
    snmp_varbind_t req_vb = make_null_varbind(OID_C, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_BULK_REQUEST, "public", 34, 0, 2, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.varbind_count, 2);
    UM_CHECK_EQ_INT(resp.varbinds[0].value_tag, SNMP_TAG_COUNTER64);
    UM_CHECK(resp.varbinds[0].counter64_value == s_mock_d_value);
    UM_CHECK_EQ_INT(resp.varbinds[1].value_tag, SNMP_TAG_END_OF_MIB_VIEW);
}

UM_TEST(test_set_request_dropped_without_write_access)
{
    setup();
    snmp_varbind_t req_vb = make_int_varbind(OID_B, 9, 42);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_SET_REQUEST, "public", 3, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK_EQ_INT(response_len, 0);
    UM_CHECK_EQ_INT(s_mock_b_value, 0);
}

UM_TEST(test_set_request_success)
{
    setup();
    snmp_varbind_t req_vb = make_int_varbind(OID_B, 9, 42);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_SET_REQUEST, "private", 4, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);
    UM_CHECK_EQ_INT(s_mock_b_value, 42);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, 0);
    UM_CHECK_EQ_INT(resp.varbinds[0].int_value, 42);
}

UM_TEST(test_set_request_on_read_only_object)
{
    setup();
    snmp_varbind_t req_vb = make_int_varbind(OID_A, 9, 1);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_SET_REQUEST, "private", 5, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, SNMP_V1_ERR_READ_ONLY);
    UM_CHECK_EQ_INT(resp.error_index, 1);
}

UM_TEST(test_unknown_community_dropped)
{
    setup();
    snmp_varbind_t req_vb = make_null_varbind(OID_A, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "bogus", 6, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK_EQ_INT(response_len, 0);
}

UM_TEST(test_unsupported_version_dropped)
{
    setup();
    /* No security model is registered for version 99 -- deliberately an
     * incomplete message (no community/PDU follow) since the version
     * check must reject it before ever trying to parse further. */
    uint8_t packet[64];
    size_t cursor = sizeof(packet);
    ber_encode_integer(packet, sizeof(packet), &cursor, 99);
    size_t content_len = sizeof(packet) - cursor;
    ber_encode_container_header(packet, sizeof(packet), &cursor, BER_TAG_SEQUENCE, content_len);
    memmove(packet, packet + cursor, sizeof(packet) - cursor);
    size_t packet_len = sizeof(packet) - cursor;

    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK_EQ_INT(response_len, 0);
}

UM_TEST(test_getbulk_walks_and_hits_end_of_view)
{
    setup();
    uint32_t before_all[] = {1, 3, 6, 1, 4, 1, 11111, 0};
    snmp_varbind_t req_vb = make_null_varbind(before_all, 8);
    uint8_t packet[512];
    /* non-repeaters=0, max-repetitions=5 over a 3-object module: expect 3
     * real values then one endOfMibView, then early termination (see
     * snmp_pdu_getbulk.c's any_active early-stop) rather than padding out
     * to a full 5 repetitions. */
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_BULK_REQUEST, "public", 9, 0, 5, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.varbind_count, 4);
    UM_CHECK_EQ_INT(resp.varbinds[0].int_value, 100);
    UM_CHECK_EQ_INT(resp.varbinds[1].int_value, 0);
    UM_CHECK_EQ_INT(resp.varbinds[2].int_value, 300);
    UM_CHECK_EQ_INT(resp.varbinds[3].value_tag, SNMP_TAG_END_OF_MIB_VIEW);
}

UM_TEST(test_getbulk_non_repeaters)
{
    setup();
    uint32_t before_all[] = {1, 3, 6, 1, 4, 1, 11111, 0};
    snmp_varbind_t reqs[2];
    reqs[0] = make_null_varbind(before_all, 8); /* non-repeater -> resolves to A */
    reqs[1] = make_null_varbind(OID_A, 9);      /* repeater, starts at A -> rep 1 resolves to B */
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_BULK_REQUEST, "public", 10, 1, 1, reqs, 2, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.varbind_count, 2);
    UM_CHECK_EQ_INT(resp.varbinds[0].int_value, 100);
    UM_CHECK_EQ_INT(resp.varbinds[1].int_value, 0);
}

UM_TEST(test_getbulk_clamps_excess_repeating_columns)
{
    setup();
    /* 20 distinct repeating varbinds (all starting at the same "before
     * all objects" OID here, for simplicity -- the point is the *count*,
     * not that they're meaningfully different columns) against
     * snmp_pdu_getbulk.c's SNMP_MAX_REPEATING_COLUMNS=16 clamp. Must not
     * crash/overrun, and the response should reflect exactly 16 clamped
     * repeaters x 2 rounds, not 20 x 2. */
    uint32_t before_all[] = {1, 3, 6, 1, 4, 1, 11111, 0};
    snmp_varbind_t reqs[20];
    for (int i = 0; i < 20; i++) {
        reqs[i] = make_null_varbind(before_all, 8);
    }
    uint8_t packet[2048];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_BULK_REQUEST, "public", 11, 0, 2, reqs, 20, packet, sizeof(packet));
    UM_CHECK(packet_len > 0);

    uint8_t response[2048];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    /* 16 repeaters (clamped from 20) x 2 rounds: round 1 all resolve to
     * A (int_value=100), round 2 all resolve to B (int_value=0). */
    UM_CHECK_EQ_INT(resp.varbind_count, 32);
    for (int i = 0; i < 16; i++) {
        UM_CHECK_EQ_INT(resp.varbinds[i].int_value, 100);
    }
    for (int i = 16; i < 32; i++) {
        UM_CHECK_EQ_INT(resp.varbinds[i].int_value, 0);
    }
}

UM_TEST(test_get_table_cell_end_to_end)
{
    setup_with_table();
    uint32_t cell_oid[11];
    memcpy(cell_oid, TABLE_ENTRY, 9 * sizeof(uint32_t));
    cell_oid[9] = 1;
    cell_oid[10] = 1;
    snmp_varbind_t req_vb = make_null_varbind(cell_oid, 11);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_REQUEST, "public", 20, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, 0);
    UM_CHECK_EQ_INT(resp.varbinds[0].int_value, 10);
}

UM_TEST(test_getnext_walks_from_scalar_into_table_end_to_end)
{
    setup_with_table();
    snmp_varbind_t req_vb = make_null_varbind(OID_C, 9); /* last scalar */
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_NEXT_REQUEST, "public", 21, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.varbinds[0].oid_len, 11);
    for (int i = 0; i < 9; i++) {
        UM_CHECK_EQ_INT(resp.varbinds[0].oid[i], TABLE_ENTRY[i]);
    }
    UM_CHECK_EQ_INT(resp.varbinds[0].oid[9], 1); /* column 1 */
    UM_CHECK_EQ_INT(resp.varbinds[0].oid[10], 1); /* row 1 */
    UM_CHECK_EQ_INT(resp.varbinds[0].int_value, 10);
}

UM_TEST(test_getbulk_walks_full_table_end_to_end)
{
    setup_with_table();
    uint32_t before_table[9];
    memcpy(before_table, TABLE_ENTRY, 9 * sizeof(uint32_t));
    /* Start right at the table's own entry OID (no column/index yet). */
    snmp_varbind_t req_vb = make_null_varbind(before_table, 9);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_GET_BULK_REQUEST, "public", 22, 0, 5, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    /* row1(10), row2(20), then endOfMibView -- early-stop, not padded to 5. */
    UM_CHECK_EQ_INT(resp.varbind_count, 3);
    UM_CHECK_EQ_INT(resp.varbinds[0].int_value, 10);
    UM_CHECK_EQ_INT(resp.varbinds[1].int_value, 20);
    UM_CHECK_EQ_INT(resp.varbinds[2].value_tag, SNMP_TAG_END_OF_MIB_VIEW);
}

UM_TEST(test_set_table_cell_end_to_end)
{
    setup_with_table();
    uint32_t cell_oid[11];
    memcpy(cell_oid, TABLE_ENTRY, 9 * sizeof(uint32_t));
    cell_oid[9] = 1;
    cell_oid[10] = 2;
    snmp_varbind_t req_vb = make_int_varbind(cell_oid, 11, 99);
    uint8_t packet[512];
    size_t packet_len = build_request(SNMP_VERSION_V2C, SNMP_PDU_SET_REQUEST, "private", 23, 0, 0, &req_vb, 1, packet, sizeof(packet));
    uint8_t response[512];
    size_t response_len = snmp_message_process(packet, packet_len, response, sizeof(response));
    UM_CHECK(response_len > 0);
    UM_CHECK_EQ_INT(s_table_row2_value, 99);

    snmp_pdu_ctx_t resp;
    UM_CHECK(decode_message_any_tag(response, response_len, &resp));
    UM_CHECK_EQ_INT(resp.error_status, 0);
}

UM_TEST(test_v2c_trap_build_and_decode)
{
    uint32_t trap_oid[] = {1, 3, 6, 1, 4, 1, 99999, 3, 0, 1};
    snmp_varbind_t extra = make_int_varbind(OID_B, 9, 1);
    uint8_t packet[512];
    size_t len = snmp_trap_build(SNMP_VERSION_V2C, "public", 12345, trap_oid, 10, NULL, &extra, 1, packet, sizeof(packet));
    UM_CHECK(len > 0);

    snmp_pdu_ctx_t decoded;
    UM_CHECK(decode_message_any_tag(packet, len, &decoded));
    UM_CHECK_EQ_INT(decoded.pdu_tag, SNMP_PDU_TRAP_V2);
    UM_CHECK_EQ_INT(decoded.varbind_count, 3); /* sysUpTime.0, snmpTrapOID.0, extra */
    UM_CHECK_EQ_INT(decoded.varbinds[0].value_tag, SNMP_TAG_TIMETICKS);
    UM_CHECK_EQ_INT(decoded.varbinds[0].int_value, 12345);
    UM_CHECK_EQ_INT(decoded.varbinds[1].value_tag, BER_TAG_OID);
    UM_CHECK_EQ_INT(decoded.varbinds[2].int_value, 1);
}

UM_TEST(test_v1_trap_build_starts_with_correct_envelope)
{
    uint32_t enterprise_oid[] = {1, 3, 6, 1, 4, 1, 99999};
    uint8_t agent_addr[4] = {192, 168, 1, 50};
    snmp_varbind_t extra = make_int_varbind(OID_B, 9, 1);
    uint8_t packet[512];
    size_t len = snmp_trap_build(SNMP_VERSION_V1, "public", 999, enterprise_oid, 7, agent_addr, &extra, 1, packet, sizeof(packet));
    UM_CHECK(len > 0);

    /* v1 Trap-PDU has a genuinely different field shape than
     * decode_message_any_tag assumes (no request-id/error-status/error-
     * index), so just sanity-check the outer envelope + PDU tag by hand. */
    ber_tlv_t top;
    UM_CHECK_EQ_INT(ber_expect_tag(packet, len, 0, BER_TAG_SEQUENCE, &top), BER_OK);
    ber_tlv_t version_tlv;
    UM_CHECK_EQ_INT(ber_expect_tag(top.value, top.length, 1, BER_TAG_INTEGER, &version_tlv), BER_OK);
    int32_t version = -1;
    ber_decode_integer(&version_tlv, &version);
    UM_CHECK_EQ_INT(version, SNMP_VERSION_V1);
}

int main(void)
{
    UM_RUN(test_get_request_success);
    UM_RUN(test_get_request_v1_no_such_name);
    UM_RUN(test_get_request_v2c_no_such_object);
    UM_RUN(test_get_next_request_walks_to_first_object);
    UM_RUN(test_v2c_get_counter64_returns_value);
    UM_RUN(test_v1_get_counter64_returns_no_such_name);
    UM_RUN(test_v2c_getnext_reaches_counter64);
    UM_RUN(test_v1_getnext_walks_past_counter64_to_end_of_view);
    UM_RUN(test_getbulk_walks_through_counter64_v2c);
    UM_RUN(test_set_request_dropped_without_write_access);
    UM_RUN(test_set_request_success);
    UM_RUN(test_set_request_on_read_only_object);
    UM_RUN(test_unknown_community_dropped);
    UM_RUN(test_unsupported_version_dropped);
    UM_RUN(test_getbulk_walks_and_hits_end_of_view);
    UM_RUN(test_getbulk_non_repeaters);
    UM_RUN(test_getbulk_clamps_excess_repeating_columns);
    UM_RUN(test_get_table_cell_end_to_end);
    UM_RUN(test_getnext_walks_from_scalar_into_table_end_to_end);
    UM_RUN(test_getbulk_walks_full_table_end_to_end);
    UM_RUN(test_set_table_cell_end_to_end);
    UM_RUN(test_v2c_trap_build_and_decode);
    UM_RUN(test_v1_trap_build_starts_with_correct_envelope);
    return um_summary();
}
