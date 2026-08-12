#include "unity_mini.h"
#include "ber_codec.h"

UM_TEST(test_decode_short_form_length)
{
    /* INTEGER 5 -> 02 01 05 */
    uint8_t buf[] = {0x02, 0x01, 0x05};
    ber_tlv_t tlv;
    ber_status_t st = ber_decode_tlv(buf, sizeof(buf), 0, &tlv);
    UM_CHECK_EQ_INT(st, BER_OK);
    UM_CHECK_EQ_INT(tlv.tag, BER_TAG_INTEGER);
    UM_CHECK_EQ_INT(tlv.length, 1);
    UM_CHECK_EQ_INT(tlv.value[0], 5);
    UM_CHECK(tlv.next == buf + 3);
}

UM_TEST(test_decode_long_form_length)
{
    /* OCTET STRING of 200 bytes: 04 81 C8 <200 bytes> */
    uint8_t buf[3 + 200];
    buf[0] = BER_TAG_OCTET_STRING;
    buf[1] = 0x81;
    buf[2] = 200;
    for (int i = 0; i < 200; i++) {
        buf[3 + i] = (uint8_t)i;
    }
    ber_tlv_t tlv;
    ber_status_t st = ber_decode_tlv(buf, sizeof(buf), 0, &tlv);
    UM_CHECK_EQ_INT(st, BER_OK);
    UM_CHECK_EQ_INT(tlv.length, 200);
    UM_CHECK_EQ_INT(tlv.value[199], 199);
}

UM_TEST(test_decode_rejects_indefinite_length)
{
    /* SNMP never uses indefinite length -- 0x80 alone must be rejected. */
    uint8_t buf[] = {BER_TAG_SEQUENCE, 0x80, 0x00, 0x00};
    ber_tlv_t tlv;
    ber_status_t st = ber_decode_tlv(buf, sizeof(buf), 0, &tlv);
    UM_CHECK_EQ_INT(st, BER_ERR_BAD_LENGTH);
}

UM_TEST(test_decode_rejects_truncated_buffer)
{
    /* Declares 10 bytes of content but only 2 are actually present. */
    uint8_t buf[] = {BER_TAG_OCTET_STRING, 10, 0x01, 0x02};
    ber_tlv_t tlv;
    ber_status_t st = ber_decode_tlv(buf, sizeof(buf), 0, &tlv);
    UM_CHECK_EQ_INT(st, BER_ERR_TRUNCATED);
}

UM_TEST(test_decode_rejects_empty_buffer)
{
    ber_tlv_t tlv;
    ber_status_t st = ber_decode_tlv(NULL, 0, 0, &tlv);
    UM_CHECK(st != BER_OK);
}

UM_TEST(test_decode_rejects_excess_nesting_depth)
{
    uint8_t buf[] = {BER_TAG_SEQUENCE, 0x00};
    ber_tlv_t tlv;
    ber_status_t st = ber_decode_tlv(buf, sizeof(buf), BER_MAX_NEST_DEPTH + 1, &tlv);
    UM_CHECK_EQ_INT(st, BER_ERR_DEPTH);
}

UM_TEST(test_decode_integer_positive)
{
    uint8_t buf[] = {0x02, 0x02, 0x01, 0x00}; /* INTEGER 256 */
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    int32_t v = 0;
    UM_CHECK_EQ_INT(ber_decode_integer(&tlv, &v), BER_OK);
    UM_CHECK_EQ_INT(v, 256);
}

UM_TEST(test_decode_integer_negative)
{
    uint8_t buf[] = {0x02, 0x01, 0xFF}; /* INTEGER -1 */
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    int32_t v = 0;
    UM_CHECK_EQ_INT(ber_decode_integer(&tlv, &v), BER_OK);
    UM_CHECK_EQ_INT(v, -1);
}

UM_TEST(test_decode_integer_wrong_tag)
{
    uint8_t buf[] = {BER_TAG_NULL, 0x00};
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    int32_t v = 0;
    UM_CHECK_EQ_INT(ber_decode_integer(&tlv, &v), BER_ERR_BAD_TAG);
}

UM_TEST(test_decode_unsigned_gauge32)
{
    /* Gauge32 value 0xFFFFFFFF encoded with a leading pad byte: 42 05 00 FF FF FF FF */
    uint8_t buf[] = {SNMP_TAG_GAUGE32, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    uint32_t v = 0;
    UM_CHECK_EQ_INT(ber_decode_unsigned(&tlv, &v), BER_OK);
    UM_CHECK(v == 0xFFFFFFFFu);
}

UM_TEST(test_decode_octet_string)
{
    uint8_t buf[] = {BER_TAG_OCTET_STRING, 5, 'h', 'e', 'l', 'l', 'o'};
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    uint8_t out[16];
    size_t out_len = 0;
    UM_CHECK_EQ_INT(ber_decode_octet_string(&tlv, out, sizeof(out), &out_len), BER_OK);
    UM_CHECK_EQ_INT(out_len, 5);
    UM_CHECK_EQ_MEM(out, "hello", 5);
}

UM_TEST(test_decode_octet_string_overflow)
{
    uint8_t buf[] = {BER_TAG_OCTET_STRING, 5, 'h', 'e', 'l', 'l', 'o'};
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    uint8_t out[2];
    size_t out_len = 0;
    UM_CHECK_EQ_INT(ber_decode_octet_string(&tlv, out, sizeof(out), &out_len), BER_ERR_OVERFLOW);
}

UM_TEST(test_decode_null)
{
    uint8_t buf[] = {BER_TAG_NULL, 0x00};
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    UM_CHECK_EQ_INT(ber_decode_null(&tlv), BER_OK);
}

UM_TEST(test_decode_oid_sysdescr)
{
    /* sysDescr.0 = 1.3.6.1.2.1.1.1.0 -> 06 08 2B 06 01 02 01 01 01 00
     * (well-known encoding: this is the textbook golden vector for OID BER.) */
    uint8_t buf[] = {BER_TAG_OID, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    uint32_t oid[16];
    size_t oid_len = 0;
    UM_CHECK_EQ_INT(ber_decode_oid(&tlv, oid, 16, &oid_len), BER_OK);
    uint32_t expect[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    UM_CHECK_EQ_INT(oid_len, 9);
    for (int i = 0; i < 9; i++) {
        UM_CHECK_EQ_INT(oid[i], expect[i]);
    }
}

UM_TEST(test_decode_oid_multibyte_arc)
{
    /* Enterprise arc 99999 = 0x0186 9F, base-128: 99999 = 0b11000011010011111
     * split into 7-bit groups (MSB first): 0000110 0000110 1001111
     *   -> wait, do it properly by trusting the round-trip encode test
     *      instead; here just check a known 2-byte VLQ: arc 300 -> 82 2C. */
    uint8_t buf[] = {BER_TAG_OID, 0x03, 0x2B, 0x82, 0x2C}; /* 1.3.300 */
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    uint32_t oid[8];
    size_t oid_len = 0;
    UM_CHECK_EQ_INT(ber_decode_oid(&tlv, oid, 8, &oid_len), BER_OK);
    UM_CHECK_EQ_INT(oid_len, 3);
    UM_CHECK_EQ_INT(oid[0], 1);
    UM_CHECK_EQ_INT(oid[1], 3);
    UM_CHECK_EQ_INT(oid[2], 300);
}

UM_TEST(test_decode_oid_truncated_continuation)
{
    /* Last byte still has its continuation bit set -- malformed. */
    uint8_t buf[] = {BER_TAG_OID, 0x02, 0x2B, 0x82};
    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf, sizeof(buf), 0, &tlv), BER_OK);
    uint32_t oid[8];
    size_t oid_len = 0;
    UM_CHECK_EQ_INT(ber_decode_oid(&tlv, oid, 8, &oid_len), BER_ERR_TRUNCATED);
}

int main(void)
{
    UM_RUN(test_decode_short_form_length);
    UM_RUN(test_decode_long_form_length);
    UM_RUN(test_decode_rejects_indefinite_length);
    UM_RUN(test_decode_rejects_truncated_buffer);
    UM_RUN(test_decode_rejects_empty_buffer);
    UM_RUN(test_decode_rejects_excess_nesting_depth);
    UM_RUN(test_decode_integer_positive);
    UM_RUN(test_decode_integer_negative);
    UM_RUN(test_decode_integer_wrong_tag);
    UM_RUN(test_decode_unsigned_gauge32);
    UM_RUN(test_decode_octet_string);
    UM_RUN(test_decode_octet_string_overflow);
    UM_RUN(test_decode_null);
    UM_RUN(test_decode_oid_sysdescr);
    UM_RUN(test_decode_oid_multibyte_arc);
    UM_RUN(test_decode_oid_truncated_continuation);
    return um_summary();
}
