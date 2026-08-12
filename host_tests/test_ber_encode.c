#include "unity_mini.h"
#include "ber_codec.h"

UM_TEST(test_encode_integer_zero)
{
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_integer(buf, sizeof(buf), &cursor, 0), BER_OK);
    uint8_t expect[] = {0x02, 0x01, 0x00};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_integer_negative_one)
{
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_integer(buf, sizeof(buf), &cursor, -1), BER_OK);
    uint8_t expect[] = {0x02, 0x01, 0xFF};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_integer_256_needs_two_bytes)
{
    /* 256 = 0x0100; a naive single low-byte encoding (0x00) would be wrong
     * (and would also look like the value 0), so this must be 2 bytes. */
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_integer(buf, sizeof(buf), &cursor, 256), BER_OK);
    uint8_t expect[] = {0x02, 0x02, 0x01, 0x00};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_integer_127_stays_one_byte)
{
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_integer(buf, sizeof(buf), &cursor, 127), BER_OK);
    uint8_t expect[] = {0x02, 0x01, 0x7F};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_integer_128_needs_pad_byte)
{
    /* 128 = 0x80; without a leading 0x00 pad this would decode as -128. */
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_integer(buf, sizeof(buf), &cursor, 128), BER_OK);
    uint8_t expect[] = {0x02, 0x02, 0x00, 0x80};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_unsigned_gauge32_max)
{
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_unsigned_tagged(buf, sizeof(buf), &cursor, SNMP_TAG_GAUGE32, 0xFFFFFFFFu), BER_OK);
    uint8_t expect[] = {SNMP_TAG_GAUGE32, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_unsigned_zero)
{
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_unsigned_tagged(buf, sizeof(buf), &cursor, SNMP_TAG_TIMETICKS, 0), BER_OK);
    uint8_t expect[] = {SNMP_TAG_TIMETICKS, 0x01, 0x00};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_octet_string)
{
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_octet_string(buf, sizeof(buf), &cursor, (const uint8_t *)"hi", 2), BER_OK);
    uint8_t expect[] = {BER_TAG_OCTET_STRING, 0x02, 'h', 'i'};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_octet_string_long_form_length)
{
    uint8_t data[200];
    for (int i = 0; i < 200; i++) data[i] = (uint8_t)i;
    uint8_t buf[256];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_octet_string(buf, sizeof(buf), &cursor, data, sizeof(data)), BER_OK);
    UM_CHECK_EQ_INT(buf[cursor], BER_TAG_OCTET_STRING);
    UM_CHECK_EQ_INT(buf[cursor + 1], 0x81);
    UM_CHECK_EQ_INT(buf[cursor + 2], 200);
    UM_CHECK_EQ_MEM(buf + cursor + 3, data, 200);
}

UM_TEST(test_encode_null)
{
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_null(buf, sizeof(buf), &cursor), BER_OK);
    uint8_t expect[] = {BER_TAG_NULL, 0x00};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_exception_no_such_object)
{
    uint8_t buf[16];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_null_tagged(buf, sizeof(buf), &cursor, SNMP_TAG_NO_SUCH_OBJECT), BER_OK);
    uint8_t expect[] = {SNMP_TAG_NO_SUCH_OBJECT, 0x00};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_oid_sysdescr_matches_golden_vector)
{
    uint32_t oid[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    uint8_t buf[32];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_oid(buf, sizeof(buf), &cursor, oid, 9), BER_OK);
    uint8_t expect[] = {BER_TAG_OID, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_oid_multibyte_arc)
{
    uint32_t oid[] = {1, 3, 300};
    uint8_t buf[32];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_oid(buf, sizeof(buf), &cursor, oid, 3), BER_OK);
    uint8_t expect[] = {BER_TAG_OID, 0x03, 0x2B, 0x82, 0x2C};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_oid_private_enterprise_arc)
{
    /* wespeMIB = 1.3.6.1.4.1.99999 -- exercises a large multi-byte arc
     * (99999) end-to-end via round trip since the exact byte pattern is
     * less well-known than the sysDescr golden vector. */
    uint32_t oid[] = {1, 3, 6, 1, 4, 1, 99999};
    uint8_t buf[32];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_oid(buf, sizeof(buf), &cursor, oid, 7), BER_OK);

    ber_tlv_t tlv;
    UM_CHECK_EQ_INT(ber_decode_tlv(buf + cursor, sizeof(buf) - cursor, 0, &tlv), BER_OK);
    uint32_t decoded[16];
    size_t decoded_len = 0;
    UM_CHECK_EQ_INT(ber_decode_oid(&tlv, decoded, 16, &decoded_len), BER_OK);
    UM_CHECK_EQ_INT(decoded_len, 7);
    for (int i = 0; i < 7; i++) {
        UM_CHECK_EQ_INT(decoded[i], oid[i]);
    }
}

UM_TEST(test_encode_container_wraps_prior_content)
{
    /* Build SEQUENCE { INTEGER 5 } by hand and confirm the wrapper header
     * is correct given the already-encoded inner content. */
    uint8_t buf[32];
    size_t cursor = sizeof(buf);
    UM_CHECK_EQ_INT(ber_encode_integer(buf, sizeof(buf), &cursor, 5), BER_OK);
    size_t content_len = sizeof(buf) - cursor;
    UM_CHECK_EQ_INT(ber_encode_container_header(buf, sizeof(buf), &cursor, BER_TAG_SEQUENCE, content_len), BER_OK);
    uint8_t expect[] = {BER_TAG_SEQUENCE, 0x03, 0x02, 0x01, 0x05};
    UM_CHECK_EQ_INT(sizeof(buf) - cursor, sizeof(expect));
    UM_CHECK_EQ_MEM(buf + cursor, expect, sizeof(expect));
}

UM_TEST(test_encode_overflow_when_buffer_too_small)
{
    uint8_t buf[2];
    size_t cursor = sizeof(buf);
    ber_status_t st = ber_encode_octet_string(buf, sizeof(buf), &cursor, (const uint8_t *)"toolong", 7);
    UM_CHECK_EQ_INT(st, BER_ERR_OVERFLOW);
}

/* Round-trip fuzz-ish sweep: every int32 in a representative set encodes
 * then decodes back to the same value. */
UM_TEST(test_integer_round_trip_sweep)
{
    int32_t values[] = {0, 1, -1, 127, -128, 128, -129, 255, -256, 32767, -32768,
                         32768, 65535, -65536, 1000000, -1000000, 2147483647, -2147483647 - 1};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        uint8_t buf[16];
        size_t cursor = sizeof(buf);
        UM_CHECK_EQ_INT(ber_encode_integer(buf, sizeof(buf), &cursor, values[i]), BER_OK);
        ber_tlv_t tlv;
        UM_CHECK_EQ_INT(ber_decode_tlv(buf + cursor, sizeof(buf) - cursor, 0, &tlv), BER_OK);
        int32_t out = 0;
        UM_CHECK_EQ_INT(ber_decode_integer(&tlv, &out), BER_OK);
        UM_CHECK_EQ_INT(out, values[i]);
    }
}

UM_TEST(test_unsigned_round_trip_sweep)
{
    uint32_t values[] = {0, 1, 127, 128, 255, 256, 65535, 65536, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        uint8_t buf[16];
        size_t cursor = sizeof(buf);
        UM_CHECK_EQ_INT(ber_encode_unsigned_tagged(buf, sizeof(buf), &cursor, SNMP_TAG_COUNTER32, values[i]), BER_OK);
        ber_tlv_t tlv;
        UM_CHECK_EQ_INT(ber_decode_tlv(buf + cursor, sizeof(buf) - cursor, 0, &tlv), BER_OK);
        uint32_t out = 0;
        UM_CHECK_EQ_INT(ber_decode_unsigned(&tlv, &out), BER_OK);
        UM_CHECK(out == values[i]);
    }
}

int main(void)
{
    UM_RUN(test_encode_integer_zero);
    UM_RUN(test_encode_integer_negative_one);
    UM_RUN(test_encode_integer_256_needs_two_bytes);
    UM_RUN(test_encode_integer_127_stays_one_byte);
    UM_RUN(test_encode_integer_128_needs_pad_byte);
    UM_RUN(test_encode_unsigned_gauge32_max);
    UM_RUN(test_encode_unsigned_zero);
    UM_RUN(test_encode_octet_string);
    UM_RUN(test_encode_octet_string_long_form_length);
    UM_RUN(test_encode_null);
    UM_RUN(test_encode_exception_no_such_object);
    UM_RUN(test_encode_oid_sysdescr_matches_golden_vector);
    UM_RUN(test_encode_oid_multibyte_arc);
    UM_RUN(test_encode_oid_private_enterprise_arc);
    UM_RUN(test_encode_container_wraps_prior_content);
    UM_RUN(test_encode_overflow_when_buffer_too_small);
    UM_RUN(test_integer_round_trip_sweep);
    UM_RUN(test_unsigned_round_trip_sweep);
    return um_summary();
}
