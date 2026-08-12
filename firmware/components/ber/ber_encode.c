/* ASN.1 BER encoder. Builds each TLV right-to-left into a caller-owned
 * scratch buffer (the same trick mbedTLS's asn1write.c uses): content is
 * written first, then tag+length are prepended once the content length is
 * known, avoiding a separate length-computation pass. No ESP-IDF/FreeRTOS
 * dependency -- see host_tests/ for native unit tests. */
#include "ber_codec.h"
#include <string.h>

static ber_status_t prepend_byte(uint8_t *buf, size_t cap, size_t *cursor, uint8_t b)
{
    (void)cap;
    if (*cursor < 1) {
        return BER_ERR_OVERFLOW;
    }
    buf[--(*cursor)] = b;
    return BER_OK;
}

ber_status_t ber_encode_prepend_bytes(uint8_t *buf, size_t cap, size_t *cursor, const uint8_t *data, size_t len)
{
    if (buf == NULL || cursor == NULL || (data == NULL && len > 0)) {
        return BER_ERR_BAD_ARGS;
    }
    (void)cap;
    if (*cursor < len) {
        return BER_ERR_OVERFLOW;
    }
    *cursor -= len;
    if (len > 0) {
        memcpy(buf + *cursor, data, len);
    }
    return BER_OK;
}

ber_status_t ber_encode_prepend_tlv_header(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag, size_t content_len)
{
    if (buf == NULL || cursor == NULL) {
        return BER_ERR_BAD_ARGS;
    }

    if (content_len <= 0x7Fu) {
        ber_status_t st = prepend_byte(buf, cap, cursor, (uint8_t)content_len);
        if (st != BER_OK) {
            return st;
        }
    } else {
        /* Long form: 0x80|n followed by n big-endian length octets. Collect
         * the value little-endian first (LSB at index 0), then prepend
         * index 0 first -- since prepending is back-to-front, the first
         * call ends up rightmost (adjacent to the content, i.e. the LSB
         * position of a big-endian field) and the last call ends up
         * leftmost (the MSB position), producing correct big-endian order. */
        uint8_t len_bytes[4];
        uint8_t n = 0;
        size_t tmp = content_len;
        while (tmp > 0) {
            len_bytes[n++] = (uint8_t)(tmp & 0xFFu);
            tmp >>= 8;
        }
        for (uint8_t i = 0; i < n; i++) {
            ber_status_t st = prepend_byte(buf, cap, cursor, len_bytes[i]);
            if (st != BER_OK) {
                return st;
            }
        }
        ber_status_t st = prepend_byte(buf, cap, cursor, (uint8_t)(0x80u | n));
        if (st != BER_OK) {
            return st;
        }
    }
    return prepend_byte(buf, cap, cursor, tag);
}

ber_status_t ber_encode_container_header(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag, size_t content_len)
{
    return ber_encode_prepend_tlv_header(buf, cap, cursor, tag, content_len);
}

ber_status_t ber_encode_integer(uint8_t *buf, size_t cap, size_t *cursor, int32_t value)
{
    uint8_t raw[4];
    uint32_t u = (uint32_t)value;
    raw[0] = (uint8_t)(u >> 24);
    raw[1] = (uint8_t)(u >> 16);
    raw[2] = (uint8_t)(u >> 8);
    raw[3] = (uint8_t)(u);

    /* Minimal two's-complement encoding: strip redundant leading 0x00 (if
     * the value stays non-negative) or 0xFF (if it stays negative) bytes,
     * stopping the instant trimming further would flip the represented
     * sign -- the standard BER INTEGER minimality rule. */
    size_t start = 0;
    while (start < 3) {
        uint8_t b = raw[start];
        uint8_t next = raw[start + 1];
        if (b == 0x00u && (next & 0x80u) == 0) {
            start++;
            continue;
        }
        if (b == 0xFFu && (next & 0x80u) != 0) {
            start++;
            continue;
        }
        break;
    }
    size_t content_len = 4 - start;
    ber_status_t st = ber_encode_prepend_bytes(buf, cap, cursor, raw + start, content_len);
    if (st != BER_OK) {
        return st;
    }
    return ber_encode_prepend_tlv_header(buf, cap, cursor, BER_TAG_INTEGER, content_len);
}

ber_status_t ber_encode_unsigned_tagged(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag, uint32_t value)
{
    uint8_t raw[5];
    raw[0] = 0x00u; /* explicit pad candidate */
    raw[1] = (uint8_t)(value >> 24);
    raw[2] = (uint8_t)(value >> 16);
    raw[3] = (uint8_t)(value >> 8);
    raw[4] = (uint8_t)(value);

    size_t start = 1;
    while (start < 4 && raw[start] == 0x00u && (raw[start + 1] & 0x80u) == 0) {
        start++;
    }
    /* If the most-significant retained byte's high bit is set, restore the
     * pad byte so the value isn't misread as a negative two's-complement
     * INTEGER by a strict decoder. */
    if ((raw[start] & 0x80u) != 0) {
        start--;
    }

    size_t content_len = 5 - start;
    ber_status_t st = ber_encode_prepend_bytes(buf, cap, cursor, raw + start, content_len);
    if (st != BER_OK) {
        return st;
    }
    return ber_encode_prepend_tlv_header(buf, cap, cursor, tag, content_len);
}

ber_status_t ber_encode_octet_string(uint8_t *buf, size_t cap, size_t *cursor, const uint8_t *data, size_t len)
{
    ber_status_t st = ber_encode_prepend_bytes(buf, cap, cursor, data, len);
    if (st != BER_OK) {
        return st;
    }
    return ber_encode_prepend_tlv_header(buf, cap, cursor, BER_TAG_OCTET_STRING, len);
}

ber_status_t ber_encode_null(uint8_t *buf, size_t cap, size_t *cursor)
{
    return ber_encode_prepend_tlv_header(buf, cap, cursor, BER_TAG_NULL, 0);
}

ber_status_t ber_encode_null_tagged(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag)
{
    return ber_encode_prepend_tlv_header(buf, cap, cursor, tag, 0);
}

ber_status_t ber_encode_oid(uint8_t *buf, size_t cap, size_t *cursor, const uint32_t *oid, size_t oid_len)
{
    if (buf == NULL || cursor == NULL || oid == NULL) {
        return BER_ERR_BAD_ARGS;
    }
    if (oid_len < 2) {
        return BER_ERR_BAD_LENGTH;
    }
    if (oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40)) {
        return BER_ERR_OVERFLOW; /* not representable in the single combined first byte */
    }

    size_t start_cursor = *cursor;

    /* Encode arcs from last to first so the whole OID content ends up in
     * the right order once all the per-arc prepends are done (each arc's
     * bytes get pushed further left than the ones already written for
     * later arcs). */
    for (size_t i = oid_len; i-- > 2;) {
        uint32_t arc = oid[i];
        uint8_t tmp[5];
        uint8_t n = 0;
        tmp[n++] = (uint8_t)(arc & 0x7Fu);
        arc >>= 7;
        while (arc > 0) {
            tmp[n++] = (uint8_t)((arc & 0x7Fu) | 0x80u);
            arc >>= 7;
        }
        /* tmp[0] is the terminal (no continuation bit) least-significant
         * group; tmp[n-1] is the most-significant group. Prepend ascending
         * (tmp[0] first) so tmp[0] ends up rightmost -- adjacent to
         * whatever follows this arc -- and tmp[n-1] ends up leftmost,
         * yielding the correct MSB-first-with-continuation-bits wire
         * order. */
        for (uint8_t k = 0; k < n; k++) {
            ber_status_t st = prepend_byte(buf, cap, cursor, tmp[k]);
            if (st != BER_OK) {
                return st;
            }
        }
    }

    uint8_t first_byte = (uint8_t)(oid[0] * 40u + oid[1]);
    ber_status_t st = prepend_byte(buf, cap, cursor, first_byte);
    if (st != BER_OK) {
        return st;
    }

    size_t content_len = start_cursor - *cursor;
    return ber_encode_prepend_tlv_header(buf, cap, cursor, BER_TAG_OID, content_len);
}
