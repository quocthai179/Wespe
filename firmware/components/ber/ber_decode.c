/* ASN.1 BER decoder, scoped to exactly what SNMP needs: definite-length
 * encoding only, plus the handful of universal/application/context tags
 * used on the wire (RFC1157 / RFC3416). No ESP-IDF or FreeRTOS dependency
 * on purpose -- see host_tests/ for the native unit tests this enables. */
#include "ber_codec.h"
#include <string.h>
#include <limits.h>

/* Parses BER length octets starting at `buf` (i.e. the byte *after* the
 * tag). Rejects indefinite-length (0x80) since SNMP never produces it, and
 * caps long-form length to 4 octets -- anything requiring more than a
 * 32-bit length is never legitimate inside a UDP-bounded SNMP message. */
static ber_status_t decode_length(const uint8_t *buf, size_t len, size_t *out_len, size_t *header_len)
{
    if (len < 1) {
        return BER_ERR_TRUNCATED;
    }
    uint8_t first = buf[0];
    if ((first & 0x80u) == 0) {
        *out_len = first;
        *header_len = 1;
        return BER_OK;
    }
    uint8_t nbytes = (uint8_t)(first & 0x7Fu);
    if (nbytes == 0) {
        return BER_ERR_BAD_LENGTH; /* indefinite length, not used by SNMP */
    }
    if (nbytes > 4) {
        return BER_ERR_OVERFLOW;
    }
    if (len < (size_t)(1 + nbytes)) {
        return BER_ERR_TRUNCATED;
    }
    uint32_t value = 0;
    for (uint8_t i = 0; i < nbytes; i++) {
        value = (value << 8) | buf[1 + i];
    }
    *out_len = value;
    *header_len = (size_t)(1 + nbytes);
    return BER_OK;
}

ber_status_t ber_decode_tlv(const uint8_t *buf, size_t len, unsigned depth, ber_tlv_t *out)
{
    if (buf == NULL || out == NULL) {
        return BER_ERR_BAD_ARGS;
    }
    if (depth > BER_MAX_NEST_DEPTH) {
        return BER_ERR_DEPTH;
    }
    if (len < 2) {
        return BER_ERR_TRUNCATED; /* need at least a tag byte + one length byte */
    }

    uint8_t tag = buf[0];
    size_t content_len = 0;
    size_t len_header = 0;
    ber_status_t st = decode_length(buf + 1, len - 1, &content_len, &len_header);
    if (st != BER_OK) {
        return st;
    }

    size_t total_header = 1 + len_header;
    if (len - total_header < content_len) {
        return BER_ERR_TRUNCATED;
    }

    out->tag = tag;
    out->value = buf + total_header;
    out->length = content_len;
    out->next = buf + total_header + content_len;
    return BER_OK;
}

ber_status_t ber_expect_tag(const uint8_t *buf, size_t len, unsigned depth, uint8_t expect_tag, ber_tlv_t *out)
{
    ber_status_t st = ber_decode_tlv(buf, len, depth, out);
    if (st != BER_OK) {
        return st;
    }
    if (out->tag != expect_tag) {
        return BER_ERR_BAD_TAG;
    }
    return BER_OK;
}

ber_status_t ber_decode_integer(const ber_tlv_t *tlv, int32_t *out)
{
    if (tlv == NULL || out == NULL) {
        return BER_ERR_BAD_ARGS;
    }
    if (tlv->tag != BER_TAG_INTEGER) {
        return BER_ERR_BAD_TAG;
    }
    if (tlv->length == 0 || tlv->length > 4) {
        return BER_ERR_OVERFLOW;
    }
    /* Sign-extend from the leading byte, then fold in the rest -- standard
     * two's-complement BER INTEGER decoding. */
    int32_t value = (tlv->value[0] & 0x80u) ? -1 : 0;
    for (size_t i = 0; i < tlv->length; i++) {
        value = (int32_t)(((uint32_t)value << 8) | tlv->value[i]);
    }
    *out = value;
    return BER_OK;
}

ber_status_t ber_decode_unsigned(const ber_tlv_t *tlv, uint32_t *out)
{
    if (tlv == NULL || out == NULL) {
        return BER_ERR_BAD_ARGS;
    }
    switch (tlv->tag) {
        case SNMP_TAG_COUNTER32:
        case SNMP_TAG_GAUGE32:
        case SNMP_TAG_TIMETICKS:
            break;
        default:
            return BER_ERR_BAD_TAG;
    }
    /* Up to 5 content bytes are legal: BER allows a leading 0x00 pad byte
     * to keep an unsigned value from being misread as negative. */
    if (tlv->length == 0 || tlv->length > 5) {
        return BER_ERR_OVERFLOW;
    }
    uint32_t value = 0;
    for (size_t i = 0; i < tlv->length; i++) {
        value = (value << 8) | tlv->value[i];
    }
    *out = value;
    return BER_OK;
}

ber_status_t ber_decode_octet_string(const ber_tlv_t *tlv, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (tlv == NULL || out == NULL || out_len == NULL) {
        return BER_ERR_BAD_ARGS;
    }
    if (tlv->tag != BER_TAG_OCTET_STRING) {
        return BER_ERR_BAD_TAG;
    }
    if (tlv->length > out_cap) {
        return BER_ERR_OVERFLOW;
    }
    memcpy(out, tlv->value, tlv->length);
    *out_len = tlv->length;
    return BER_OK;
}

ber_status_t ber_decode_null(const ber_tlv_t *tlv)
{
    if (tlv == NULL) {
        return BER_ERR_BAD_ARGS;
    }
    if (tlv->tag != BER_TAG_NULL) {
        return BER_ERR_BAD_TAG;
    }
    if (tlv->length != 0) {
        return BER_ERR_BAD_LENGTH;
    }
    return BER_OK;
}

ber_status_t ber_decode_oid(const ber_tlv_t *tlv, uint32_t *out, size_t out_cap, size_t *out_len)
{
    if (tlv == NULL || out == NULL || out_len == NULL) {
        return BER_ERR_BAD_ARGS;
    }
    if (tlv->tag != BER_TAG_OID) {
        return BER_ERR_BAD_TAG;
    }
    if (tlv->length == 0) {
        return BER_ERR_BAD_LENGTH;
    }
    if (out_cap < 2) {
        return BER_ERR_OVERFLOW;
    }

    const uint8_t *p = tlv->value;
    const uint8_t *end = tlv->value + tlv->length;
    size_t n = 0;

    /* First byte packs the first two arcs as (arc0 * 40) + arc1, per
     * X.690 8.19.4 (SNMP OIDs always start with 1.3 or 2.x, so arc0 is
     * always 0-2 and this never overflows a uint32). */
    uint8_t first = *p++;
    out[n++] = first / 40u;
    out[n++] = first % 40u;

    while (p < end) {
        uint32_t arc = 0;
        int got_final_byte = 0;
        while (p < end) {
            uint8_t b = *p++;
            if (arc > (UINT32_MAX >> 7)) {
                return BER_ERR_OVERFLOW; /* next shift would overflow */
            }
            arc = (arc << 7) | (uint32_t)(b & 0x7Fu);
            if ((b & 0x80u) == 0) {
                got_final_byte = 1;
                break;
            }
        }
        if (!got_final_byte) {
            return BER_ERR_TRUNCATED; /* continuation bit set on the last byte */
        }
        if (n >= out_cap) {
            return BER_ERR_OVERFLOW;
        }
        out[n++] = arc;
    }

    *out_len = n;
    return BER_OK;
}
