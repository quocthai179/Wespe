#ifndef WESPE_BER_CODEC_H
#define WESPE_BER_CODEC_H

#include "ber_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * Decoding
 *
 * SNMP always uses definite-length BER (never indefinite-length / EOC
 * octets), which meaningfully simplifies the decoder: there is no 0x80
 * "indefinite length" special case to handle at all -- it's rejected as
 * BER_ERR_BAD_LENGTH.
 * ------------------------------------------------------------------- */

typedef struct {
    uint8_t        tag;    /* full identifier octet, e.g. 0x02, 0x30, 0xA0 */
    const uint8_t *value;  /* pointer into the original buffer, not owned */
    size_t         length; /* length of value in bytes */
    const uint8_t *next;   /* pointer just past this TLV, for iterating siblings */
} ber_tlv_t;

/* Parse one TLV element at `buf` (definite-length only). `depth` is the
 * current nesting depth of the caller and is checked against
 * BER_MAX_NEST_DEPTH before parsing; pass 0 at the top level and increment
 * by 1 each time you recurse into a constructed type's content. */
ber_status_t ber_decode_tlv(const uint8_t *buf, size_t len, unsigned depth, ber_tlv_t *out);

/* Convenience: decode a TLV and require it to have exactly `expect_tag`. */
ber_status_t ber_expect_tag(const uint8_t *buf, size_t len, unsigned depth, uint8_t expect_tag, ber_tlv_t *out);

ber_status_t ber_decode_integer(const ber_tlv_t *tlv, int32_t *out);
/* Counter32 / Gauge32 (Unsigned32) / TimeTicks all share this shape. */
ber_status_t ber_decode_unsigned(const ber_tlv_t *tlv, uint32_t *out);
/* Counter64 -- same shape, widened to 64 bits (up to 9 content bytes: 8
 * value bytes plus a possible leading 0x00 pad). */
ber_status_t ber_decode_unsigned64(const ber_tlv_t *tlv, uint64_t *out);
ber_status_t ber_decode_octet_string(const ber_tlv_t *tlv, uint8_t *out, size_t out_cap, size_t *out_len);
ber_status_t ber_decode_null(const ber_tlv_t *tlv);
ber_status_t ber_decode_oid(const ber_tlv_t *tlv, uint32_t *out, size_t out_cap, size_t *out_len);

/* ---------------------------------------------------------------------
 * Encoding
 *
 * All encoders build right-to-left into a caller-owned scratch buffer:
 * `*cursor` starts at some position <= cap and moves toward 0 as bytes are
 * prepended (mirroring mbedTLS's asn1write.c approach). This lets tag+
 * length be written *after* the content length is already known, with no
 * separate length-computation pass. The finished message occupies
 * [*cursor, original *cursor value in the outermost caller's frame).
 *
 * Callers typically initialize `size_t cursor = cap;` then call encoders
 * innermost-content-first, each one prepending further left.
 * ------------------------------------------------------------------- */

ber_status_t ber_encode_prepend_bytes(uint8_t *buf, size_t cap, size_t *cursor, const uint8_t *data, size_t len);
ber_status_t ber_encode_prepend_tlv_header(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag, size_t content_len);

ber_status_t ber_encode_integer(uint8_t *buf, size_t cap, size_t *cursor, int32_t value);
/* `tag` selects Counter32/Gauge32/TimeTicks/Unsigned32 -- same wire shape,
 * different application tag. */
ber_status_t ber_encode_unsigned_tagged(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag, uint32_t value);
/* Counter64, same shape widened to 64 bits -- `tag` is always
 * SNMP_TAG_COUNTER64 in practice, taken as a parameter for symmetry with
 * ber_encode_unsigned_tagged() rather than hardcoded. */
ber_status_t ber_encode_unsigned64_tagged(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag, uint64_t value);
ber_status_t ber_encode_octet_string(uint8_t *buf, size_t cap, size_t *cursor, const uint8_t *data, size_t len);
ber_status_t ber_encode_null(uint8_t *buf, size_t cap, size_t *cursor);
/* Encodes a zero-length value under an arbitrary tag -- used both for plain
 * NULL and for the v2c exception values (noSuchObject/noSuchInstance/
 * endOfMibView), which are wire-identical to NULL but for the tag byte. */
ber_status_t ber_encode_null_tagged(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag);
ber_status_t ber_encode_oid(uint8_t *buf, size_t cap, size_t *cursor, const uint32_t *oid, size_t oid_len);
/* Wraps whatever has already been prepended into [*cursor, content_end) in
 * a SEQUENCE (or other constructed-tag) TLV header. Caller passes the
 * number of content bytes already written. */
ber_status_t ber_encode_container_header(uint8_t *buf, size_t cap, size_t *cursor, uint8_t tag, size_t content_len);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_BER_CODEC_H */
