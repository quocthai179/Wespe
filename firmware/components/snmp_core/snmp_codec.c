/* Shared PDU/varbind encode-decode logic -- the inner-PDU grammar common
 * to every security model. See snmp_codec.h for why this split matters
 * for SNMPv3-readiness. */
#include "snmp_codec.h"
#include <string.h>

ber_status_t snmp_decode_value(const ber_tlv_t *tlv, snmp_varbind_t *vb)
{
    if (tlv == NULL || vb == NULL) {
        return BER_ERR_BAD_ARGS;
    }
    vb->value_tag = tlv->tag;

    switch (tlv->tag) {
        case BER_TAG_INTEGER:
            return ber_decode_integer(tlv, &vb->int_value);
        case BER_TAG_OCTET_STRING:
            return ber_decode_octet_string(tlv, vb->octets, sizeof(vb->octets), &vb->octets_len);
        case BER_TAG_NULL:
            return ber_decode_null(tlv);
        case BER_TAG_OID:
            return ber_decode_oid(tlv, vb->oid_value, BER_MAX_OID_LEN, &vb->oid_value_len);
        case SNMP_TAG_COUNTER32:
        case SNMP_TAG_GAUGE32:
        case SNMP_TAG_TIMETICKS: {
            uint32_t u = 0;
            ber_status_t st = ber_decode_unsigned(tlv, &u);
            vb->int_value = (int32_t)u;
            return st;
        }
        case SNMP_TAG_COUNTER64:
            return ber_decode_unsigned64(tlv, &vb->counter64_value);
        case SNMP_TAG_IPADDRESS:
        case SNMP_TAG_OPAQUE:
            /* Byte-string-shaped application types, carried like an OCTET
             * STRING but under their own tag -- no dedicated decoder
             * needed beyond a bounds-checked raw copy. */
            if (tlv->length > sizeof(vb->octets)) {
                return BER_ERR_OVERFLOW;
            }
            memcpy(vb->octets, tlv->value, tlv->length);
            vb->octets_len = tlv->length;
            return BER_OK;
        case SNMP_TAG_NO_SUCH_OBJECT:
        case SNMP_TAG_NO_SUCH_INSTANCE:
        case SNMP_TAG_END_OF_MIB_VIEW:
            if (tlv->length != 0) {
                return BER_ERR_BAD_LENGTH;
            }
            return BER_OK;
        default:
            return BER_ERR_BAD_TAG;
    }
}

ber_status_t snmp_encode_value(uint8_t *buf, size_t cap, size_t *cursor, const snmp_varbind_t *vb)
{
    switch (vb->value_tag) {
        case BER_TAG_INTEGER:
            return ber_encode_integer(buf, cap, cursor, vb->int_value);
        case BER_TAG_OCTET_STRING:
            return ber_encode_octet_string(buf, cap, cursor, vb->octets, vb->octets_len);
        case BER_TAG_NULL:
            return ber_encode_null(buf, cap, cursor);
        case BER_TAG_OID:
            return ber_encode_oid(buf, cap, cursor, vb->oid_value, vb->oid_value_len);
        case SNMP_TAG_COUNTER32:
        case SNMP_TAG_GAUGE32:
        case SNMP_TAG_TIMETICKS:
            return ber_encode_unsigned_tagged(buf, cap, cursor, vb->value_tag, (uint32_t)vb->int_value);
        case SNMP_TAG_COUNTER64:
            return ber_encode_unsigned64_tagged(buf, cap, cursor, vb->value_tag, vb->counter64_value);
        case SNMP_TAG_NO_SUCH_OBJECT:
        case SNMP_TAG_NO_SUCH_INSTANCE:
        case SNMP_TAG_END_OF_MIB_VIEW:
            return ber_encode_null_tagged(buf, cap, cursor, vb->value_tag);
        case SNMP_TAG_IPADDRESS:
        case SNMP_TAG_OPAQUE: {
            ber_status_t st = ber_encode_prepend_bytes(buf, cap, cursor, vb->octets, vb->octets_len);
            if (st != BER_OK) {
                return st;
            }
            return ber_encode_prepend_tlv_header(buf, cap, cursor, vb->value_tag, vb->octets_len);
        }
        default:
            return BER_ERR_BAD_TAG;
    }
}

ber_status_t snmp_encode_varbind(uint8_t *buf, size_t cap, size_t *cursor, const snmp_varbind_t *vb)
{
    size_t start = *cursor;
    ber_status_t st = snmp_encode_value(buf, cap, cursor, vb);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_oid(buf, cap, cursor, vb->oid, vb->oid_len);
    if (st != BER_OK) {
        return st;
    }
    size_t content_len = start - *cursor;
    return ber_encode_container_header(buf, cap, cursor, BER_TAG_SEQUENCE, content_len);
}

ber_status_t snmp_encode_varbind_list(uint8_t *buf, size_t cap, size_t *cursor, const snmp_varbind_t *varbinds, size_t count)
{
    size_t start = *cursor;
    /* Encode last-to-first: the first prepend call ends up rightmost, so
     * processing varbinds[count-1] first and varbinds[0] last reproduces
     * the original left-to-right order in the finished buffer (same
     * backward-building convention used throughout ber_encode.c). */
    for (size_t i = count; i-- > 0;) {
        ber_status_t st = snmp_encode_varbind(buf, cap, cursor, &varbinds[i]);
        if (st != BER_OK) {
            return st;
        }
    }
    size_t content_len = start - *cursor;
    return ber_encode_container_header(buf, cap, cursor, BER_TAG_SEQUENCE, content_len);
}

static ber_status_t decode_varbind_from_seq_tlv(const ber_tlv_t *seq, unsigned depth, snmp_varbind_t *vb)
{
    ber_tlv_t name_tlv;
    ber_status_t st = ber_expect_tag(seq->value, seq->length, depth, BER_TAG_OID, &name_tlv);
    if (st != BER_OK) {
        return st;
    }
    st = ber_decode_oid(&name_tlv, vb->oid, BER_MAX_OID_LEN, &vb->oid_len);
    if (st != BER_OK) {
        return st;
    }

    size_t remaining = (size_t)((seq->value + seq->length) - name_tlv.next);
    ber_tlv_t value_tlv;
    st = ber_decode_tlv(name_tlv.next, remaining, depth, &value_tlv);
    if (st != BER_OK) {
        return st;
    }
    return snmp_decode_value(&value_tlv, vb);
}

ber_status_t snmp_decode_varbind_list(const uint8_t *buf, size_t len, unsigned depth, snmp_varbind_t *out, size_t out_cap, size_t *out_count)
{
    ber_tlv_t list_seq;
    ber_status_t st = ber_expect_tag(buf, len, depth, BER_TAG_SEQUENCE, &list_seq);
    if (st != BER_OK) {
        return st;
    }

    const uint8_t *p = list_seq.value;
    const uint8_t *end = list_seq.value + list_seq.length;
    size_t n = 0;
    while (p < end) {
        ber_tlv_t vb_seq;
        st = ber_expect_tag(p, (size_t)(end - p), depth + 1, BER_TAG_SEQUENCE, &vb_seq);
        if (st != BER_OK) {
            return st;
        }
        if (n >= out_cap) {
            return BER_ERR_OVERFLOW;
        }
        st = decode_varbind_from_seq_tlv(&vb_seq, depth + 2, &out[n]);
        if (st != BER_OK) {
            return st;
        }
        p = vb_seq.next;
        n++;
    }
    *out_count = n;
    return BER_OK;
}

ber_status_t snmp_encode_response_shaped_pdu(uint8_t *buf, size_t cap, size_t *cursor, uint8_t pdu_tag,
                                              int32_t request_id, int32_t error_status, int32_t error_index,
                                              const snmp_varbind_t *varbinds, size_t count)
{
    size_t start = *cursor;
    ber_status_t st = snmp_encode_varbind_list(buf, cap, cursor, varbinds, count);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_integer(buf, cap, cursor, error_index);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_integer(buf, cap, cursor, error_status);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_integer(buf, cap, cursor, request_id);
    if (st != BER_OK) {
        return st;
    }
    size_t content_len = start - *cursor;
    return ber_encode_container_header(buf, cap, cursor, pdu_tag, content_len);
}

ber_status_t snmp_decode_request_pdu(const uint8_t *buf, size_t len, unsigned depth, snmp_pdu_ctx_t *ctx)
{
    ber_tlv_t pdu;
    ber_status_t st = ber_decode_tlv(buf, len, depth, &pdu);
    if (st != BER_OK) {
        return st;
    }
    switch (pdu.tag) {
        case SNMP_PDU_GET_REQUEST:
        case SNMP_PDU_GET_NEXT_REQUEST:
        case SNMP_PDU_SET_REQUEST:
        case SNMP_PDU_GET_BULK_REQUEST:
            break;
        default:
            return BER_ERR_BAD_TAG;
    }
    ctx->pdu_tag = pdu.tag;

    const uint8_t *p = pdu.value;
    size_t remaining = pdu.length;
    ber_tlv_t f_request_id, f_field2, f_field3;

    st = ber_expect_tag(p, remaining, depth + 1, BER_TAG_INTEGER, &f_request_id);
    if (st != BER_OK) {
        return st;
    }
    st = ber_decode_integer(&f_request_id, &ctx->request_id);
    if (st != BER_OK) {
        return st;
    }
    remaining -= (size_t)(f_request_id.next - p);
    p = f_request_id.next;

    st = ber_expect_tag(p, remaining, depth + 1, BER_TAG_INTEGER, &f_field2);
    if (st != BER_OK) {
        return st;
    }
    st = ber_decode_integer(&f_field2, &ctx->error_status); /* non-repeaters, for GetBulk */
    if (st != BER_OK) {
        return st;
    }
    remaining -= (size_t)(f_field2.next - p);
    p = f_field2.next;

    st = ber_expect_tag(p, remaining, depth + 1, BER_TAG_INTEGER, &f_field3);
    if (st != BER_OK) {
        return st;
    }
    st = ber_decode_integer(&f_field3, &ctx->error_index); /* max-repetitions, for GetBulk */
    if (st != BER_OK) {
        return st;
    }
    remaining -= (size_t)(f_field3.next - p);
    p = f_field3.next;

    return snmp_decode_varbind_list(p, remaining, depth + 1, ctx->varbinds, SNMP_MAX_VARBINDS, &ctx->varbind_count);
}

ber_status_t snmp_encode_v1_trap_pdu(uint8_t *buf, size_t cap, size_t *cursor,
                                      const uint32_t *enterprise_oid, size_t enterprise_oid_len,
                                      const uint8_t agent_addr[4], int32_t generic_trap, int32_t specific_trap,
                                      uint32_t time_stamp_hundredths,
                                      const snmp_varbind_t *varbinds, size_t count)
{
    size_t start = *cursor;
    ber_status_t st = snmp_encode_varbind_list(buf, cap, cursor, varbinds, count);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_unsigned_tagged(buf, cap, cursor, SNMP_TAG_TIMETICKS, time_stamp_hundredths);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_integer(buf, cap, cursor, specific_trap);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_integer(buf, cap, cursor, generic_trap);
    if (st != BER_OK) {
        return st;
    }
    /* IpAddress is a 4-byte raw value under its own application tag, same
     * shape as Opaque -- no dedicated encoder needed. */
    st = ber_encode_prepend_bytes(buf, cap, cursor, agent_addr, 4);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_prepend_tlv_header(buf, cap, cursor, SNMP_TAG_IPADDRESS, 4);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_oid(buf, cap, cursor, enterprise_oid, enterprise_oid_len);
    if (st != BER_OK) {
        return st;
    }
    size_t content_len = start - *cursor;
    return ber_encode_container_header(buf, cap, cursor, SNMP_PDU_TRAP_V1, content_len);
}
