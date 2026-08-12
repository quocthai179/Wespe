#ifndef WESPE_SNMP_CODEC_H
#define WESPE_SNMP_CODEC_H

#include "ber_codec.h"
#include "snmp_pdu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Shared PDU/varbind encode-decode helpers. These know the *inner* PDU
 * shape (request-id/error-status/error-index/varbind-list, and the
 * varbind/value grammar) but nothing about the *outer* envelope
 * (community string vs. USM security parameters) -- that split is what
 * lets both today's snmp_security_community.c and a future
 * snmp_security_usm.c reuse this exact code unchanged. */

/* Decodes one value TLV into `vb`, dispatching on the BER/SNMP tag
 * (INTEGER, OCTET STRING, NULL, OID, Counter32/Gauge32/TimeTicks,
 * IpAddress/Opaque as raw bytes, or a v2c exception tag) and setting
 * vb->value_tag accordingly. Does not touch vb->oid/oid_len. */
ber_status_t snmp_decode_value(const ber_tlv_t *tlv, snmp_varbind_t *vb);

/* Encodes vb's value per vb->value_tag -- the encode-side counterpart of
 * snmp_decode_value(). */
ber_status_t snmp_encode_value(uint8_t *buf, size_t cap, size_t *cursor, const snmp_varbind_t *vb);

/* Encodes one varbind: SEQUENCE { name OBJECT IDENTIFIER, value ANY }. */
ber_status_t snmp_encode_varbind(uint8_t *buf, size_t cap, size_t *cursor, const snmp_varbind_t *vb);

/* Encodes a SEQUENCE OF varbind, preserving `varbinds[0..count)` order. */
ber_status_t snmp_encode_varbind_list(uint8_t *buf, size_t cap, size_t *cursor, const snmp_varbind_t *varbinds, size_t count);

/* Decodes a SEQUENCE OF varbind into out[0..*out_count), bounded by
 * out_cap. Used for both request PDUs (values are typically NULL except
 * for SetRequest, which carries real values) and, in tests, for decoding
 * this agent's own encoded responses. */
ber_status_t snmp_decode_varbind_list(const uint8_t *buf, size_t len, unsigned depth, snmp_varbind_t *out, size_t out_cap, size_t *out_count);

/* Encodes a GetResponse/SetResponse/SNMPv2-Trap-shaped PDU: tag,
 * request-id, error-status, error-index, varbind-list -- the one wire
 * shape shared by every SNMP PDU except GetBulkRequest (semantically
 * different field names, same encoding) and the v1 Trap-PDU (genuinely
 * different fields, see snmp_encode_v1_trap_pdu). */
ber_status_t snmp_encode_response_shaped_pdu(uint8_t *buf, size_t cap, size_t *cursor, uint8_t pdu_tag,
                                              int32_t request_id, int32_t error_status, int32_t error_index,
                                              const snmp_varbind_t *varbinds, size_t count);

/* Decodes a request-shaped PDU (GetRequest/GetNextRequest/SetRequest/
 * GetBulkRequest all share this wire shape) into `ctx`. For GetBulkRequest
 * the second and third INTEGER fields are non-repeaters/max-repetitions
 * rather than error-status/error-index -- ctx->error_status/error_index
 * hold the raw decoded values either way; snmp_pdu_getbulk.c reinterprets
 * them. Rejects any pdu tag that isn't a request. */
ber_status_t snmp_decode_request_pdu(const uint8_t *buf, size_t len, unsigned depth, snmp_pdu_ctx_t *ctx);

/* v1 Trap-PDU (RFC1157 4.1.6): SEQUENCE { enterprise OID, agent-addr
 * IpAddress(4 bytes), generic-trap INTEGER, specific-trap INTEGER,
 * time-stamp TimeTicks, variable-bindings }. Structurally unlike every
 * other PDU in this codec, so it gets its own encoder rather than reusing
 * snmp_encode_response_shaped_pdu. */
ber_status_t snmp_encode_v1_trap_pdu(uint8_t *buf, size_t cap, size_t *cursor,
                                      const uint32_t *enterprise_oid, size_t enterprise_oid_len,
                                      const uint8_t agent_addr[4], int32_t generic_trap, int32_t specific_trap,
                                      uint32_t time_stamp_hundredths,
                                      const snmp_varbind_t *varbinds, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_CODEC_H */
