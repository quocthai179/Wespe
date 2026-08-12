#ifndef WESPE_SNMP_DISPATCH_H
#define WESPE_SNMP_DISPATCH_H

#include "ber_types.h"
#include "snmp_pdu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Handles ctx in place: on entry, ctx holds the parsed request (pdu_tag,
 * request_id, varbinds with OIDs -- and for SetRequest, request values,
 * for GetBulkRequest error_status/error_index repurposed as non-repeaters/
 * max-repetitions); on return, ctx has been transformed into the response
 * (pdu_tag set to SNMP_PDU_GET_RESPONSE, varbinds filled with values/
 * exceptions, error_status/error_index set per snmp_error_translate()).
 * Returns BER_OK if a response was produced, or a nonzero ber_status_t if
 * the request should get NO response at all -- e.g. a SetRequest without
 * write access (dropped, same as an unrecognized community, rather than
 * answered with an error, since responding would confirm which
 * credentials are "close"). */
typedef ber_status_t (*snmp_pdu_handler_fn)(snmp_pdu_ctx_t *ctx);

ber_status_t snmp_pdu_handle_get(snmp_pdu_ctx_t *ctx);
ber_status_t snmp_pdu_handle_getnext(snmp_pdu_ctx_t *ctx);
ber_status_t snmp_pdu_handle_set(snmp_pdu_ctx_t *ctx);
ber_status_t snmp_pdu_handle_getbulk(snmp_pdu_ctx_t *ctx);

/* Dispatches ctx->pdu_tag to the matching handler above. Returns
 * BER_ERR_BAD_TAG if the PDU type isn't one this agent answers as a
 * *request* (e.g. a GetResponse or Trap arriving inbound, which is never
 * valid), or if GetBulkRequest arrives under SNMPv1 (it doesn't exist in
 * that version). */
ber_status_t snmp_dispatch_pdu(snmp_pdu_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_DISPATCH_H */
