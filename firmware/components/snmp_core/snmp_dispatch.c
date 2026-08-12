#include "snmp_dispatch.h"

ber_status_t snmp_dispatch_pdu(snmp_pdu_ctx_t *ctx)
{
    switch (ctx->pdu_tag) {
        case SNMP_PDU_GET_REQUEST:
            return snmp_pdu_handle_get(ctx);
        case SNMP_PDU_GET_NEXT_REQUEST:
            return snmp_pdu_handle_getnext(ctx);
        case SNMP_PDU_SET_REQUEST:
            return snmp_pdu_handle_set(ctx);
        case SNMP_PDU_GET_BULK_REQUEST:
            return snmp_pdu_handle_getbulk(ctx);
        default:
            /* Anything else (GetResponse, Trap-PDU, InformRequest)
             * arriving as an inbound *request* is never valid -- drop it. */
            return BER_ERR_BAD_TAG;
    }
}
