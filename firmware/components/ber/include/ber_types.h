#ifndef WESPE_BER_TYPES_H
#define WESPE_BER_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Tag classes (bits 7-6 of the identifier octet). */
typedef enum {
    BER_CLASS_UNIVERSAL   = 0x00,
    BER_CLASS_APPLICATION = 0x40,
    BER_CLASS_CONTEXT     = 0x80,
    BER_CLASS_PRIVATE     = 0xC0,
} ber_class_t;

#define BER_CONSTRUCTED_FLAG 0x20u

/* Universal ASN.1 tags used by SNMP (RFC1157 / RFC3416). */
#define BER_TAG_INTEGER      0x02u
#define BER_TAG_OCTET_STRING 0x04u
#define BER_TAG_NULL         0x05u
#define BER_TAG_OID          0x06u
#define BER_TAG_SEQUENCE     0x30u /* universal, constructed */

/* SNMP application-class types (tag = 0x40 | n). */
#define SNMP_TAG_IPADDRESS 0x40u
#define SNMP_TAG_COUNTER32 0x41u
#define SNMP_TAG_GAUGE32   0x42u /* == Unsigned32 */
#define SNMP_TAG_TIMETICKS 0x43u
#define SNMP_TAG_OPAQUE    0x44u
/* SNMPv2's "high capacity" 64-bit counter (RFC2578 7.1.10). Does NOT
 * exist in SNMPv1 -- RFC 2089 / RFC 3584 require a v1 manager never see
 * one: a v1 GET of a Counter64 object must answer noSuchName, and a v1
 * GETNEXT/walk must silently skip over it as if it weren't registered at
 * all. See snmp_pdu_get.c's lookup_and_fetch() for where that's enforced. */
#define SNMP_TAG_COUNTER64 0x46u

/* SNMPv2c exception values (RFC3416 3.2.2): context-specific, primitive,
 * zero-length content -- structurally like NULL but a different tag. */
#define SNMP_TAG_NO_SUCH_OBJECT   0x80u
#define SNMP_TAG_NO_SUCH_INSTANCE 0x81u
#define SNMP_TAG_END_OF_MIB_VIEW  0x82u

/* SNMP PDU tags (context class, constructed). */
#define SNMP_PDU_GET_REQUEST      0xA0u
#define SNMP_PDU_GET_NEXT_REQUEST 0xA1u
#define SNMP_PDU_GET_RESPONSE     0xA2u
#define SNMP_PDU_SET_REQUEST      0xA3u
#define SNMP_PDU_TRAP_V1          0xA4u
#define SNMP_PDU_GET_BULK_REQUEST 0xA5u
#define SNMP_PDU_INFORM_REQUEST   0xA6u
#define SNMP_PDU_TRAP_V2          0xA7u

typedef enum {
    BER_OK             = 0,
    BER_ERR_TRUNCATED  = -1, /* buffer ended before the declared length */
    BER_ERR_BAD_TAG    = -2, /* tag didn't match what the caller expected */
    BER_ERR_BAD_LENGTH = -3, /* indefinite-length or otherwise malformed length octets */
    BER_ERR_OVERFLOW   = -4, /* value too large for the destination type/buffer */
    BER_ERR_DEPTH      = -5, /* nested SEQUENCE recursion exceeded BER_MAX_NEST_DEPTH */
    BER_ERR_BAD_ARGS   = -6, /* NULL pointer or otherwise invalid call */
} ber_status_t;

/* SNMP messages nest at most ~4-5 levels deep (message -> PDU -> varbind
 * list -> varbind -> value). A cap of 6 comfortably covers legitimate
 * traffic while rejecting adversarially deep-nested payloads outright. */
#define BER_MAX_NEST_DEPTH 6

/* Max number of sub-identifiers (arcs) supported in a decoded/encoded OID.
 * Real MIB OIDs in this project are at most ~12 arcs deep (a table cell
 * like ifTable's ifDescr.1 is 1.3.6.1.2.1.2.2.1.2.1 = 11 arcs); 20 leaves
 * comfortable headroom without inviting an oversized fixed allocation --
 * this array is repeated twice per snmp_varbind_t (mib_types.h), which is
 * itself repeated SNMP_MAX_VARBINDS times in snmp_pdu_ctx_t, so shrinking
 * it directly shrinks that budget. */
#define BER_MAX_OID_LEN 20

#ifdef __cplusplus
}
#endif

#endif /* WESPE_BER_TYPES_H */
