#ifndef WESPE_MIB_OBJECT_H
#define WESPE_MIB_OBJECT_H

#include "mib_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MIB_ACCESS_RO = 0,
    MIB_ACCESS_RW = 1,
} mib_access_t;

/* Getter fills a varbind for a GET/GETNEXT/GETBULK response. `vb->oid` /
 * `vb->oid_len` are pre-populated by the caller with the object's own OID
 * before the getter runs; the getter only needs to fill value_tag and the
 * matching value field. Returning anything other than MIB_OK (e.g.
 * MIB_GEN_ERR for a sensor that's currently unavailable) is folded into
 * the response by the PDU handler via snmp_error_translate(). */
typedef mib_result_t (*mib_get_fn)(snmp_varbind_t *vb);

/* Setter receives an incoming varbind that the two-pass SetRequest handler
 * has already type/range-validated against this object's value_tag before
 * ever calling it, so a setter only needs to apply the value and can still
 * return MIB_WRONG_VALUE for a range/semantic check the generic validator
 * can't express (e.g. an enum not being 0 or 1). */
typedef mib_result_t (*mib_set_fn)(const snmp_varbind_t *vb);

/* A build-time-sorted (ascending OID) array of these forms one MIB module;
 * see mib_tree.h. `oid` includes the trailing .0 instance for scalars. */
typedef struct {
    const uint32_t *oid;
    uint8_t          oid_len;
    uint8_t          value_tag; /* expected BER_TAG_* / SNMP_TAG_* for this object's value */
    mib_access_t     access;
    mib_get_fn       getter;
    mib_set_fn       setter;    /* NULL for MIB_ACCESS_RO objects */
} mib_object_t;

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_OBJECT_H */
