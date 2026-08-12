/* Version-specific SNMP error semantics, isolated to this one file so
 * PDU handlers (snmp_pdu_get.c, snmp_pdu_getnext.c via snmp_dispatch.c)
 * and the MIB layer stay entirely version-neutral. */
#include "snmp_error.h"

snmp_error_translation_t snmp_error_translate(snmp_version_t version, mib_result_t result)
{
    snmp_error_translation_t out;
    out.pdu_level_abort = 0;
    out.v1_error_status = SNMP_V1_ERR_NO_ERROR;
    out.v2c_exception_tag = 0;

    if (result == MIB_OK) {
        return out;
    }

    if (version == SNMP_VERSION_V1) {
        /* RFC1157 4.1.2: a v1 GetResponse carries at most one error for
         * the whole PDU -- the first failing varbind wins, and the caller
         * (snmp_pdu_get.c/getnext) is responsible for echoing back the
         * *original request* varbind values, not partial results. */
        out.pdu_level_abort = 1;
        switch (result) {
            case MIB_NO_SUCH_OBJECT:
            case MIB_NO_SUCH_INSTANCE:
            case MIB_END_OF_VIEW:
                out.v1_error_status = SNMP_V1_ERR_NO_SUCH_NAME;
                break;
            case MIB_WRONG_TYPE:
            case MIB_WRONG_VALUE:
                out.v1_error_status = SNMP_V1_ERR_BAD_VALUE;
                break;
            case MIB_NOT_WRITABLE:
                out.v1_error_status = SNMP_V1_ERR_READ_ONLY;
                break;
            default:
                out.v1_error_status = SNMP_V1_ERR_GEN_ERR;
                break;
        }
        return out;
    }

    /* v2c (and, once implemented, v3) GET-family lookups: no PDU-level
     * abort -- substitute a per-varbind exception value instead and keep
     * building the rest of the response normally (RFC3416 3.2.2). Note
     * SetRequest does NOT use this path even under v2c: it still aborts
     * the whole PDU with a v1-style error-status (see snmp_pdu_set.c),
     * since SET has no exception-value concept in any version. */
    switch (result) {
        case MIB_NO_SUCH_OBJECT:
            out.v2c_exception_tag = SNMP_TAG_NO_SUCH_OBJECT;
            break;
        case MIB_NO_SUCH_INSTANCE:
            out.v2c_exception_tag = SNMP_TAG_NO_SUCH_INSTANCE;
            break;
        case MIB_END_OF_VIEW:
            out.v2c_exception_tag = SNMP_TAG_END_OF_MIB_VIEW;
            break;
        default:
            /* WRONG_TYPE/WRONG_VALUE/NOT_WRITABLE/GEN_ERR shouldn't
             * normally occur on a read path (getters don't validate
             * input), but fall back to a PDU-level abort so the failure
             * is never silently swallowed. */
            out.pdu_level_abort = 1;
            out.v1_error_status = SNMP_V1_ERR_GEN_ERR;
            break;
    }
    return out;
}
