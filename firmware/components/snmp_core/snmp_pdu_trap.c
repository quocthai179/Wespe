/* Trap generation. Unlike GET/GETNEXT/SET/GETBULK, a trap isn't a response
 * to an incoming request, so it doesn't go through the
 * snmp_security_model_t::prepare_outgoing path (that's keyed to whatever
 * security context a *request* negotiated) -- it just encodes the
 * envelope directly against a configured trap community/version. */
#include "snmp_trap.h"
#include "snmp_codec.h"
#include <string.h>

#define SNMP_TRAP_MAX_VARBINDS SNMP_MAX_VARBINDS

/* snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0 (SNMPv2-MIB) -- the standard
 * varbind that carries *which* notification this is, per the v2c/
 * SNMPv2-Trap convention (RFC3416 4.2.6). */
static const uint32_t OID_SNMP_TRAP_OID[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
static const uint32_t OID_SYS_UPTIME[]    = {1, 3, 6, 1, 2, 1, 1, 3, 0};

static ber_status_t encode_envelope_and_finish(int32_t version, const char *community, uint8_t *buf, size_t cap,
                                                size_t *cursor, size_t *out_len)
{
    size_t community_len = strlen(community);
    ber_status_t st = ber_encode_octet_string(buf, cap, cursor, (const uint8_t *)community, community_len);
    if (st != BER_OK) {
        return st;
    }
    st = ber_encode_integer(buf, cap, cursor, version);
    if (st != BER_OK) {
        return st;
    }
    size_t content_len = cap - *cursor;
    st = ber_encode_container_header(buf, cap, cursor, BER_TAG_SEQUENCE, content_len);
    if (st != BER_OK) {
        return st;
    }

    memmove(buf, buf + *cursor, cap - *cursor);
    *out_len = cap - *cursor;
    return BER_OK;
}

static size_t build_v2c_trap(const char *community, uint32_t uptime_hundredths, const uint32_t *trap_oid,
                              size_t trap_oid_len, const snmp_varbind_t *extra_varbinds, size_t extra_count,
                              uint8_t *out, size_t cap)
{
    if (extra_count + 2 > SNMP_TRAP_MAX_VARBINDS) {
        return 0;
    }
    snmp_varbind_t varbinds[SNMP_TRAP_MAX_VARBINDS];
    size_t n = 0;

    memset(&varbinds[n], 0, sizeof(varbinds[n]));
    memcpy(varbinds[n].oid, OID_SYS_UPTIME, sizeof(OID_SYS_UPTIME));
    varbinds[n].oid_len = sizeof(OID_SYS_UPTIME) / sizeof(OID_SYS_UPTIME[0]);
    varbinds[n].value_tag = SNMP_TAG_TIMETICKS;
    varbinds[n].int_value = (int32_t)uptime_hundredths;
    n++;

    memset(&varbinds[n], 0, sizeof(varbinds[n]));
    memcpy(varbinds[n].oid, OID_SNMP_TRAP_OID, sizeof(OID_SNMP_TRAP_OID));
    varbinds[n].oid_len = sizeof(OID_SNMP_TRAP_OID) / sizeof(OID_SNMP_TRAP_OID[0]);
    varbinds[n].value_tag = BER_TAG_OID;
    memcpy(varbinds[n].oid_value, trap_oid, trap_oid_len * sizeof(uint32_t));
    varbinds[n].oid_value_len = trap_oid_len;
    n++;

    for (size_t i = 0; i < extra_count; i++) {
        varbinds[n++] = extra_varbinds[i];
    }

    size_t cursor = cap;
    /* SNMPv2-Trap is wire-identical to a GetResponse PDU (RFC3416 4.2.6):
     * request-id/error-status/error-index/varbind-list under a different
     * tag -- so the shared response-shaped encoder applies unchanged.
     * request-id is conventionally 0 for an unsolicited notification. */
    ber_status_t st = snmp_encode_response_shaped_pdu(out, cap, &cursor, SNMP_PDU_TRAP_V2, 0, 0, 0, varbinds, n);
    if (st != BER_OK) {
        return 0;
    }

    size_t out_len = 0;
    st = encode_envelope_and_finish((int32_t)SNMP_VERSION_V2C, community, out, cap, &cursor, &out_len);
    return (st == BER_OK) ? out_len : 0;
}

static size_t build_v1_trap(const char *community, uint32_t uptime_hundredths, const uint32_t *trap_oid,
                             size_t trap_oid_len, const uint8_t agent_addr[4], const snmp_varbind_t *extra_varbinds,
                             size_t extra_count, uint8_t *out, size_t cap)
{
    /* The v1 Trap-PDU has no snmpTrapOID.0 convention of its own -- the
     * enterprise OID + generic-trap/specific-trap fields carry that
     * information structurally instead. `trap_oid` is used as the
     * enterprise OID with genericTrap = enterpriseSpecific(6) and
     * specificTrap = the trap OID's last arc -- the conventional mapping
     * tools like net-snmp's snmptrapd use to relate a v1 trap to the
     * "same" v2c notification. */
    if (extra_count > SNMP_TRAP_MAX_VARBINDS) {
        return 0;
    }
    int32_t specific_trap = (trap_oid_len > 0) ? (int32_t)trap_oid[trap_oid_len - 1] : 0;

    size_t cursor = cap;
    ber_status_t st = snmp_encode_v1_trap_pdu(out, cap, &cursor, trap_oid, trap_oid_len, agent_addr,
                                               /* generic-trap = enterpriseSpecific */ 6, specific_trap,
                                               uptime_hundredths, extra_varbinds, extra_count);
    if (st != BER_OK) {
        return 0;
    }
    size_t out_len = 0;
    st = encode_envelope_and_finish((int32_t)SNMP_VERSION_V1, community, out, cap, &cursor, &out_len);
    return (st == BER_OK) ? out_len : 0;
}

size_t snmp_trap_build(snmp_version_t version, const char *community, uint32_t uptime_hundredths,
                        const uint32_t *trap_oid, size_t trap_oid_len, const uint8_t agent_addr[4],
                        const snmp_varbind_t *extra_varbinds, size_t extra_varbind_count, uint8_t *out, size_t cap)
{
    if (version == SNMP_VERSION_V2C) {
        return build_v2c_trap(community, uptime_hundredths, trap_oid, trap_oid_len, extra_varbinds,
                               extra_varbind_count, out, cap);
    }
    return build_v1_trap(community, uptime_hundredths, trap_oid, trap_oid_len, agent_addr, extra_varbinds,
                          extra_varbind_count, out, cap);
}
