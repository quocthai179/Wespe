#ifndef WESPE_SNMP_TRAP_H
#define WESPE_SNMP_TRAP_H

#include "ber_codec.h"
#include "snmp_pdu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Builds one complete, ready-to-send, fire-and-forget trap datagram
 * (InformRequest / acknowledged traps are out of scope -- see
 * docs/v3-readiness.md) for `trap_oid`: a v1 Trap-PDU or a v2c
 * SNMPv2-Trap depending on `version`. `extra_varbinds` is the
 * application-specific payload (e.g. the new relay state); for v2c,
 * sysUpTime.0 and snmpTrapOID.0 are prepended automatically per RFC3416
 * 4.2.6 convention -- do not include them in extra_varbinds.
 * `agent_addr` (raw 4-byte IPv4) is only used for the v1 shape.
 * Returns the number of bytes written to `out`, or 0 on failure (e.g. the
 * encoded trap doesn't fit in `cap`). */
size_t snmp_trap_build(snmp_version_t version, const char *community, uint32_t uptime_hundredths,
                        const uint32_t *trap_oid, size_t trap_oid_len, const uint8_t agent_addr[4],
                        const snmp_varbind_t *extra_varbinds, size_t extra_varbind_count, uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_TRAP_H */
