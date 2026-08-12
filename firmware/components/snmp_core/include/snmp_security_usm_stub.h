#ifndef WESPE_SNMP_SECURITY_USM_STUB_H
#define WESPE_SNMP_SECURITY_USM_STUB_H

#ifdef __cplusplus
extern "C" {
#endif

/* Registers a placeholder SNMPv3/USM security model for SNMP_VERSION_V3.
 * This is NOT a real USM implementation -- see docs/v3-readiness.md. It
 * exists to prove the snmp_security_model_t extension point (snmp_security.h)
 * actually works end-to-end: it parses enough of the v3 envelope (outer
 * SEQUENCE, msgGlobalData) to confirm the message is structurally
 * well-formed SNMPv3, then declines by returning an error so the
 * datagram is dropped -- the same "no response" outcome as an
 * unrecognized v1/v2c community, and importantly NOT a crash or a hang.
 * A real snmp_security_usm.c would have the identical process_incoming
 * signature and populate the identical snmp_pdu_ctx_t; it would just do
 * the msgSecurityParameters/USM auth-and-decrypt work this stub skips. */
void snmp_security_usm_stub_init(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_SECURITY_USM_STUB_H */
