#ifndef WESPE_SNMP_MESSAGE_H
#define WESPE_SNMP_MESSAGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Processes one received UDP datagram end-to-end: version-sniff, dispatch
 * to whichever security model is registered for that version (see
 * snmp_security.h), run the matching PDU handler (snmp_dispatch.h), and
 * encode a response. Returns the number of bytes written to `out`, or 0 if
 * no response should be sent -- unrecognized version/community, a
 * SetRequest without write access, or any other malformed/unauthorized
 * input. SNMP convention is to drop silently in all of these cases rather
 * than answer with an error, since an error response can confirm to a
 * prober which credentials/versions are "close" to valid.
 *
 * Callers are responsible for registering at least one security model
 * (snmp_security_community_init(), snmp_security_usm_stub_init()) and the
 * MIB modules to serve (mib_ii_register(), mib_wespe_register(), or a
 * test's own mock module) before calling this -- kept explicit rather
 * than hidden behind an init() function so tests can register only what a
 * given test actually needs. */
size_t snmp_message_process(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_MESSAGE_H */
