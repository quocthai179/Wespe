#ifndef WESPE_SNMP_TRANSPORT_H
#define WESPE_SNMP_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the FreeRTOS task that owns the SNMP agent's UDP socket: binds
 * :161, and for each received datagram calls snmp_message_process()
 * (components/snmp_core) and sends back whatever it returns, if anything.
 * Call once, after WiFi is up and all security models / MIB modules are
 * registered. Returns 0 on success. */
int snmp_transport_start(void);

/* Configures the trap receiver's IPv4 address (dotted-quad, e.g.
 * "192.168.1.10") for snmp_transport_send_trap(). Call before generating
 * any traps; if never called, snmp_transport_send_trap() fails harmlessly
 * (returns nonzero) rather than sending to an undefined destination. */
int snmp_transport_set_trap_destination(const char *ipv4_address);

/* Sends a pre-built trap datagram (see snmp_trap.h's snmp_trap_build())
 * to the configured trap receiver on UDP :162. Safe to call from any
 * task. Returns 0 on success. */
int snmp_transport_send_trap(const uint8_t *packet, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_TRANSPORT_H */
