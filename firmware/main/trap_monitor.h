#ifndef WESPE_TRAP_MONITOR_H
#define WESPE_TRAP_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

/* Starts a background task that polls relay state and temperature every
 * few seconds and fires the corresponding WESPE-MIB notification
 * (wespeRelayStateChangeTrap / wespeTemperatureThresholdTrap, see
 * mibs/WESPE-MIB.txt) through snmp_transport_send_trap() whenever relay
 * state changes or the configured temperature threshold is crossed (with
 * hysteresis, so a reading dithering right at the boundary doesn't spam
 * traps). Deliberately polling-based rather than event-driven: device_hal/
 * exposes plain getters with no callback/observer mechanism, which keeps
 * it simple and keeps this "when do we notify" policy entirely in
 * application code (main/) rather than leaking into device_hal/ or mib/. Call
 * once, after snmp_transport_set_trap_destination(). */
void trap_monitor_start(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_TRAP_MONITOR_H */
