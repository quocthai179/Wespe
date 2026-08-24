#ifndef WESPE_HAL_SYSINFO_H
#define WESPE_HAL_SYSINFO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hardware abstraction for device/system telemetry backing the WESPE-MIB
 * bonus objects and sysUpTime. sysinfo_esp32.c (real ESP-IDF APIs) or a
 * mock is linked in, selected via Kconfig. */

/* Milliseconds since boot -- source for sysUpTime (converted to
 * hundredths of a second by the caller) and wespeUptimeSeconds. */
uint64_t sysinfo_uptime_ms(void);

/* Current free heap, bytes -- wespeFreeHeapBytes. */
uint32_t sysinfo_free_heap_bytes(void);

/* Current WiFi RSSI, dBm (negative) -- wespeWifiRssi. Returns 0 on
 * success; nonzero (e.g. not associated) is surfaced as MIB_GEN_ERR. */
int sysinfo_wifi_rssi_dbm(int32_t *out_rssi);

/* ---------------------------------------------------------------------
 * IF-MIB backing (docs/PLAN-TABLES.md Phase 13a). The device has exactly
 * one network interface worth reporting -- the WiFi station -- so this is
 * intentionally not a general multi-netif enumeration API, just what
 * ifTable/ifXTable's single row needs.
 * ------------------------------------------------------------------- */

/* Station MAC address, 6 raw bytes -- ifPhysAddress. Returns 0 on
 * success. */
int sysinfo_wifi_mac(uint8_t mac_out[6]);

/* Whether the station is currently associated to an AP -- ifOperStatus
 * (up(1) if true, down(2) if false). Always returns 0; `*out_up` carries
 * the answer (there's no failure mode distinct from "not associated"). */
int sysinfo_wifi_oper_up(bool *out_up);

/* sysUpTime-relative timestamp (hundredths of a second, TimeTicks-shaped)
 * of the most recent ifOperStatus transition -- ifLastChange. Tracked by
 * comparing each call's sysinfo_wifi_oper_up() result against the
 * previously observed one, so this must be called at least as often as
 * the caller wants transitions detected; polling it via SNMP GET is
 * sufficient for this device's request-driven (no background poller)
 * model. Reports 0 (i.e. "at agent startup") until the first observed
 * transition, per the conventional reading of ifLastChange for an
 * interface that hasn't changed state since boot. */
uint32_t sysinfo_wifi_last_change_ticks(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_HAL_SYSINFO_H */
