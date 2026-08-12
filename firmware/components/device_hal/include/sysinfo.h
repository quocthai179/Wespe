#ifndef WESPE_HAL_SYSINFO_H
#define WESPE_HAL_SYSINFO_H

#include <stdint.h>

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

#ifdef __cplusplus
}
#endif

#endif /* WESPE_HAL_SYSINFO_H */
