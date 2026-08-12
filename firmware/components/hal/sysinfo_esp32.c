/* System/device telemetry backend for hal/sysinfo.h. Unlike sensor/relay,
 * there's no mock variant -- these ESP-IDF system APIs work identically
 * regardless of what (if anything) is wired up. */
#include "sysinfo.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_wifi.h"

uint64_t sysinfo_uptime_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000);
}

uint32_t sysinfo_free_heap_bytes(void)
{
    return (uint32_t)esp_get_free_heap_size();
}

int sysinfo_wifi_rssi_dbm(int32_t *out_rssi)
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        return -1; /* not associated */
    }
    *out_rssi = ap_info.rssi;
    return 0;
}
