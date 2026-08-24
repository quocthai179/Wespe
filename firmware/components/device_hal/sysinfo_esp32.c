/* System/device telemetry backend for device_hal/sysinfo.h. Unlike sensor/relay,
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

int sysinfo_wifi_mac(uint8_t mac_out[6])
{
    return (esp_wifi_get_mac(WIFI_IF_STA, mac_out) == ESP_OK) ? 0 : -1;
}

int sysinfo_wifi_oper_up(bool *out_up)
{
    wifi_ap_record_t ap_info;
    *out_up = (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK);
    return 0;
}

/* ifLastChange tracking state. Not thread-safe, but nothing in this
 * firmware calls into the MIB layer from more than one task (the SNMP UDP
 * task is the sole caller -- see components/transport/snmp_udp.c), so
 * plain statics match every other piece of per-request MIB state (e.g.
 * snmp_message.c's s_ctx). */
static bool     s_last_change_initialized = false;
static bool     s_last_oper_up            = false;
static uint32_t s_last_change_ticks       = 0;

uint32_t sysinfo_wifi_last_change_ticks(void)
{
    bool up = false;
    (void)sysinfo_wifi_oper_up(&up);

    if (!s_last_change_initialized) {
        /* First observation ever: treat this as "no change since boot"
         * rather than a transition, per ifLastChange's conventional
         * reading (RFC2863) of 0 meaning exactly that. */
        s_last_change_initialized = true;
        s_last_oper_up = up;
        return 0;
    }

    if (up != s_last_oper_up) {
        s_last_oper_up = up;
        s_last_change_ticks = (uint32_t)(sysinfo_uptime_ms() / 10);
    }
    return s_last_change_ticks;
}
