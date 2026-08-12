/* Boot sequence: bring up WiFi, initialize hardware, register the SNMP
 * security model(s) and MIB modules, start listening, announce ourselves
 * with a coldStart trap, then start the trap-condition monitor. Every
 * piece of actual logic lives in the component it's named after -- this
 * file is just the order they get called in. */
#include "wifi_provisioning.h"
#include "trap_monitor.h"
#include "wespe_config.h"

#include "snmp_security_community.h"
#include "snmp_security_usm_stub.h"
#include "snmp_transport.h"
#include "snmp_trap.h"
#include "snmp_pdu.h"

#include "mib_ii.h"
#include "mib_wespe.h"

#include "sensor.h"
#include "relay.h"
#include "sysinfo.h"

#include "esp_log.h"
#include "sdkconfig.h"
#include <string.h>

static const char *TAG = "app_main";

/* coldStart = 1.3.6.1.6.3.1.1.5.1 (SNMPv2-MIB) -- the standard trap,
 * fired once on boot. Reuses this well-known OID rather than a custom
 * WESPE-MIB one, since any NMS already recognizes it. */
static const uint32_t OID_COLD_START[] = {1, 3, 6, 1, 6, 3, 1, 1, 5, 1};

void app_main(void)
{
    ESP_LOGI(TAG, "Wespe SNMP agent %s starting", WESPE_FIRMWARE_VERSION);

    if (wifi_provisioning_connect_blocking() != 0) {
        ESP_LOGE(TAG, "WiFi connect failed, halting");
        return;
    }

    if (sensor_init() != 0) {
        ESP_LOGW(TAG, "sensor_init() failed -- wespeTemperature will report genErr until it recovers");
    }
    if (relay_init() != 0) {
        ESP_LOGW(TAG, "relay_init() failed");
    }

    snmp_security_community_init(CONFIG_WESPE_SNMP_RO_COMMUNITY, CONFIG_WESPE_SNMP_RW_COMMUNITY);
    snmp_security_usm_stub_init();
    mib_ii_register();
    mib_wespe_register();

    if (strlen(CONFIG_WESPE_TRAP_DEST_IP) > 0) {
        if (snmp_transport_set_trap_destination(CONFIG_WESPE_TRAP_DEST_IP) != 0) {
            ESP_LOGW(TAG, "invalid WESPE_TRAP_DEST_IP '%s', traps disabled", CONFIG_WESPE_TRAP_DEST_IP);
        }
    } else {
        ESP_LOGI(TAG, "WESPE_TRAP_DEST_IP not set, traps disabled");
    }

    if (snmp_transport_start() != 0) {
        ESP_LOGE(TAG, "snmp_transport_start() failed, halting");
        return;
    }

    uint8_t trap_packet[128];
    uint32_t uptime_hundredths = (uint32_t)(sysinfo_uptime_ms() / 10);
    size_t trap_len = snmp_trap_build(SNMP_VERSION_V2C, CONFIG_WESPE_SNMP_RO_COMMUNITY, uptime_hundredths, OID_COLD_START,
                                       sizeof(OID_COLD_START) / sizeof(OID_COLD_START[0]), NULL, NULL, 0, trap_packet,
                                       sizeof(trap_packet));
    if (trap_len > 0) {
        snmp_transport_send_trap(trap_packet, trap_len);
    }

    trap_monitor_start();

    ESP_LOGI(TAG, "Wespe SNMP agent ready (RO community '%s')", CONFIG_WESPE_SNMP_RO_COMMUNITY);
}
