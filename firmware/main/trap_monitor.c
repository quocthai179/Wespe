#include "trap_monitor.h"
#include "snmp_transport.h"
#include "snmp_trap.h"
#include "snmp_pdu.h"
#include "ber_types.h"
#include "relay.h"
#include "sensor.h"
#include "sysinfo.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include <stdbool.h>
#include <string.h>

#define POLL_INTERVAL_MS 2000

/* wespeMIB.3.{1,2} -- see mibs/WESPE-MIB.txt. */
static const uint32_t OID_RELAY_CHANGE_TRAP[]   = {1, 3, 6, 1, 4, 1, 99999, 3, 1};
static const uint32_t OID_TEMP_THRESHOLD_TRAP[] = {1, 3, 6, 1, 4, 1, 99999, 3, 2};
static const uint32_t OID_WESPE_RELAY_STATE[]   = {1, 3, 6, 1, 4, 1, 99999, 2, 2, 0};
static const uint32_t OID_WESPE_TEMPERATURE[]   = {1, 3, 6, 1, 4, 1, 99999, 2, 1, 0};

static void send_trap(const uint32_t *trap_oid, size_t trap_oid_len, const snmp_varbind_t *extra, size_t extra_count)
{
    uint8_t packet[256];
    uint32_t uptime_hundredths = (uint32_t)(sysinfo_uptime_ms() / 10);
    size_t len = snmp_trap_build(SNMP_VERSION_V2C, CONFIG_WESPE_SNMP_RO_COMMUNITY, uptime_hundredths, trap_oid,
                                  trap_oid_len, NULL, extra, extra_count, packet, sizeof(packet));
    if (len > 0) {
        snmp_transport_send_trap(packet, len);
    }
}

static void monitor_task(void *arg)
{
    (void)arg;

    bool have_relay_baseline = false;
    bool last_relay_on = false;

    bool have_temp_baseline = false;
    bool over_threshold = false;
    const int32_t threshold = CONFIG_WESPE_TEMP_THRESHOLD_DECIDEGREES;
    const int32_t hysteresis = CONFIG_WESPE_TEMP_THRESHOLD_HYSTERESIS_DECIDEGREES;

    for (;;) {
        bool relay_on = false;
        if (relay_get_state(&relay_on) == 0) {
            if (!have_relay_baseline) {
                last_relay_on = relay_on;
                have_relay_baseline = true;
            } else if (relay_on != last_relay_on) {
                snmp_varbind_t vb;
                memset(&vb, 0, sizeof(vb));
                memcpy(vb.oid, OID_WESPE_RELAY_STATE, sizeof(OID_WESPE_RELAY_STATE));
                vb.oid_len = sizeof(OID_WESPE_RELAY_STATE) / sizeof(OID_WESPE_RELAY_STATE[0]);
                vb.value_tag = BER_TAG_INTEGER;
                vb.int_value = relay_on ? 1 : 0;
                send_trap(OID_RELAY_CHANGE_TRAP, sizeof(OID_RELAY_CHANGE_TRAP) / sizeof(OID_RELAY_CHANGE_TRAP[0]), &vb, 1);
                last_relay_on = relay_on;
            }
        }

        int32_t decidegrees = 0;
        if (sensor_read_temperature_decidegrees(&decidegrees) == 0) {
            if (!have_temp_baseline) {
                over_threshold = decidegrees >= threshold;
                have_temp_baseline = true;
            } else if (!over_threshold && decidegrees >= threshold) {
                over_threshold = true;
                snmp_varbind_t vb;
                memset(&vb, 0, sizeof(vb));
                memcpy(vb.oid, OID_WESPE_TEMPERATURE, sizeof(OID_WESPE_TEMPERATURE));
                vb.oid_len = sizeof(OID_WESPE_TEMPERATURE) / sizeof(OID_WESPE_TEMPERATURE[0]);
                vb.value_tag = BER_TAG_INTEGER;
                vb.int_value = decidegrees;
                send_trap(OID_TEMP_THRESHOLD_TRAP, sizeof(OID_TEMP_THRESHOLD_TRAP) / sizeof(OID_TEMP_THRESHOLD_TRAP[0]), &vb, 1);
            } else if (over_threshold && decidegrees < threshold - hysteresis) {
                /* Only clears once comfortably back below the threshold --
                 * see trap_monitor.h for why this matters. */
                over_threshold = false;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));
    }
}

void trap_monitor_start(void)
{
    xTaskCreate(monitor_task, "trap_monitor", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
}
