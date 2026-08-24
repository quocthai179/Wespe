/* Mock backend for device_hal/sensor.h, for bring-up/simulation before real
 * hardware is wired up (Kconfig WESPE_HAL_MOCK). Returns a fixed
 * plausible reading so the WESPE-MIB objects and the SNMP path around
 * them can be exercised end to end without a DS18B20 attached. */
#include "sensor.h"
#include "sdkconfig.h"
#if CONFIG_WESPE_SENSOR_VOLATILE_ROWS
#include "esp_timer.h"
#endif

int sensor_init(void)
{
    return 0;
}

int sensor_read_temperature_decidegrees(int32_t *out_decidegrees)
{
    *out_decidegrees = 235; /* 23.5C */
    return 0;
}

/* Three simulated sensors (docs/PLAN-TABLES.md Phase 13b) -- fixed
 * plausible readings, distinct enough to tell rows apart in a walk. */
#define MOCK_SENSOR_COUNT 3
static const int32_t s_mock_decidegrees[MOCK_SENSOR_COUNT] = {235, 198, 271};

int sensor_count(void)
{
#if CONFIG_WESPE_SENSOR_VOLATILE_ROWS
    /* Cycles 1 -> 2 -> 3 -> 2 -> (repeat) on a fixed clock, entirely
     * independent of any SNMP request, so wespeSensorTable's row set
     * genuinely appears/disappears between -- or even during -- a
     * manager's poll. This is the one thing a simulator can demonstrate
     * that almost nothing else conveniently lets a polling engine be
     * tested against on demand; see docs/PLAN-TABLES.md Phase 13b. */
    static const int pattern[] = {1, 2, 3, 2};
    int64_t step = (esp_timer_get_time() / 1000000) / 10; /* one step per 10s */
    return pattern[step % (sizeof(pattern) / sizeof(pattern[0]))];
#else
    return MOCK_SENSOR_COUNT;
#endif
}

int sensor_read_decidegrees_indexed(uint32_t index, int32_t *out_decidegrees)
{
    if (index < 1 || index > MOCK_SENSOR_COUNT) {
        return -1;
    }
    *out_decidegrees = s_mock_decidegrees[index - 1];
    return 0;
}
