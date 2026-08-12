/* Mock backend for hal/sensor.h, for bring-up/simulation before real
 * hardware is wired up (Kconfig WESPE_HAL_MOCK). Returns a fixed
 * plausible reading so the WESPE-MIB objects and the SNMP path around
 * them can be exercised end to end without a DS18B20 attached. */
#include "sensor.h"

int sensor_init(void)
{
    return 0;
}

int sensor_read_temperature_decidegrees(int32_t *out_decidegrees)
{
    *out_decidegrees = 235; /* 23.5C */
    return 0;
}
