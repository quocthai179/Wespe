/* Mock backend for device_hal/relay.h, for bring-up/simulation before real
 * hardware is wired up (Kconfig WESPE_HAL_MOCK). Just remembers the
 * commanded state in RAM -- enough to exercise SetRequest/GetRequest end
 * to end without a physical relay attached. */
#include "relay.h"

static bool s_relay_on = false;

int relay_init(void)
{
    s_relay_on = false;
    return 0;
}

int relay_set_state(bool on)
{
    s_relay_on = on;
    return 0;
}

int relay_get_state(bool *out)
{
    *out = s_relay_on;
    return 0;
}
