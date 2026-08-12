/* Real hardware backend for hal/relay.h: a single-channel relay module
 * driven from one GPIO through a driver transistor (active-high assumed;
 * flip the level writes below if your module is active-low). Selected
 * instead of relay_mock.c when Kconfig WESPE_HAL_MOCK is disabled -- see
 * components/device_hal/CMakeLists.txt. */
#include "relay.h"
#include "driver/gpio.h"
#include "sdkconfig.h"

#define RELAY_GPIO CONFIG_WESPE_RELAY_GPIO

static bool s_relay_on = false;

int relay_init(void)
{
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << RELAY_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK) {
        return -1;
    }
    gpio_set_level(RELAY_GPIO, 0);
    s_relay_on = false;
    return 0;
}

int relay_set_state(bool on)
{
    gpio_set_level(RELAY_GPIO, on ? 1 : 0);
    s_relay_on = on;
    return 0;
}

int relay_get_state(bool *out)
{
    /* Reads back the last commanded state rather than the GPIO level --
     * this is an output pin, so gpio_get_level() on it would just echo
     * what we last wrote anyway, but doing it this way keeps relay_gpio.c
     * and relay_mock.c behaviorally identical from the MIB layer's view. */
    *out = s_relay_on;
    return 0;
}
