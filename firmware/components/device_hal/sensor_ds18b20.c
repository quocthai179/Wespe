/* Real hardware backend for hal/sensor.h: a bit-banged DS18B20 1-Wire
 * driver. Selected instead of sensor_mock.c when Kconfig
 * WESPE_HAL_MOCK is disabled -- see components/device_hal/CMakeLists.txt.
 *
 * A DS18B20 conversion takes up to ~750ms, which would stall the SNMP UDP
 * task for that long if done inline on every GET -- unacceptable for a
 * device meant to demonstrate responsive real-time polling. Instead, a
 * background task samples the sensor on its own schedule and caches the
 * latest reading; sensor_read_temperature_decidegrees() just returns
 * whatever is cached, non-blocking. */
#include "sensor.h"
#include "driver/gpio.h"
#include "esp_rom_sys.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "sdkconfig.h"
#include <stdbool.h>

#define ONEWIRE_GPIO      CONFIG_WESPE_DS18B20_GPIO
#define POLL_INTERVAL_MS  5000

static const char *TAG = "sensor_ds18b20";
static SemaphoreHandle_t s_lock;
static int32_t s_last_decidegrees = 0;
static bool s_have_reading = false;

static void ow_write_bit(int bit)
{
    gpio_set_direction(ONEWIRE_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(ONEWIRE_GPIO, 0);
    esp_rom_delay_us(bit ? 6 : 60);
    gpio_set_level(ONEWIRE_GPIO, 1);
    esp_rom_delay_us(bit ? 64 : 10);
}

static int ow_read_bit(void)
{
    gpio_set_direction(ONEWIRE_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(ONEWIRE_GPIO, 0);
    esp_rom_delay_us(2);
    gpio_set_direction(ONEWIRE_GPIO, GPIO_MODE_INPUT);
    esp_rom_delay_us(10);
    int bit = gpio_get_level(ONEWIRE_GPIO);
    esp_rom_delay_us(50);
    return bit;
}

static void ow_write_byte(uint8_t b)
{
    for (int i = 0; i < 8; i++) {
        ow_write_bit(b & 0x01);
        b >>= 1;
    }
}

static uint8_t ow_read_byte(void)
{
    uint8_t b = 0;
    for (int i = 0; i < 8; i++) {
        b |= (uint8_t)(ow_read_bit() << i);
    }
    return b;
}

/* Returns nonzero if a device asserted presence. */
static int ow_reset(void)
{
    gpio_set_direction(ONEWIRE_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(ONEWIRE_GPIO, 0);
    esp_rom_delay_us(480);
    gpio_set_direction(ONEWIRE_GPIO, GPIO_MODE_INPUT);
    esp_rom_delay_us(70);
    int presence = !gpio_get_level(ONEWIRE_GPIO); /* device pulls the bus low if present */
    esp_rom_delay_us(410);
    return presence;
}

static int read_once(int32_t *out_decidegrees)
{
    if (!ow_reset()) {
        return -1;
    }
    ow_write_byte(0xCC); /* Skip ROM -- single-device bus assumed */
    ow_write_byte(0x44); /* Convert T */
    vTaskDelay(pdMS_TO_TICKS(750)); /* worst-case 12-bit conversion time */

    if (!ow_reset()) {
        return -1;
    }
    ow_write_byte(0xCC);
    ow_write_byte(0xBE); /* Read Scratchpad */
    uint8_t lsb = ow_read_byte();
    uint8_t msb = ow_read_byte();

    int16_t raw = (int16_t)(((uint16_t)msb << 8) | lsb); /* 1/16 degC units, default 12-bit resolution */
    *out_decidegrees = ((int32_t)raw * 10) / 16;
    return 0;
}

static void poll_task(void *arg)
{
    (void)arg;
    for (;;) {
        int32_t decidegrees = 0;
        if (read_once(&decidegrees) == 0) {
            xSemaphoreTake(s_lock, portMAX_DELAY);
            s_last_decidegrees = decidegrees;
            s_have_reading = true;
            xSemaphoreGive(s_lock);
        } else {
            ESP_LOGW(TAG, "DS18B20 read failed (no presence pulse)");
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));
    }
}

int sensor_init(void)
{
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << ONEWIRE_GPIO,
        .mode = GPIO_MODE_INPUT_OUTPUT_OD, /* open-drain: 1-Wire is a shared, pulled-up bus */
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK) {
        return -1;
    }
    gpio_set_level(ONEWIRE_GPIO, 1);

    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) {
        return -1;
    }

    BaseType_t ok = xTaskCreate(poll_task, "ds18b20_poll", 2048, NULL, tskIDLE_PRIORITY + 2, NULL);
    return (ok == pdPASS) ? 0 : -1;
}

int sensor_read_temperature_decidegrees(int32_t *out_decidegrees)
{
    int result = -1;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_have_reading) {
        *out_decidegrees = s_last_decidegrees;
        result = 0;
    }
    xSemaphoreGive(s_lock);
    return result;
}

int sensor_count(void)
{
    return 1; /* single-device 1-Wire bus -- see file header */
}

int sensor_read_decidegrees_indexed(uint32_t index, int32_t *out_decidegrees)
{
    if (index != 1) {
        return -1;
    }
    return sensor_read_temperature_decidegrees(out_decidegrees);
}
