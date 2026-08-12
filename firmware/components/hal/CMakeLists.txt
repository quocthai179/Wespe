# Hardware abstraction layer. sysinfo_esp32.c is always built (it has no
# hardware-dependent variant); sensor/relay pick between the real driver
# and the bring-up mock based on Kconfig WESPE_HAL_MOCK (main/Kconfig.projbuild)
# -- the mib/ layer above calls the same sensor.h/relay.h interface either
# way and never knows which one is linked in.
if(CONFIG_WESPE_HAL_MOCK)
    set(HAL_SENSOR_SRC "sensor_mock.c")
    set(HAL_RELAY_SRC "relay_mock.c")
else()
    set(HAL_SENSOR_SRC "sensor_ds18b20.c")
    set(HAL_RELAY_SRC "relay_gpio.c")
endif()

idf_component_register(
    SRCS ${HAL_SENSOR_SRC} ${HAL_RELAY_SRC} "sysinfo_esp32.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES driver esp_timer esp_wifi esp_system esp_rom
)
