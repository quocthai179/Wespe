#ifndef WESPE_HAL_SENSOR_H
#define WESPE_HAL_SENSOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hardware abstraction for the temperature sensor. Exactly one
 * implementation is linked into a given build: sensor_ds18b20.c (real
 * hardware, DS18B20 1-Wire) or sensor_mock.c (bring-up/simulation, no
 * hardware required) -- selected via firmware/main/Kconfig.projbuild. The
 * MIB layer (mib_wespe.c) only ever calls this interface, so it never
 * changes when the concrete sensor does. */

/* One-time init (bus/GPIO setup). Returns 0 on success. */
int sensor_init(void);

/* Reads the current temperature in tenths of a degree Celsius (e.g. 235 =
 * 23.5C) -- matches the WESPE-MIB wespeTemperature object's SYNTAX, since
 * SNMP has no native floating-point type. Returns 0 on success; a nonzero
 * return (e.g. sensor read timeout/CRC failure) is surfaced by the MIB
 * getter as MIB_GEN_ERR rather than a stale/fabricated value. */
int sensor_read_temperature_decidegrees(int32_t *out_decidegrees);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_HAL_SENSOR_H */
