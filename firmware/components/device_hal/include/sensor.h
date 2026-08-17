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

/* ---------------------------------------------------------------------
 * Multi-sensor extension (docs/PLAN-TABLES.md Phase 13b), backing
 * wespeSensorTable (mib_sensor_table.c). The single-sensor API above is
 * untouched and still backs the original scalar wespeTemperature -- these
 * are additive.
 * ------------------------------------------------------------------- */

/* Upper bound on sensor_count()'s return value -- callers may size fixed
 * per-row storage (labels, read counters) to this without a separate
 * runtime query. sensor_ds18b20.c (real hardware) always reports 1: its
 * 1-Wire driver deliberately assumes a single-device bus (Skip ROM, see
 * that file) rather than implementing full ROM search, so genuine
 * multi-sensor support is future work, not something this MVP claims.
 * sensor_mock.c can report up to this many. */
#define SENSOR_MAX_COUNT 4

/* Number of sensors currently present. May legitimately change between
 * (or even during) calls -- see mib_table.h's first_index()/next_index()
 * contract, which this backs directly, and sensor_mock.c's optional
 * CONFIG_WESPE_SENSOR_VOLATILE_ROWS mode. */
int sensor_count(void);

/* Same contract as sensor_read_temperature_decidegrees(), for sensor
 * `index` (1-based, expected in [1, sensor_count()] -- an out-of-range
 * index is a caller bug, not a runtime condition to recover from, and is
 * simply treated as a read failure). */
int sensor_read_decidegrees_indexed(uint32_t index, int32_t *out_decidegrees);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_HAL_SENSOR_H */
