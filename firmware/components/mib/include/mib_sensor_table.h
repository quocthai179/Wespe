#ifndef WESPE_MIB_SENSOR_TABLE_H
#define WESPE_MIB_SENSOR_TABLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Registers wespeSensorTable (1.3.6.1.4.1.99999.2.6 -- see
 * mibs/WESPE-MIB.txt and docs/PLAN-TABLES.md Phase 13b), the custom-MIB
 * conceptual table demonstrating both a writable column
 * (wespeSensorLabel) and a genuinely multi-row backend (device_hal/
 * sensor.h's sensor_count()/sensor_read_decidegrees_indexed()). Call
 * once at startup, before serving requests. */
void mib_sensor_table_register(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_SENSOR_TABLE_H */
