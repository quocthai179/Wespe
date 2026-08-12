#ifndef WESPE_HAL_RELAY_H
#define WESPE_HAL_RELAY_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hardware abstraction for the relay. relay_gpio.c (real hardware, a
 * single-channel 5V relay module driven from one GPIO) or relay_mock.c
 * (bring-up/simulation) is linked in, selected via Kconfig -- see
 * sensor.h for the rationale. */

int relay_init(void);

/* Returns 0 on success. */
int relay_set_state(bool on);

/* Returns 0 on success; *out reflects the last commanded/read-back state. */
int relay_get_state(bool *out);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_HAL_RELAY_H */
