#ifndef WESPE_MIB_WESPE_H
#define WESPE_MIB_WESPE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Registers the custom WESPE-MIB objects (1.3.6.1.4.1.99999, placeholder
 * private-enterprise arc -- see docs/mib-design.md) bound to the device_hal/
 * sensor/relay/sysinfo backends. Call once at startup, before serving
 * requests. */
void mib_wespe_register(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_WESPE_H */
