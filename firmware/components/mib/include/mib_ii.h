#ifndef WESPE_MIB_II_H
#define WESPE_MIB_II_H

#ifdef __cplusplus
extern "C" {
#endif

/* Registers the standard MIB-II `system` group (1.3.6.1.2.1.1) -- the 7
 * scalars any generic SNMP tool expects a device to expose. Call once at
 * startup, before serving requests. */
void mib_ii_register(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_II_H */
