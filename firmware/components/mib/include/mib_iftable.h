#ifndef WESPE_MIB_IFTABLE_H
#define WESPE_MIB_IFTABLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Registers the standard `interfaces` group's ifNumber scalar
 * (1.3.6.1.2.1.2.1.0) plus an ifTable/ifXTable subset (1.3.6.1.2.1.2.2 /
 * 1.3.6.1.2.1.31.1.1 -- see docs/PLAN-TABLES.md Phase 13a and
 * docs/mib-design.md) describing this device's one real interface, the
 * WiFi station. Standard IANA OIDs, deliberately -- unlike WESPE-MIB,
 * this isn't authored anywhere in mibs/: any tool that already knows
 * IF-MIB (every serious NMS does) renders it correctly with zero extra
 * config. Call once at startup, before serving requests. */
void mib_iftable_register(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_MIB_IFTABLE_H */
