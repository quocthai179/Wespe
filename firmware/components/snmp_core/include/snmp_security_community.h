#ifndef WESPE_SNMP_SECURITY_COMMUNITY_H
#define WESPE_SNMP_SECURITY_COMMUNITY_H

#ifdef __cplusplus
extern "C" {
#endif

/* Configures the read-only and read-write community strings and registers
 * this model (the v1/v2c security model -- see snmp_security.h) for both
 * SNMP_VERSION_V1 and SNMP_VERSION_V2C, which share the identical
 * community-based wire shape and authorization rule.
 *
 * Kept as a runtime call rather than a compile-time #define so this file
 * has zero ESP-IDF/Kconfig dependency and stays host-testable: production
 * firmware calls it once at startup with Kconfig-sourced strings
 * (main/app_main.c); tests call it with test-chosen strings. */
void snmp_security_community_init(const char *ro_community, const char *rw_community);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_SNMP_SECURITY_COMMUNITY_H */
