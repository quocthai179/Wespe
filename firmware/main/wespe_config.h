#ifndef WESPE_CONFIG_H
#define WESPE_CONFIG_H

/* Firmware identity -- shown in boot logs. Runtime-tunable behavior
 * (WiFi credentials, community strings, GPIOs, trap destination,
 * temperature threshold) lives in Kconfig (Kconfig.projbuild) instead,
 * since those are things a builder legitimately wants to change per
 * device without editing source. Bump this when cutting a release. */
#define WESPE_FIRMWARE_VERSION "0.1.0-dev"

#endif /* WESPE_CONFIG_H */
