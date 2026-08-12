#ifndef WESPE_WIFI_PROVISIONING_H
#define WESPE_WIFI_PROVISIONING_H

#ifdef __cplusplus
extern "C" {
#endif

/* Brings up WiFi station mode using the Kconfig-configured SSID/password
 * (CONFIG_WESPE_WIFI_SSID/CONFIG_WESPE_WIFI_PASSWORD) and blocks until
 * either an IP address is obtained or a bounded number of connection
 * retries are exhausted. Call once, early in app_main(), before starting
 * the SNMP UDP task. Returns 0 on success. */
int wifi_provisioning_connect_blocking(void);

#ifdef __cplusplus
}
#endif

#endif /* WESPE_WIFI_PROVISIONING_H */
