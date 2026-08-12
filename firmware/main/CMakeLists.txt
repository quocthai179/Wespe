idf_component_register(
    SRCS "app_main.c" "wifi_provisioning.c" "trap_monitor.c"
    INCLUDE_DIRS "."
    REQUIRES snmp_core mib hal transport nvs_flash esp_wifi esp_netif esp_event
)
