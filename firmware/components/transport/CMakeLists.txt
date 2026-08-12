# UDP socket ownership. The only component in the tree that touches
# lwIP/FreeRTOS APIs directly -- everything protocol-related is delegated
# to snmp_core, which stays socket-agnostic.
idf_component_register(
    SRCS "snmp_udp.c"
    INCLUDE_DIRS "include"
    REQUIRES snmp_core
    PRIV_REQUIRES lwip
)
