# SNMP message parsing, the security-model dispatch table (the SNMPv3-
# readiness extension point), PDU handlers, and trap generation. No
# ESP-IDF/FreeRTOS dependency -- host-buildable, see host_tests/.
idf_component_register(
    SRCS
        "snmp_codec.c"
        "snmp_error.c"
        "snmp_security.c"
        "snmp_security_community.c"
        "snmp_security_usm_stub.c"
        "snmp_pdu_get.c"
        "snmp_pdu_set.c"
        "snmp_pdu_getbulk.c"
        "snmp_pdu_trap.c"
        "snmp_dispatch.c"
        "snmp_message.c"
    INCLUDE_DIRS "include"
    REQUIRES ber mib
)
