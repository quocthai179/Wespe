# ASN.1 BER codec component. Deliberately has ZERO ESP-IDF/FreeRTOS
# dependencies (only stdint.h/stddef.h/string.h/limits.h) so these exact
# source files also build as a plain native target under host_tests/ --
# see host_tests/CMakeLists.txt.
idf_component_register(
    SRCS "ber_encode.c" "ber_decode.c"
    INCLUDE_DIRS "include"
)
