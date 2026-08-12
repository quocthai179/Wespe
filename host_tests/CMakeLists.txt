# Native (host-compiler) build of the hardware/RTOS-independent protocol
# core, so the BER codec, MIB registry, and SNMP message/PDU logic can be
# unit-tested without an ESP-IDF toolchain or real hardware.
#
#   cmake -S host_tests -B host_tests/build && cmake --build host_tests/build
#   ctest --test-dir host_tests/build --output-on-failure
cmake_minimum_required(VERSION 3.16)
project(wespe_host_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
add_compile_options(-Wall -Wextra -Werror -fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

set(BER_DIR ${CMAKE_SOURCE_DIR}/../firmware/components/ber)
set(MIB_DIR ${CMAKE_SOURCE_DIR}/../firmware/components/mib)
set(SNMP_CORE_DIR ${CMAKE_SOURCE_DIR}/../firmware/components/snmp_core)

add_library(ber_host STATIC
    ${BER_DIR}/ber_encode.c
    ${BER_DIR}/ber_decode.c
)
target_include_directories(ber_host PUBLIC ${BER_DIR}/include)

add_library(mib_host STATIC
    ${MIB_DIR}/mib_registry.c
)
target_include_directories(mib_host PUBLIC ${MIB_DIR}/include)
target_link_libraries(mib_host PUBLIC ber_host)

add_library(snmp_core_host STATIC
    ${SNMP_CORE_DIR}/snmp_codec.c
    ${SNMP_CORE_DIR}/snmp_error.c
    ${SNMP_CORE_DIR}/snmp_security.c
    ${SNMP_CORE_DIR}/snmp_security_community.c
    ${SNMP_CORE_DIR}/snmp_security_usm_stub.c
    ${SNMP_CORE_DIR}/snmp_pdu_get.c
    ${SNMP_CORE_DIR}/snmp_pdu_set.c
    ${SNMP_CORE_DIR}/snmp_pdu_getbulk.c
    ${SNMP_CORE_DIR}/snmp_pdu_trap.c
    ${SNMP_CORE_DIR}/snmp_dispatch.c
    ${SNMP_CORE_DIR}/snmp_message.c
)
target_include_directories(snmp_core_host PUBLIC ${SNMP_CORE_DIR}/include)
target_link_libraries(snmp_core_host PUBLIC ber_host mib_host)

enable_testing()

function(wespe_add_test name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE ${ARGN})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

wespe_add_test(test_ber_encode ber_host)
wespe_add_test(test_ber_decode ber_host)
wespe_add_test(test_mib_registry mib_host)
wespe_add_test(test_snmp_message snmp_core_host)
wespe_add_test(test_fuzz_corpus snmp_core_host)

# Standalone local dev/demo agent -- a real, runnable (non-test) UDP SNMP
# server for exercising the agent with real tools (snmpget/snmpwalk/
# snmpset/snmpbulkwalk, pysnmp) without any ESP32 hardware. Not part of
# `ctest`; see tools/dev_agent/dev_agent.c and docs/testing.md.
add_executable(dev_agent ${CMAKE_SOURCE_DIR}/../tools/dev_agent/dev_agent.c)
target_link_libraries(dev_agent PRIVATE snmp_core_host)
