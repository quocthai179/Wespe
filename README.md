Wespe turns an ESP32 into a real, physical SNMP-managed device — exposing a custom MIB (temperature, relay state, uptime, and more) that can be polled just like an enterprise network device. 
Instead of validating the SNMP-MCP polling engine against simulators alone, Wespe provides a genuine hardware target: a real agent, real UDP traffic, real edge cases.

Built on deep SNMP4J and enterprise network-management expertise (developed through large-scale multi-vendor polling systems), 
Wespe is both a concrete hardware demo for pitching the SNMP-MCP concept and a hands-on exercise in implementing the SNMP protocol at the device level — 
a perspective rarely explored when working primarily at the enterprise management-system layer.

## Status

The SNMP agent (from-scratch BER codec, MIB registry, GET/GETNEXT/SET/GETBULK/TRAP
handling, and a pluggable security-model layer ready for SNMPv3) is implemented and
tested; the ESP-IDF firmware build (transport, hardware drivers, WiFi bring-up) is
written but not yet flashed to physical hardware. See [`docs/PLAN.md`](docs/PLAN.md)
for the full design and [`docs/testing.md`](docs/testing.md) for real integration-test
sessions against the agent.

## Repository layout

```
firmware/     ESP-IDF project (components/ber, mib, snmp_core, transport, hal; main/)
host_tests/   Native unit tests for the hardware-independent protocol core
mibs/         WESPE-MIB.txt, the authoritative SMIv2 MIB module
tools/        pysnmp integration script, fuzz replay tooling, dev_agent (see below)
docs/         Architecture, MIB design, hardware wiring, SNMPv3 readiness, testing
```

## Quick start (no hardware required)

The protocol core has zero ESP-IDF dependency, so you can build and run the whole
SNMP agent as a plain Linux process and talk to it with real tools:

```sh
cd host_tests
cmake -S . -B build && cmake --build build -j
./build/dev_agent 1161 &

snmpwalk -v2c -c public -O n 127.0.0.1:1161 1.3.6.1.4.1.99999
snmpset  -v2c -c private -O n 127.0.0.1:1161 1.3.6.1.4.1.99999.2.2.0 i 1

python3 tools/snmp_test.py 127.0.0.1 1161
```

Run the unit test suite (BER codec, MIB registry, full SNMP request/response paths,
and a malformed-packet hardening corpus — ASan/UBSan-instrumented):

```sh
ctest --test-dir host_tests/build --output-on-failure
```

## Building the firmware

Requires the [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/get-started/)
toolchain targeting `esp32s3`:

```sh
cd firmware
idf.py set-target esp32s3
idf.py menuconfig   # under "Wespe SNMP Agent Configuration": WiFi credentials,
                     # community strings, GPIOs (or enable mock hal/ for bring-up
                     # without a sensor/relay wired up yet -- see docs/hardware-wiring.md)
idf.py build flash monitor
```
