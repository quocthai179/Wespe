# Wespe — Project Plan

## Context

`quocthai179/wespe` starts as a blank slate: only `README.md` (the project
pitch) and an MIT `LICENSE` exist — no code, no build config, no MIB, no
docs. The README describes the goal: turn an ESP32 into a genuine
SNMP-speaking hardware device — exposing temperature, relay state, uptime,
and more via a custom MIB — so that a separate SNMP-MCP polling engine
(built elsewhere) can be validated against real hardware/UDP traffic instead
of simulators only. It's also explicitly meant as a hands-on exercise in
implementing SNMP at the protocol level, a vantage point the author hasn't
worked from before despite deep SNMP4J/enterprise-NMS experience.

This document lays out the from-scratch build: architecture, MIB design,
repo layout, and a phased milestone sequence to take the repo from empty to
a working, real-hardware SNMP demo.

**Decisions locked in:**
- Implement the SNMP agent **from scratch** (hand-rolled UDP, ASN.1/BER, PDU
  logic) — no third-party embedded SNMP library. This is the point of the
  exercise.
- Framework: **ESP-IDF** (native, FreeRTOS + lwIP), not Arduino.
- Protocol scope for MVP: **SNMPv1 + SNMPv2c** (community-string auth), with
  the architecture designed so **SNMPv3 (USM)** can be added later without
  rewriting the PDU/MIB layers.
- Hardware: **ESP32-S3** dev board. Exact temperature sensor / relay module
  not yet specified — plan assumes a common default (DS18B20 + GPIO relay
  module) behind a swappable hardware-abstraction layer, flagged as a TBD to
  confirm once parts are in hand.

---

## Repo layout to create

```
firmware/                        # ESP-IDF project (idf.py build root)
  CMakeLists.txt
  sdkconfig.defaults             # target=esp32s3
  main/
    app_main.c                   # NVS -> WiFi connect -> start agent/sensor tasks
    wifi_provisioning.c/.h
    Kconfig.projbuild             # RO/RW community strings, trap target, WiFi creds, GPIO pins
  components/
    ber/                        # ASN.1 BER codec — NO ESP-IDF/FreeRTOS deps (host-buildable)
      ber_encode.c  ber_decode.c  include/ber_codec.h ber_types.h
    snmp_core/                  # message parsing, security-model dispatch, PDU handlers
      snmp_message.c             # version-sniff + security-model dispatch table (v3 extension point)
      snmp_security_community.c  # v1/v2c community model
      snmp_pdu_get.c snmp_pdu_set.c snmp_pdu_getbulk.c snmp_pdu_trap.c
      snmp_dispatch.c
    mib/                        # OID table + lookup/GETNEXT-walk
      mib_registry.c              # sorted array, binary search, lower-bound walk
      mib_ii.c                    # standard system group
      mib_wespe.c                 # custom WESPE-MIB, bound to hal/ callbacks
    transport/
      snmp_udp.c                  # FreeRTOS task: bind :161 recv/send; trap sender :162
    hal/                         # hardware abstraction — swappable/mockable
      sensor_ds18b20.c relay_gpio.c sysinfo_esp32.c
      sensor_mock.c relay_mock.c   # for bring-up before hardware is wired
host_tests/                     # standalone native CMake project (no ESP-IDF)
  CMakeLists.txt  test_ber_encode.c test_ber_decode.c test_mib_registry.c
mibs/
  WESPE-MIB.txt                 # authoritative SMIv2 module
tools/
  snmp_test.py                  # pysnmp scripted integration test
  fuzz/                         # malformed-packet corpus + replay script (Phase 8)
docs/
  architecture.md mib-design.md hardware-wiring.md v3-readiness.md testing.md
.github/workflows/
  host-tests.yml  idf-build.yml  mib-lint.yml
```

**Key constraint:** `components/ber/` must only use `stdint.h`/`stddef.h`/
`string.h` — never an ESP-IDF or FreeRTOS header. That's what lets the exact
same source build both inside the firmware and inside `host_tests/`, so the
codec — the piece most worth testing rigorously — never needs real hardware
to verify.

---

## Core architecture

**UDP transport**: one FreeRTOS task owns a UDP socket bound to `:161`;
`recvfrom()` → bounded buffer (cap ~1472 bytes) → `snmp_dispatch_process()` →
`sendto()` the response. A separate outbound-only path sends TRAPs to a
configured `trap_dest_ip:162`.

**BER codec**: definite-length BER only (SNMP never uses indefinite-length,
which simplifies the decoder). Generic TLV parser underneath; typed helpers
for INTEGER/OCTET STRING/NULL/OID/SEQUENCE plus SNMP application types
(IpAddress, Counter32, Gauge32/Unsigned32, TimeTicks, Opaque — Counter64
explicitly deferred). Encode by building right-to-left into a scratch buffer
(prepend tag+length once content length is known — the same trick mbedTLS's
`asn1write.c` uses) then one final `memmove`. Every decoder returns a status
enum and caps nested-SEQUENCE recursion at a small fixed depth (~6) — this
is the module Phase 8's malformed-packet fuzzing targets directly.

**Message dispatch — the SNMPv3-readiness extension point** (the most
important architectural decision): `snmp_message_parse_header()` decodes
only the outer SEQUENCE + `version` field generically, then dispatches to a
registered **security-model interface**:

```c
typedef struct {
    int (*process_incoming)(const uint8_t *msg, size_t len, snmp_pdu_ctx_t *out_ctx);
    int (*prepare_outgoing)(const snmp_pdu_ctx_t *ctx, uint8_t *out, size_t cap, size_t *out_len);
} snmp_security_model_t;
```

MVP registers one implementation (`snmp_security_community.c`) for v1/v2c.
It decodes the community string, sets an abstract `access_mode`
(NONE/READ/READWRITE) on a neutral `snmp_pdu_ctx_t`, and **the PDU/MIB
layers never see a raw community string** — only `access_mode`/`principal`.
Adding SNMPv3 later means writing `snmp_security_usm.c` against the same
two-function interface and registering it for `version == 3`; zero changes
needed in the PDU handlers or MIB registry. Phase 9 proves this works with a
USM *stub* (parses enough to respond correctly, no real crypto yet).

**MIB tree**: a `const`, build-time-sorted flat array of
`{oid, oid_len, type, access, getter, setter}`, not a pointer-based tree —
appropriate for the ~15-25 scalar objects in scope. GET = binary search;
GETNEXT/GETBULK = lower-bound search + forward walk. Living in flash as
`const` data, with only the getter/setter callbacks varying, is exactly what
makes `hal/sensor_mock.c` swappable for `hal/sensor_ds18b20.c` without
touching any SNMP code. (Caveat for later: this flat-array design doesn't
natively support conceptual/indexed tables — fine to defer until
multi-sensor support is actually needed.)

**PDU handlers**: GetRequest/GetNextRequest read via the registry;
SetRequest is two-pass (validate all varbinds, only then commit — preserves
SNMP's all-or-nothing SET semantics); GetBulkRequest expands
non-repeaters/max-repetitions into a flattened, size-bounded response;
Trap/SNMPv2-Trap builds a fire-and-forget PDU (InformRequest deferred — no
retry state machine in MVP). Internally, MIB lookups return a
version-neutral result enum (`MIB_OK`, `NO_SUCH_OBJECT`, `NO_SUCH_INSTANCE`,
`END_OF_VIEW`, `WRONG_TYPE`, `NOT_WRITABLE`, ...) which a single
`snmp_error_translate(version, ...)` step turns into v1's PDU-level
error-status/error-index or v2c's per-varbind exception values
(`noSuchObject`=0x80, `noSuchInstance`=0x81, `endOfMibView`=0x82) — one PDU
builder, no duplicated version-specific logic.

**Access control**: two configured community strings (`Kconfig.projbuild`,
defaults `"public"`/`"private"`, documented as demo-only, not
production-safe). A message matching neither community gets silently
dropped (per SNMP convention — no response leaks less than an error would).

---

## MIB design

**Standard MIB-II `system` group** (`1.3.6.1.2.1.1`): sysDescr, sysObjectID,
sysUpTime, sysContact (RW), sysName (RW), sysLocation (RW), sysServices —
the usual 7 scalars, needed so any generic SNMP tool recognizes the device.

**Custom WESPE-MIB** under a placeholder private-enterprise arc
`1.3.6.1.4.1.99999` (not a real registered IANA PEN — flagged as an open
item to fix later):

| Object | OID suffix | Type | Access |
|---|---|---|---|
| wespeTemperature | `.2.1.0` | INTEGER (tenths of °C) | RO |
| wespeRelayState | `.2.2.0` | INTEGER enum off(0)/on(1) | **RW** — the SET-exercising object |
| wespeUptimeSeconds | `.2.3.0` | Gauge32 | RO |
| wespeFreeHeapBytes | `.2.4.0` | Gauge32 | RO (bonus) |
| wespeWifiRssi | `.2.5.0` | INTEGER (dBm) | RO (bonus) |
| wespeRelayStateChangeTrap / wespeTemperatureThresholdTrap | `.3.0.1` / `.3.0.2` | NOTIFICATION-TYPE | — |

`mibs/WESPE-MIB.txt` is authored as a real SMIv2 module (`MODULE-IDENTITY`,
`OBJECT-TYPE` per object, `NOTIFICATION-TYPE` for the traps) and validated
with `smilint -s -l 6 mibs/WESPE-MIB.txt`. It's the OID system of record;
`mib_wespe.c` is kept manually in sync with it.

---

## Phased build-up

| Phase | Focus | Exit criteria |
|---|---|---|
| 0 | ESP-IDF scaffold, WiFi connect, heartbeat blink | Board joins WiFi, logs IP |
| 1 | UDP echo + hand-built single-OID v1 GET for sysDescr.0 (before the general codec exists) | `snmpget -v1 -c public <ip> sysDescr.0` returns correctly |
| 2 | General BER codec + `host_tests/` unit tests; rewire Phase 1 through it | Host tests green in CI; Phase 1 check still passes |
| 3 | Dispatch skeleton incl. security-model extension point (built now, not deferred) + MIB-II group + GETNEXT | `snmpwalk` over `1.3.6.1.2.1.1` returns all 7 scalars |
| 4 | WESPE-MIB wired to real DS18B20 + GPIO relay via `hal/` | `snmpwalk` over `1.3.6.1.4.1.99999` matches physical reality |
| 5 | SetRequest (two-pass) + RW community gating | `snmpset` toggles relay physically; RO-community SET rejected; bad-type SET doesn't crash |
| 6 | GetBulkRequest (v2c), size-bounded | `snmpbulkwalk` matches `snmpwalk`; large max-repetitions truncates cleanly |
| 7 | Traps: coldStart on boot, relay-change, temperature-threshold (with hysteresis) | All three observed correctly in `snmptrapd` |
| 8 | Hardening: malformed/truncated/oversized/deep-nested packet corpus + replay | Full corpus replay, zero crashes/reboots |
| 9 | v3-readiness stub (`snmp_security_usm_stub.c`) + docs/demo polish | `snmpget -v3` gets a graceful rejection, not a hang; docs are enough for a fresh contributor to pick up |

---

## Testing / verification strategy

- **Host-side unit tests** (`host_tests/`): plain native CMake target linking
  directly against `components/ber/*.c` + `mib_registry.c` with a mocked
  table — round-trip encode/decode, boundary values (0, negative INTEGER,
  multi-byte lengths, OID arcs >127 needing base-128 VLQ encoding), malformed
  input rejection. This is the fast primary iteration loop, no target
  toolchain needed.
- **Real-hardware integration**: net-snmp CLI tools (`snmpget`, `snmpwalk`,
  `snmpbulkwalk`, `snmpset`, `snmptrapd`) from a PC on the same LAN — the
  main "does it interoperate with a standards-compliant implementation" gate
  at every phase, directly serving the README's "real agent, real UDP
  traffic, real edge cases" goal.
- **Scripted validation**: `tools/snmp_test.py` (pysnmp) or a small SNMP4J-
  based harness (leaning on existing expertise) scripting: walk MIB-II, walk
  WESPE-MIB, SET relay + read back, trigger threshold trap + listen.
- **MIB validation**: `smilint -s -l 6 mibs/WESPE-MIB.txt`, plus
  `snmptranslate -Tp -m ALL -M mibs/` as a load sanity check.
- **CI**: `host-tests.yml` (native, fast), `idf-build.yml` (`idf.py build`
  via the `espressif/idf` Docker image, compile-only), `mib-lint.yml`
  (`smilint`).

---

## Open items / explicitly deferred

SNMPv3 USM real crypto (HMAC auth + AES/DES priv) · DTLS transport ·
OTA updates · registering a real IANA Private Enterprise Number ·
PCB/enclosure design · conceptual/indexed-table MIB support (multi-sensor) ·
InformRequest with retry/timeout · runtime-configurable credentials via
NVS+provisioning (vs. compile-time Kconfig) · Counter64 support · confirming
exact sensor/relay part numbers once hardware is on hand.

## Critical files

- `firmware/components/ber/ber_decode.c` / `ber_encode.c` — the from-scratch
  codec; correctness here underpins everything else.
- `firmware/components/snmp_core/snmp_message.c` — the v3-readiness
  extension point; get this right in Phase 3, not as a retrofit.
- `firmware/components/mib/mib_registry.c` — sorted-array OID table, binary
  search, GETNEXT lower-bound walk.
- `firmware/components/mib/mib_wespe.c` — seam between protocol code and
  real hardware via `hal/`.
- `mibs/WESPE-MIB.txt` — authoritative OID documentation, `smilint`-checked.
