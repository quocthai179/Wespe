# Testing

Three layers, from fastest/most isolated to closest-to-real:

1. **Host-native unit tests** (`host_tests/`) — no ESP-IDF, no hardware,
   ASan/UBSan-instrumented.
2. **MIB linting** (`smilint`, `snmptranslate`) — validates
   `mibs/WESPE-MIB.txt` as a standalone artifact.
3. **Real-client integration** — actual `net-snmp` CLI tools and a
   `pysnmp`-based script, talking real SNMP wire protocol to a running
   agent. Everything in this section was actually run against
   `tools/dev_agent/dev_agent.c` (see below) in the environment this
   project was built in; the exact commands and output are reproduced
   here, not just described.

## 1. Host-native unit tests

```
cd host_tests
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Builds `components/ber`, `components/mib`, and `components/snmp_core`
exactly as ESP-IDF will (see each component's `CMakeLists.txt` — the
`SRCS` lists are identical), linked into 5 native test binaries with
`-fsanitize=address,undefined -Wall -Wextra -Werror`. As last run:

```
100% tests passed, 0 tests failed out of 5
```

with real assertion counts (not vacuous zero-check passes):

| Binary | Checks |
|---|---|
| `test_ber_encode` | 173 |
| `test_ber_decode` | 51 |
| `test_mib_registry` | 19 |
| `test_snmp_message` | 68 |
| `test_fuzz_corpus` | 66 |

`test_fuzz_corpus` is the Phase 8 hardening suite: empty/truncated/
indefinite-length/oversized-length packets, every prefix-truncation of a
real request, a corrupted OID continuation bit, negative and
1,000,000-repetition `GetBulkRequest`s, an oversized community string,
and a max-varbind-count request — all confirmed to be handled safely
(no crash, no buffer overrun, response never exceeds the caller's
buffer) under the sanitizers.

## 2. MIB linting

```
smilint -s -l 6 -p SNMPv2-SMI -p SNMPv2-TC -p SNMPv2-CONF mibs/WESPE-MIB.txt
```

Clean except two lowest-severity (`[5]`, informational) notes:

```
mibs/WESPE-MIB.txt:116: [5] warning: notification `wespeRelayStateChangeTrap' is not reverse mappable
mibs/WESPE-MIB.txt:126: [5] warning: notification `wespeTemperatureThresholdTrap' is not reverse mappable
```

These are about whether a v2 `NOTIFICATION-TYPE` OID can be
auto-derived back into an SMIv1 `(enterprise, generic-trap,
specific-trap)` triple by a generic tool — irrelevant here, since
`snmp_pdu_trap.c`'s v1 encoder computes `specific-trap` itself rather
than relying on any such derivation. Common on real-world private MIBs.

`snmptranslate -Tp -m ALL -M mibs/` (the secondary load-sanity check
`PLAN.md` calls for) was attempted but could not be completed in the
sandbox this was built in: that environment's bundled net-snmp MIB set
is itself incomplete (its *own* default modules like `NET-SNMP-MIB`,
`UCD-SNMP-MIB` fail to resolve, independent of anything in this repo).
Re-run it in an environment with a complete net-snmp MIB installation
(a normal developer workstation, or CI with `snmp-mibs-downloader`
properly configured) — `smilint`'s clean result is the authoritative
check either way.

## 3. Real-client integration

### The `dev_agent` trick

`tools/dev_agent/dev_agent.c` links the exact same `components/ber`,
`components/mib`-shaped object bindings (in-memory instead of `device_hal/`
hardware), and `components/snmp_core` sources as the firmware, behind a
plain POSIX UDP socket instead of lwIP — a full agent that runs as an
ordinary Linux process:

```
cd host_tests && cmake -S . -B build && cmake --build build -j
./build/dev_agent 1161 &
```

```
[dev_agent] listening on 127.0.0.1:1161 (RO community 'public', RW community 'private')
```

This makes the *exact same* `net-snmp`/`pysnmp` commands below directly
reusable against real ESP32-S3 firmware later — just swap
`127.0.0.1:1161` for the board's DHCP address and port 161.

### net-snmp CLI

```
$ snmpget -v2c -c public -O n 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
.1.3.6.1.2.1.1.1.0 = STRING: "Wespe dev-agent (host build -- not real ESP32-S3 hardware)"

$ snmpwalk -v2c -c public -O n 127.0.0.1:1161 1.3.6.1.2.1.1
.1.3.6.1.2.1.1.1.0 = STRING: "Wespe dev-agent (host build -- not real ESP32-S3 hardware)"
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.99999.1.1
.1.3.6.1.2.1.1.3.0 = Timeticks: (1200) 0:00:12.00
.1.3.6.1.2.1.1.5.0 = STRING: "wespe-dev-agent"

$ snmpwalk -v2c -c public -O n 127.0.0.1:1161 1.3.6.1.4.1.99999
.1.3.6.1.4.1.99999.2.1.0 = INTEGER: 235
.1.3.6.1.4.1.99999.2.2.0 = INTEGER: 0
.1.3.6.1.4.1.99999.2.3.0 = Gauge32: 12
.1.3.6.1.4.1.99999.2.3.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

$ snmpget -v1 -c public -O n 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
.1.3.6.1.2.1.1.1.0 = STRING: "Wespe dev-agent (host build -- not real ESP32-S3 hardware)"

$ snmpset -v2c -c private -O n 127.0.0.1:1161 1.3.6.1.4.1.99999.2.2.0 i 1
.1.3.6.1.4.1.99999.2.2.0 = INTEGER: 1
[dev_agent] relay -> ON        # printed by the agent process itself

$ timeout 3 snmpset -v2c -c public -O n 127.0.0.1:1161 1.3.6.1.4.1.99999.2.2.0 i 0
$ echo $?
124                             # timed out: RO community correctly denied the write

$ snmpget -v2c -c public -O n 127.0.0.1:1161 1.3.6.1.4.1.99999.2.2.0
.1.3.6.1.4.1.99999.2.2.0 = INTEGER: 1     # confirms the rejected SET had no effect

$ snmpbulkwalk -v2c -c public -O n 127.0.0.1:1161 1.3.6.1.4.1.99999
.1.3.6.1.4.1.99999.2.1.0 = INTEGER: 235
.1.3.6.1.4.1.99999.2.2.0 = INTEGER: 1
.1.3.6.1.4.1.99999.2.3.0 = Gauge32: 24
.1.3.6.1.4.1.99999.2.3.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

$ snmpget -v1 -c public -O n 127.0.0.1:1161 1.3.6.1.4.1.99999.2.9.0
Error in packet
Reason: (noSuchName) There is no such variable name in this MIB.
Failed object: .1.3.6.1.4.1.99999.2.9.0

$ timeout 3 snmpget -v3 -l noAuthNoPriv -u nobody 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
$ echo $?
124                             # v3 declined gracefully -- times out, doesn't hang the agent

$ snmpget -v2c -c public -O n 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
.1.3.6.1.2.1.1.1.0 = STRING: "Wespe dev-agent (host build -- not real ESP32-S3 hardware)"
                                # agent still fully responsive after the v3 attempt
```

This is independent verification: `net-snmp` is a different codebase
entirely, developed with no knowledge of this implementation, correctly
decoding this project's from-scratch BER/SNMP encoding for GET, GETNEXT
(via walk), SET (accepted and correctly-rejected cases), GETBULK
(including its `endOfMibView` exception handling), v1 error semantics,
and community-based access control.

### `tools/snmp_test.py` (pysnmp)

```
pip install pysnmp
python3 tools/snmp_test.py 127.0.0.1 1161
```

Walks MIB-II and WESPE-MIB, SETs the relay with the RW community and
reads it back, confirms a RO-community SET is rejected, and runs a
GETBULK. Last run against `dev_agent`: **all checks passed** (see the
script's own inline comments for one real bug this run caught and fixed
during development — pysnmp's `next_cmd` doesn't stop advancing on its
own past `endOfMibView`, it re-returns the same OID with an
`EndOfMibView` value forever, so the walk helper has to recognize that
type explicitly rather than relying on the OID ever changing again).

### `tools/fuzz/fuzz_replay.py`

```
python3 tools/fuzz/fuzz_replay.py 127.0.0.1 1161
```

Sends `tools/fuzz/corpus.py`'s malformed datagrams over a real UDP
socket and confirms a legitimate follow-up request still succeeds after
each one. Last run: **49 fuzz datagrams replayed, 0 liveness failures**.
This is the network-facing counterpart to `test_fuzz_corpus.c` — it
can't detect memory corruption the way the ASan-instrumented host test
can, but unlike that one, it can be pointed at real ESP32-S3 hardware.
