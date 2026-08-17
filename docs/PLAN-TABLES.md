# Plan — Phase 10–14: Conceptual Tables, Counter64, and Memory Correctness

## Context

Phases 0–9 ([`PLAN.md`](PLAN.md)) delivered a working from-scratch SNMP
v1/v2c agent, merged in PR #1. But it exposes **12 scalar objects and
nothing else**, and `mib_registry.c` is scalar-only by design.

That is the gap this phase closes. Real network devices are *mostly
tables* — an NMS or polling engine spends the overwhelming majority of
its time walking `ifTable`-shaped data, doing GETBULK across columns,
handling rows that appear and disappear between polls, and computing
deltas over 64-bit counters. Against 12 scalars, a polling engine
exercises almost none of its real code paths. Against a real table it
exercises nearly all of them.

Given the project's current purpose is **pitching the SNMP-MCP concept**
(the polling engine itself hasn't been started) and **no hardware is on
hand yet**, this phase is scoped so that:

- everything is verifiable via `tools/dev_agent` + mock backends, with no
  ESP32 required;
- the headline demo is "point any NMS at Wespe and it discovers network
  interfaces and sensors, just like a switch" — which is far more
  convincing than a handful of scalars;
- the work stays honest: the `ifTable` data comes from real ESP-IDF
  network state, not fabricated numbers.

### Prerequisite discovered while planning (P0 — must fix first)

Measured against the current `HEAD`:

| Thing | Size |
|---|---|
| UDP task stack (`transport/snmp_udp.c:93`) | 8 192 B |
| `snmp_pdu_ctx_t`, allocated on that stack in `snmp_message_process()` | **10 056 B** |
| `snmp_pdu_handle_getbulk()` locals (`response[24]` + `cursor[24]`) | **+19 968 B** |

The very first SNMP request on real hardware would overflow the task
stack. This was invisible until now because host tests run with ~8 MB
stacks and the ESP-IDF CI job is compile-only. Tables make it strictly
worse (GETBULK over a table is exactly the deep path). **Fix this before
adding any table code.**

---

## Phase 10 — Memory correctness (P0)

**Goal:** the agent's peak stack usage is a documented, CI-enforced
number well under the task stack, with headroom for tables.

1. **Shrink `snmp_varbind_t`** (`mib/include/mib_types.h`, currently
   416 B): make the value storage a `union` (`value_tag` already
   discriminates it — the original "deliberately not a union" comment
   traded memory for simplicity, a trade that no longer holds), and
   reduce `BER_MAX_OID_LEN` 32 → 20 arcs (the deepest OID this project
   produces is ~13 arcs: `ifTable` cell = 11, WESPE table cell = 12).
   Target ≈ 220 B/varbind.
2. **Stop putting the context on the stack.** The UDP task handles one
   datagram at a time, so a single file-scope `static snmp_pdu_ctx_t` in
   `snmp_message.c` is correct and free — but the non-reentrancy must be
   stated explicitly in `snmp_message.h` (it is currently implied by
   nothing).
3. **Remove GETBULK's double buffer.** `snmp_pdu_getbulk.c` currently
   builds a full `response[]` copy *and* a `cursor[]` array. Reuse the
   context's varbind array in place and keep only the small `cursor[]`
   (one per repeater, not one per response slot).
4. **Guard it in CI.** Add `_Static_assert(sizeof(snmp_pdu_ctx_t) <=
   WESPE_PDU_CTX_BUDGET_BYTES, ...)`. This turns the existing
   compile-only `idf-build.yml` into a real memory regression gate —
   which is the only kind of check that would have caught this.
5. Raise the UDP task stack to a measured value with margin, and record
   the actual high-water mark via `uxTaskGetStackHighWaterMark()` behind
   a debug Kconfig.

Only after this is `SNMP_MAX_VARBINDS` raised (24 → ~50) so GETBULK can
return a useful slice of a table in one round trip.

---

## Phase 11 — Table support in the MIB registry

**Goal:** the registry can serve a whole conceptual-table subtree, and
the PDU handlers stop caring whether an object is a scalar or a cell.

### The interface change

Today `mib_registry_find*()` returns a `const mib_object_t *` whose OID
is fully known up front. That cannot work for a table, where GETNEXT
must return an OID the registry *computes* (`.entry.<column>.<index>`).
Replace both with a resolution API:

```c
typedef struct {
    uint32_t      oid[BER_MAX_OID_LEN];  /* fully-resolved instance OID */
    size_t        oid_len;
    uint8_t       value_tag;
    mib_access_t  access;
    const void   *binding;               /* scalar object, or table + column + index */
    uint32_t      index;
    uint8_t       column;
} mib_resolved_t;

mib_result_t mib_registry_resolve(const uint32_t *oid, size_t len, mib_resolved_t *out);
mib_result_t mib_registry_resolve_next(const uint32_t *oid, size_t len, mib_resolved_t *out);
mib_result_t mib_resolved_get(const mib_resolved_t *r, snmp_varbind_t *vb);
mib_result_t mib_resolved_set(const mib_resolved_t *r, const snmp_varbind_t *vb);
```

This *simplifies* the callers: `snmp_pdu_get.c`'s `lookup_and_fetch()`,
`snmp_pdu_set.c`'s two-pass validate/commit, and
`snmp_pdu_getbulk.c`'s `getnext_into()` all collapse to
resolve-then-get, with no scalar/table branching anywhere in
`snmp_core/`.

### The table entry model

Follow the net-snmp "iterator" shape — it is the model that handles
**sparse** indices, which matters because rows must be allowed to
disappear:

```c
typedef struct {
    const uint32_t *entry_oid;      /* the Entry node, e.g. …4.1 */
    uint8_t         entry_oid_len;
    const mib_column_t *columns;    /* {column_number, value_tag, access} */
    size_t          column_count;
    mib_result_t (*first_index)(uint32_t *out);
    mib_result_t (*next_index)(uint32_t current, uint32_t *out);
    mib_result_t (*index_exists)(uint32_t index);
    mib_result_t (*get_cell)(uint8_t column, uint32_t index, snmp_varbind_t *vb);
    mib_result_t (*set_cell)(uint8_t column, uint32_t index, const snmp_varbind_t *vb);
} mib_table_t;
```

MVP supports a **single `Integer32` index** (`ifIndex`-style). Multi-part
and string-valued indices (`INDEX { a, b }`) are deferred — call it out
in `mib-design.md` rather than half-building it.

### Ordering — the part that is easy to get wrong

GETNEXT must be **column-major**, because that is what plain
lexicographic OID ordering produces and what every walker expects:

```
…4.1.1.1, …4.1.1.2, …4.1.1.3,   ← column 1, every row
…4.1.2.1, …4.1.2.2, …4.1.2.3,   ← then column 2, every row
```

`resolve_next` must handle every entry point correctly:
- a bare prefix (`…4`, `…4.1`, `…4.1.2` with no index) → first row of the
  appropriate column;
- last row of a column → first row of the next column;
- last row of the last column → fall *out* of the table subtree and
  continue into the next registry entry;
- an index that no longer exists → the next index strictly greater than
  it (not an error — this is the row-disappeared case).

These are exactly the cases the host tests must pin down.

---

## Phase 12 — Counter64

- `ber_encode_unsigned64_tagged()` / `ber_decode_unsigned64()` for tag
  `0x46`, plus a `uint64_t` arm in the varbind union
  (`ber_encode.c`/`ber_decode.c`, `mib_types.h`).
- **The v1 edge case, which is the interesting part:** `Counter64` does
  not exist in SNMPv1. Per RFC 2089 / RFC 3584 a v1 manager must never
  see one — a v1 GETNEXT has to **skip over** Counter64 objects entirely,
  and a v1 GET of one returns `noSuchName`. This lives naturally in
  `snmp_error.c`/the resolve loop, and is precisely the sort of
  version-dependent behavior a polling engine gets wrong — i.e. exactly
  the "real edge cases" the README promises.

---

## Phase 13 — The actual tables

**`ifTable` subset (standard, `1.3.6.1.2.1.2`)** — the headline. Because
it is a *standard* MIB, every NMS and `snmpwalk -m ALL` renders it with
proper names and semantics automatically, with zero extra config. The
ESP32-S3 genuinely has network interfaces, so this is real data, not a
mock:

- `ifNumber` (scalar), then per-row: `ifIndex`, `ifDescr`, `ifType`
  (`ieee80211(71)`), `ifMtu`, `ifSpeed`, `ifPhysAddress` (real MAC via
  `esp_wifi_get_mac`), `ifAdminStatus`, `ifOperStatus`, `ifLastChange`.
- Octet/packet counters: source from lwIP's per-netif `mib2_counters`
  (requires `LWIP_MIB2_CALLBACKS`). **Verify this is actually enabled and
  populated in ESP-IDF v5.3 before committing to it** — if it is not,
  either enable it via `sdkconfig.defaults` or expose only the fields we
  can source honestly and document the omission. Do not invent numbers on
  the real backend.
- Counter64 high-capacity counters (`ifHCInOctets`/`ifHCOutOctets`) come
  from the same source, widened.

**`wespeSensorTable` (custom, under `wespeObjects`)** — demonstrates the
custom-MIB table path and a **writable column**:

- `wespeSensorIndex`, `wespeSensorLabel` (**read-write** — exercises SET
  through the new resolve path), `wespeSensorTempDeciC`,
  `wespeSensorReadCount` (Counter64), `wespeSensorStatus`.
- Architecturally honest: 1-Wire genuinely supports multiple DS18B20s on
  one bus, so a multi-sensor table is the real shape this device would
  take — the mock backend simply reports N simulated sensors today.
- **Opt-in "volatile rows" Kconfig**: rows appear/disappear on a timer.
  Deliberately included because a polling engine *must* tolerate the row
  set changing mid-walk, and almost nothing else lets you test that on
  demand.

Both must be added to `mibs/WESPE-MIB.txt` (the custom one) and kept
`smilint`-clean; the `ifTable` side imports from the standard `IF-MIB`
rather than redefining it.

---

## Phase 14 — Verification, hardening, demo

- **Host tests** (`host_tests/test_mib_table.c`, new): every ordering
  case above, sparse/disappearing indices, column boundaries, table→next
  entry fallout, Counter64 round-trip, and v1 Counter64 skip/noSuchName.
- **Extend the fuzz corpus** (`test_fuzz_corpus.c`, `tools/fuzz/`) with
  table-shaped hostile input: absurd index values, index arcs > 2³²,
  truncated cell OIDs, GETBULK with `max-repetitions` far exceeding the
  table size (must truncate cleanly, now that the response can actually
  be large).
- **`dev_agent`** grows the same two tables so all of the above is
  exercisable with no hardware.
- **Demo script** (`tools/demo.sh`): a single command that walks
  `ifTable`, GETBULK-walks it, SETs a sensor label, shows Counter64
  climbing between two polls, and shows a row disappearing. This is the
  pitch artifact.
- Update `docs/architecture.md`, `docs/mib-design.md`, `docs/testing.md`
  with captured real output, same as Phase 0–9 did.

---

## Verification (end to end, no hardware needed)

```sh
cd host_tests && cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure        # incl. new table + Counter64 suites
./build/dev_agent 1161 &

snmpwalk     -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.2      # ifTable, named by IF-MIB
snmpbulkwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.2      # same data, GETBULK path
snmpset      -v2c -c private 127.0.0.1:1161 <wespeSensorLabel>.1 s "rack-top"
snmpget      -v1  -c public 127.0.0.1:1161 <ifHCInOctets>.1    # must be noSuchName (v1)
snmpwalk     -v1  -c public 127.0.0.1:1161 1.3.6.1.2.1.2      # must SKIP Counter64 columns

python3 tools/snmp_test.py 127.0.0.1 1161
python3 tools/fuzz/fuzz_replay.py 127.0.0.1 1161
smilint -s -l 6 -p SNMPv2-SMI -p SNMPv2-TC -p SNMPv2-CONF mibs/WESPE-MIB.txt
```

CI (`host-tests`, `idf-build` incl. the new `_Static_assert` memory gate,
`mib-lint`) must be green.

## Critical files

- `firmware/components/mib/mib_registry.c` + `include/mib_tree.h`,
  `include/mib_object.h` — the resolve API and table walk.
- `firmware/components/mib/mib_iftable.c`, `mib_sensor_table.c` (new).
- `firmware/components/snmp_core/snmp_pdu_{get,set,getbulk}.c` —
  simplified onto `mib_resolved_t`.
- `firmware/components/snmp_core/snmp_message.c` — static context (P0).
- `firmware/components/ber/ber_{encode,decode}.c` — Counter64.
- `firmware/components/device_hal/` — multi-sensor + netif-stats backends
  (real + mock).

## Explicitly still deferred

SNMPv3/USM crypto · DTLS · OTA · real IANA enterprise number ·
multi-part/string table indices · `InformRequest` · NVS provisioning ·
PCB/enclosure · physical-hardware bring-up (blocked on parts).
