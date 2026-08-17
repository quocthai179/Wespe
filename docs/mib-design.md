# MIB Design

The authoritative OID documentation is [`mibs/WESPE-MIB.txt`](../mibs/WESPE-MIB.txt)
(SMIv2, `smilint`-clean — see [`testing.md`](testing.md)). This document
explains the numbering and how it maps to code.

## Tree

```
iso.org.dod.internet.mgmt.mib-2.system     1.3.6.1.2.1.1        (standard MIB-II, mib_ii.c)
├─ sysDescr.0                              .1   OCTET STRING RO
├─ sysObjectID.0                           .2   OID          RO  → 1.3.6.1.4.1.99999.1.1
├─ sysUpTime.0                             .3   TimeTicks    RO
├─ sysContact.0                            .4   OCTET STRING RW
├─ sysName.0                               .5   OCTET STRING RW
├─ sysLocation.0                           .6   OCTET STRING RW
└─ sysServices.0                           .7   INTEGER      RO  (64, static)

iso.org.dod.internet.private.enterprises.99999   wespeMIB   (custom, mib_wespe.c)
├─ wespeAgent                              .1
│  └─ wespeAgentESP32S3                    .1.1     ← sysObjectID.0 points here
├─ wespeObjects                            .2
│  ├─ wespeTemperature.0                   .2.1.0   INTEGER (tenths °C)  RO
│  ├─ wespeRelayState.0                    .2.2.0   INTEGER {off,on}     RW
│  ├─ wespeUptimeSeconds.0                 .2.3.0   Gauge32              RO
│  ├─ wespeFreeHeapBytes.0                 .2.4.0   Gauge32              RO
│  └─ wespeWifiRssi.0                      .2.5.0   INTEGER (dBm)        RO
├─ wespeTraps                              .3
│  ├─ wespeRelayStateChangeTrap            .3.1     NOTIFICATION-TYPE
│  └─ wespeTemperatureThresholdTrap        .3.2     NOTIFICATION-TYPE
└─ wespeConformance                        .4       (OBJECT-GROUP / MODULE-COMPLIANCE)
```

```
iso.org.dod.internet.mgmt.mib-2.interfaces   1.3.6.1.2.1.2   (standard IF-MIB subset, mib_iftable.c)
├─ ifNumber.0                     .1.0   INTEGER       RO  (= 1: the WiFi station)
└─ ifTable / ifEntry              .2.1
   ├─ ifIndex                     .1     INTEGER       RO
   ├─ ifDescr                     .2     OCTET STRING  RO
   ├─ ifType                      .3     INTEGER       RO  (71 = ieee80211)
   ├─ ifMtu                       .4     INTEGER       RO
   ├─ ifSpeed                     .5     Gauge32       RO
   ├─ ifPhysAddress               .6     OCTET STRING  RO  (real MAC)
   ├─ ifAdminStatus               .7     INTEGER       RO
   ├─ ifOperStatus                .8     INTEGER       RO
   ├─ ifLastChange                .9     TimeTicks     RO
   ├─ ifInOctets                  .10    Counter32     RO  (known gap, see below)
   └─ ifOutOctets                 .16    Counter32     RO  (known gap, see below)

iso.org.dod.internet.mgmt.mib-2.31.1.1.1   ifXTable / ifXEntry   1.3.6.1.2.1.31.1.1.1   (mib_iftable.c)
├─ ifName          .1    OCTET STRING  RO
├─ ifHCInOctets     .6    Counter64     RO  (known gap, see below)
└─ ifHCOutOctets    .10   Counter64     RO  (known gap, see below)
```

Both are **standard IANA MIBs** (RFC1213/RFC2863) -- unlike WESPE-MIB,
their `.txt` module definitions live in every serious NMS and
`net-snmp`'s own MIB directory already, not in `mibs/`; implementing the
well-known OIDs correctly is all that's needed for `snmpwalk -m ALL`/an
NMS auto-discovery pass to render them with proper names automatically.
Row count is permanently 1 (the WiFi station is this device's only real
network interface) -- see `mib_iftable.c`'s `if_first_index()`/
`if_next_index()`.

**Known gap:** `ifInOctets`/`ifOutOctets`/`ifHCInOctets`/`ifHCOutOctets`
currently always report `0`. The intent (docs/PLAN-TABLES.md Phase 13a)
was sourcing them from lwIP's per-netif `mib2_counters`
(`LWIP_MIB2_CALLBACKS`), but confirming that's actually enabled and
populated on ESP-IDF v5.3 requires real hardware bring-up, which hasn't
happened yet (see [`hardware-wiring.md`](hardware-wiring.md)). Reporting
a fabricated nonzero number would be strictly worse than a correctly-
typed, honestly-zero counter, so this is a documented placeholder to
revisit once hardware exists -- not a bug. Every other ifTable/ifXTable
column above is real device data (`sysinfo_wifi_mac()`,
`sysinfo_wifi_oper_up()`, etc. -- see `device_hal/sysinfo.h`).
`tools/dev_agent/dev_agent.c`'s mock versions of these two tables *do*
report nonzero, climbing counters, specifically so the table-walk/
GETBULK/Counter64 machinery has something realistic to exercise without
waiting on that hardware verification.

`99999` is a **placeholder**, not a real IANA-assigned Private Enterprise
Number — see the open item in [`v3-readiness.md`](v3-readiness.md).
Registering a real one and updating this file plus `mib_ii.c`/`mib_wespe.c`
together is a prerequisite for anything beyond a lab/demo deployment,
since another placeholder-99999 device on the same network would collide.

Notifications are direct children of `wespeTraps` (`wespeTraps.1`,
`wespeTraps.2`), not nested under a reserved `.0` arc — the more common
convention in modern private MIBs (e.g. IF-MIB's `linkDown`/`linkUp`
under `snmpTraps`), and it sidesteps `smilint`'s "implicit node
definition" note that the `.0` convention triggers.

## Code ↔ MIB correspondence

Each `mib_object_t` in `mib_ii.c`/`mib_wespe.c` is `{oid, oid_len,
value_tag, access, getter, setter}` — a direct C mirror of one
`OBJECT-TYPE`'s `OID`/`SYNTAX`/`MAX-ACCESS`. There's no code generation
from the `.txt` module (an explicitly deferred stretch goal, see
`PLAN.md`); the two are kept in sync by hand, and a mismatch would show
up immediately as `smilint` documenting one OID while the agent actually
answers a different one at that address — worth checking whenever either
file changes.

**Scalars and conceptual tables.** `mib_ii.c`/`mib_wespe.c` register flat
`mib_object_t` arrays (scalars) the same way they always have; `mib_iftable.c`
(and Phase 13b's `mib_sensor_table.c`) instead register a `mib_table_t`
(`mib_table.h`) -- column definitions plus row-iteration/cell-access
callbacks, no `SEQUENCE OF`/`INDEX` machinery of their own to hand-roll
per table. The registry (`mib_registry.c`) resolves both kinds through
one unified API (`mib_registry_resolve()`/`_resolve_next()`) so
`snmp_core`'s PDU handlers never branch on which kind an OID names — see
`docs/PLAN-TABLES.md` Phase 11 for the design and `mib_table.h`'s comments
for the column-major GETNEXT-ordering contract implementers must follow.

**Why `wespeTemperature` is `INTEGER` in tenths, not a float.** SNMP/BER
has no native floating-point type (SMIv2's `Integer32`/`Gauge32` are it).
Fixed-point tenths-of-a-degree is the conventional workaround, same as
e.g. `HOST-RESOURCES-MIB` does for percentages-with-decimals elsewhere in
the SNMP world.

**Why `wespeRelayState` is a plain `INTEGER` enum, not something
fancier.** It's the one write-exercising object in the whole MIB
(everything else is read-only telemetry), so keeping its type maximally
simple keeps the two-pass `SetRequest` validation in `snmp_pdu_set.c`
easy to reason about — a real type/value check (`0` or `1`, nothing
else), not a rubber-stamp.
