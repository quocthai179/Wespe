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

**Why scalars only.** The registry (`mib_registry.c`) is a flat sorted
array with no notion of conceptual/indexed tables (`SEQUENCE OF`,
`INDEX`). Fine for ~15-25 fixed scalar objects; would need extending
before, say, exposing multiple temperature sensors as table rows —
explicitly deferred, see `PLAN.md`'s open items.

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
