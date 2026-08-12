# Architecture

This document describes what's actually implemented, not just planned —
see [`PLAN.md`](PLAN.md) for the original design rationale, which this
mostly matches.

## Component graph

```
                 ┌──────────┐
                 │   main   │  app_main.c: boot sequence, coldStart trap,
                 │ (ESP-IDF)│  trap_monitor.c: relay/temperature watcher
                 └────┬─────┘
        ┌──────────────┼───────────────┬───────────────┐
        ▼              ▼               ▼               ▼
  ┌───────────┐  ┌───────────┐   ┌───────────┐   ┌───────────┐
  │ transport │  │ snmp_core │   │    mib    │   │device_hal │
  │ (ESP-IDF/ │─▶│ (portable)│──▶│ (portable)│──▶│ (ESP-IDF/ │
  │  sockets) │  │           │   │           │   │  mock)    │
  └───────────┘  └─────┬─────┘   └─────┬─────┘   └───────────┘
                       ▼               ▼
                  ┌───────────┐  (registry, mib_ii, mib_wespe)
                  │    ber    │
                  │ (portable)│
                  └───────────┘
```

"Portable" = zero ESP-IDF/FreeRTOS dependency, builds as plain host C (see
`host_tests/CMakeLists.txt`). Only `transport` and the real (non-mock)
`device_hal` backends touch ESP-IDF/lwIP APIs directly. (Named
`device_hal`, not `hal` — ESP-IDF ships its own built-in component
literally called `hal`, and a project component of the same name
silently shadows it, breaking mbedtls and anything else that expects the
real one. Found via a failing CI build; see `components/mib/CMakeLists.txt`'s
comment.) This is what makes
`tools/dev_agent/dev_agent.c` possible: it links `ber` + `mib` +
`snmp_core` unmodified and swaps in a plain POSIX-socket transport and
in-memory MIB bindings — a full agent, running as an ordinary Linux
process, that real SNMP clients can talk to. See
[`testing.md`](testing.md) for an actual session doing exactly that.

## Request/response flow

1. `transport/snmp_udp.c` (or `dev_agent.c`'s `main()`) `recvfrom()`s one
   UDP datagram and passes it to `snmp_message_process()`.
2. `snmp_message.c` decodes only the outer `SEQUENCE` + `msgVersion` —
   the one field every SNMP version puts in the same place — and looks up
   a registered `snmp_security_model_t` for that version
   (`snmp_security.c`'s registration table).
3. The model's `process_incoming()` decodes everything version-specific
   (community string for v1/v2c) and the inner PDU
   (`snmp_codec.c`'s `snmp_decode_request_pdu()`), producing a
   version-neutral `snmp_pdu_ctx_t`.
4. `snmp_dispatch_pdu()` routes on PDU tag to
   `snmp_pdu_get.c`/`snmp_pdu_set.c`/`snmp_pdu_getbulk.c`, which look
   objects up via `mib_registry_find()`/`mib_registry_find_next()` and
   call their getter/setter function pointers.
5. The model's `prepare_outgoing()` encodes the response, and
   `snmp_message_process()` hands the bytes back to the transport to
   `sendto()`.

Every step that can fail (bad community, malformed PDU, no write access,
response too large) makes `snmp_message_process()` return `0`, and the
transport sends nothing — the "drop silently" convention used throughout
(see `snmp_message.h`).

## Key design decisions

**Backward-building BER encoder.** Every `ber_encode_*` call prepends
into a caller-owned buffer from the end, so tag+length can be written
*after* content length is known — no separate length-computation pass.
Same technique as mbedTLS's `asn1write.c`. See `ber_encode.c`'s module
comment for the exact prepend-ordering rules (they're easy to get
backwards; there's a full derivation there plus round-trip tests).

**Flat sorted-array MIB registry**, not a tree. At ~15-25 objects total,
a pointer-based tree buys nothing but heap-fragmentation risk; binary
search on a `const` array is O(log n), trivially testable, and — because
only the getter/setter function pointers vary — is exactly what makes
`device_hal/sensor_mock.c` swap in for `device_hal/sensor_ds18b20.c`
without touching any SNMP code. See `mib_registry.c`.

**Security-model dispatch table = the SNMPv3 extension point.** PDU
handlers and the MIB layer never see a raw community string — only an
abstract `access_mode`. Adding real USM later means writing one new
`snmp_security_model_t` implementation and registering it for version 3;
`snmp_security_usm_stub.c` proves the seam works today without
implementing any cryptography. Full rationale in
[`v3-readiness.md`](v3-readiness.md).

**Two-pass SetRequest.** `snmp_pdu_set.c` validates every varbind
(exists, writable, correct type) before calling a single setter — SNMP's
all-or-nothing SET semantics, in every version (v2c has no per-varbind
exception concept for SET, unlike GET).

**Non-blocking sensor reads.** A DS18B20 conversion takes up to ~750ms;
doing that inline on every `GET` would stall the whole UDP responder.
`sensor_ds18b20.c` instead runs a background FreeRTOS task that samples
every 5s into a mutex-guarded cache; `sensor_read_temperature_decidegrees()`
just returns whatever's cached.

**GetBulk response grouped by repetition, not by variable**, per
RFC3416 — round 1 of every repeating varbind, then round 2, etc. — and
capped at `SNMP_MAX_VARBINDS` regardless of how large `max-repetitions`
is, so a hostile or just very large request truncates cleanly instead of
overflowing a fixed buffer. See `snmp_pdu_getbulk.c`.

## Critical files

- `components/ber/ber_encode.c` / `ber_decode.c` — the codec everything
  else builds on.
- `components/snmp_core/snmp_security.c` + `snmp_security_community.c` —
  the v3-readiness extension point and its only current implementation.
- `components/mib/mib_registry.c` — the OID lookup/walk data structure.
- `components/mib/mib_wespe.c` — where protocol meets hardware, via
  `device_hal/`.
- `mibs/WESPE-MIB.txt` — authoritative OID documentation; must stay in
  sync with `mib_ii.c`/`mib_wespe.c` by hand (no code generation).
