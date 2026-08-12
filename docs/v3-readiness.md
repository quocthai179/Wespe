# SNMPv3 Readiness

## What exists today

`components/snmp_core/include/snmp_security.h` defines one interface:

```c
typedef struct {
    ber_status_t (*process_incoming)(const uint8_t *msg, size_t len, unsigned depth, snmp_pdu_ctx_t *out_ctx);
    ber_status_t (*prepare_outgoing)(const snmp_pdu_ctx_t *ctx, uint8_t *out, size_t cap, size_t *out_len);
} snmp_security_model_t;
```

`snmp_message.c` decodes only the outer `SEQUENCE` + `msgVersion`, looks
up whichever model is registered for that version
(`snmp_security_register()`/`snmp_security_lookup()` in
`snmp_security.c`), and delegates everything else to it. Two models are
registered today:

- **`snmp_security_community.c`** — the real v1/v2c implementation.
  Decodes the community string, maps it to `SNMP_ACCESS_NONE` /
  `READ` / `READWRITE` via the configured RO/RW community strings, and
  decodes the inner PDU. Registered for both `SNMP_VERSION_V1` and
  `SNMP_VERSION_V2C` (identical wire shape).
- **`snmp_security_usm_stub.c`** — registered for `SNMP_VERSION_V3`.
  Parses just enough of the v3 envelope (outer `SEQUENCE`, `msgVersion`,
  the `msgGlobalData SEQUENCE` header) to confirm the datagram is
  structurally well-formed SNMPv3, then **declines** — returns an error
  so `snmp_message_process()` drops the datagram, the same "no response"
  outcome as an unrecognized v1/v2c community. No USM authentication,
  encryption, or engine-ID/time-sync bookkeeping is implemented.

**Verified, not just asserted:** an actual `snmpget -v3` against the
host-native `dev_agent` build times out cleanly (client-side timeout, no
agent-side hang or crash) — see [`testing.md`](testing.md) for the
session. Everything else (`snmpget -v2c`, `snmpwalk`, `snmpset`,
`snmpbulkwalk`) against the same running process in the same session
confirms the stub doesn't interfere with v1/v2c traffic at all.

**Why this proves the extension point works**, not just that a stub
exists: `snmp_pdu_get.c`/`snmp_pdu_set.c`/`snmp_pdu_getbulk.c` and
`mib_registry.c` never reference community strings, USM, or any
version-specific concept — only `snmp_pdu_ctx_t::access_mode`/`principal`,
which any security model populates identically. Swapping the v3 stub for
a real implementation requires touching exactly one file plus adding new
ones; nothing downstream changes.

## What a real SNMPv3/USM implementation would add

A `snmp_security_usm.c` replacing the stub, same interface, would need:

1. **Engine ID / boots / time.** USM authentication depends on the
   agent's `snmpEngineID` (persisted across reboots — needs NVS storage)
   and `snmpEngineBoots`/`snmpEngineTime` (RFC3414 §2.3), used for replay
   protection. A discovery exchange (an unauthenticated Report PDU
   carrying these) has to run before a manager can send an authenticated
   request at all.
2. **Localized keys.** `usmUserAuthKeyLocalized`/`usmUserPrivKeyLocalized`
   derived from a passphrase via the RFC3414 §A.2 password-to-key
   algorithm (repeated MD5/SHA over the password expanded to 1MB,
   XORed with the engine ID) — needs an MD5 or SHA-1 implementation on
   the device (mbedTLS, bundled with ESP-IDF, covers this).
3. **HMAC-MD5-96 / HMAC-SHA-96 authentication** over the whole message
   (RFC3414 §6), truncated to 12 bytes, carried in
   `msgSecurityParameters`.
4. **DES-CBC or AES-CFB privacy** (RFC3414 §8 / RFC3826) to encrypt the
   PDU, with a per-message salt/IV derived from a local counter.
5. **View-based Access Control (VACM)**, RFC3415 — USM only authenticates
   *who*; a separate model decides *what* they can read/write. The
   current community model's crude RO/RW split would need to become a
   real VACM view if v3 users need different-shaped access than "read
   everything" / "read+write everything".

This is a substantial, security-sensitive undertaking — correctly
implementing #1-#3 alone is where most homegrown SNMPv3 agents introduce
real vulnerabilities (replay windows, timing side-channels in HMAC
comparison, key-derivation bugs). Treated here as explicitly out of
scope for this project's current phase, not a "should be quick" TODO.

## Other explicitly deferred items

(Superset of `PLAN.md`'s open items, kept here since this is where a
reader looking for "what's not done yet" will land.)

- Real SNMPv3 USM crypto (above).
- DTLS-secured transport (RFC 6353) as a USM alternative/complement.
- A real registered IANA Private Enterprise Number, replacing the
  `99999` placeholder throughout `mibs/WESPE-MIB.txt` and
  `mib_ii.c`/`mib_wespe.c`.
- Conceptual/indexed MIB tables (e.g. multiple temperature sensors) —
  `mib_registry.c` is scalar-only by design at the current object count.
- `InformRequest` (acknowledged traps with a retry/timeout state
  machine) — traps are fire-and-forget today (`snmp_pdu_trap.c`).
- `Counter64` support in the BER codec.
- OTA firmware updates.
- Runtime-configurable WiFi/community credentials via NVS + a
  provisioning flow, replacing today's compile-time Kconfig values.
- PCB/enclosure design beyond a breadboard/dev-board demo.
