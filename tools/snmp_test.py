#!/usr/bin/env python3
"""Scripted SNMP integration test for Wespe, using pysnmp as an
independent client implementation (i.e. not our own from-scratch codec on
both ends of the wire).

Targets pysnmp >= 7's async hlapi (`pysnmp.hlapi.v3arch.asyncio`). pysnmp's
API has changed across major versions (the classic synchronous
`pysnmp.hlapi` used in most older tutorials was rewritten as fully async
in pysnmp 7) -- if you're on an older pinned version, either upgrade or
adapt the calls below to your installed API's equivalent.

Usage:
    pip install pysnmp
    python3 tools/snmp_test.py <host> [port] [--ro-community public]
                                             [--rw-community private]

Runs against either the real ESP32-S3 firmware (port 161, needs root or a
capability grant for that privileged port) or the host-native dev_agent
(tools/dev_agent/dev_agent.c, default port 1161, no special privileges
needed) -- e.g.:

    (cd host_tests && cmake -S . -B build && cmake --build build)
    ./host_tests/build/dev_agent 1161 &
    python3 tools/snmp_test.py 127.0.0.1 1161

Exercises: walk MIB-II, walk WESPE-MIB, SET the relay + read back, GETBULK
over WESPE-MIB. See docs/testing.md for an example session (including
output captured against dev_agent) and for how this fits alongside the
host_tests/ unit tests and net-snmp CLI checks.
"""
import argparse
import asyncio
import sys

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    Integer,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_cmd,
    get_cmd,
    next_cmd,
    set_cmd,
)
from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

END_OF_WALK_TYPES = (EndOfMibView, NoSuchObject, NoSuchInstance)

MIB_II_SYSTEM = "1.3.6.1.2.1.1"
WESPE_MIB_OBJECTS = "1.3.6.1.4.1.99999.2"
WESPE_RELAY_STATE = "1.3.6.1.4.1.99999.2.2.0"

FAILURES = 0


def report(ok: bool, label: str) -> None:
    global FAILURES
    status = "OK  " if ok else "FAIL"
    print(f"[{status}] {label}")
    if not ok:
        FAILURES += 1


async def walk(engine, auth, target, ctx, base_oid, label):
    """GETNEXT-walks base_oid until it steps outside that subtree or the
    agent signals it's out of objects, printing every varbind along the
    way. Returns the varbinds seen.

    A v2c GETNEXT past the end of the MIB view doesn't raise an error or
    stop advancing on its own -- the agent (correctly, per RFC3416)
    re-returns the *same* requested OID with an EndOfMibView exception
    value forever, so the walk has to recognize that value type itself
    rather than relying on the OID ever changing again. (A stray
    NoSuchObject/NoSuchInstance is treated the same way, defensively --
    neither should appear mid-walk against a well-behaved agent, but
    "stop cleanly" beats "spin forever" either way.) """
    print(f"--- walking {label} ({base_oid}) ---")
    results = []
    current = base_oid
    for _ in range(64):  # generous bound so a genuine bug still can't spin forever
        error_indication, error_status, error_index, var_binds = await next_cmd(
            engine, auth, target, ctx, ObjectType(ObjectIdentity(current))
        )
        if error_indication:
            report(False, f"{label}: walk error: {error_indication}")
            return results
        if error_status:
            report(False, f"{label}: walk error-status: {error_status.prettyPrint()}")
            return results
        name, value = var_binds[0]
        if isinstance(value, END_OF_WALK_TYPES):
            break
        oid_str = str(name)
        if not oid_str.startswith(base_oid):
            break
        print(f"  {oid_str} = {value.prettyPrint()}")
        results.append((oid_str, value))
        current = oid_str
    else:
        report(False, f"{label}: walk did not terminate within the iteration bound")
        return results
    report(len(results) > 0, f"{label}: walk covered {len(results)} object(s)")
    return results


async def run(host: str, port: int, ro_community: str, rw_community: str) -> int:
    engine = SnmpEngine()
    ro_auth = CommunityData(ro_community, mpModel=1)  # mpModel=1 -> SNMPv2c
    rw_auth = CommunityData(rw_community, mpModel=1)
    target = await UdpTransportTarget.create((host, port), timeout=2, retries=1)
    ctx = ContextData()

    mib_ii_results = await walk(engine, ro_auth, target, ctx, MIB_II_SYSTEM, "MIB-II system group")
    report(len(mib_ii_results) >= 1, "MIB-II system group returned at least one object")

    wespe_results = await walk(engine, ro_auth, target, ctx, WESPE_MIB_OBJECTS, "WESPE-MIB objects")
    report(len(wespe_results) >= 1, "WESPE-MIB objects returned at least one object")

    print(f"--- SET {WESPE_RELAY_STATE} = 1 (RW community) ---")
    error_indication, error_status, error_index, var_binds = await set_cmd(
        engine, rw_auth, target, ctx, ObjectType(ObjectIdentity(WESPE_RELAY_STATE), Integer(1))
    )
    set_ok = not error_indication and not error_status
    report(set_ok, "SET wespeRelayState=1 with RW community succeeded")
    if not set_ok:
        print(f"  error_indication={error_indication} error_status={error_status}")

    print(f"--- GET {WESPE_RELAY_STATE} (read back) ---")
    error_indication, error_status, error_index, var_binds = await get_cmd(
        engine, ro_auth, target, ctx, ObjectType(ObjectIdentity(WESPE_RELAY_STATE))
    )
    readback_ok = not error_indication and not error_status and int(var_binds[0][1]) == 1
    report(readback_ok, "GET after SET reflects the new value")
    if var_binds:
        print(f"  {var_binds[0][0]} = {var_binds[0][1].prettyPrint()}")

    print(f"--- SET {WESPE_RELAY_STATE} = 0 (RO community, must be rejected) ---")
    error_indication, error_status, error_index, var_binds = await set_cmd(
        engine, ro_auth, target, ctx, ObjectType(ObjectIdentity(WESPE_RELAY_STATE), Integer(0))
    )
    # A read-only community SET is dropped silently by design (see
    # snmp_pdu_set.c) rather than answered with an error, so this
    # legitimately shows up as a timeout (errorIndication set), not an
    # errorStatus in the response.
    rejected_ok = bool(error_indication)
    report(rejected_ok, "SET with RO community was rejected (timed out, no response)")

    print(f"--- GETBULK {WESPE_MIB_OBJECTS} (non_repeaters=0, max_repetitions=10) ---")
    error_indication, error_status, error_index, var_binds = await bulk_cmd(
        engine, ro_auth, target, ctx, 0, 10, ObjectType(ObjectIdentity(WESPE_MIB_OBJECTS))
    )
    bulk_ok = not error_indication and len(var_binds) > 0
    report(bulk_ok, "GETBULK over WESPE-MIB returned varbinds")
    for name, value in var_binds:
        print(f"  {name} = {value.prettyPrint()}")

    engine.close_dispatcher() if hasattr(engine, "close_dispatcher") else None
    return FAILURES


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", help="Agent IP/hostname (e.g. 127.0.0.1 for dev_agent, or the ESP32-S3's DHCP address)")
    parser.add_argument("port", nargs="?", type=int, default=1161, help="Agent UDP port (default: 1161, dev_agent's default; use 161 for real firmware)")
    parser.add_argument("--ro-community", default="public")
    parser.add_argument("--rw-community", default="private")
    args = parser.parse_args()

    failures = asyncio.run(run(args.host, args.port, args.ro_community, args.rw_community))
    print(f"\n{failures} check(s) failed" if failures else "\nAll checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
