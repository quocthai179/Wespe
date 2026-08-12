#!/usr/bin/env python3
"""Replays tools/fuzz/corpus.py's malformed/adversarial datagrams at a
real UDP socket -- the ESP32-S3 firmware (port 161) or the host-native
tools/dev_agent/dev_agent.c (default port 1161) -- and confirms the agent
survives every one of them: after each fuzz datagram, a legitimate
GetRequest for sysDescr.0 must still get a normal response within the
timeout. This is the network-facing counterpart to
host_tests/test_fuzz_corpus.c's ASan/UBSan-checked in-process corpus run
-- it can't detect memory corruption the way that can, but it's the only
one of the two that can be pointed at real hardware.

Usage:
    python3 tools/fuzz/fuzz_replay.py <host> [port] [--community public]
"""
import argparse
import socket
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from corpus import build_full_corpus  # noqa: E402


def build_get_sysdescr(community: bytes, request_id: int) -> bytes:
    """Hand-encodes a minimal, definitely-well-formed GetRequest for
    sysDescr.0 -- used as the "is the agent still alive and correct"
    liveness probe after each fuzz datagram, so it's deliberately built
    independently of anything in components/ (no reuse of the agent's own
    encoder for what's supposed to be an external check)."""
    rid = bytes([0x02, 0x01, request_id & 0x7F])
    pdu_inner = (
        rid
        + bytes([0x02, 0x01, 0x00])  # error-status
        + bytes([0x02, 0x01, 0x00])  # error-index
        + bytes(
            [
                0x30, 0x0E,  # varbind-list
                0x30, 0x0C,  # varbind
                0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # sysDescr.0
                0x05, 0x00,  # NULL
            ]
        )
    )
    pdu = bytes([0xA0, len(pdu_inner)]) + pdu_inner
    community_field = bytes([0x04, len(community)]) + community
    msg_inner = bytes([0x02, 0x01, 0x01]) + community_field + pdu  # version=v2c
    return bytes([0x30, len(msg_inner)]) + msg_inner


def probe_alive(sock: socket.socket, addr, community: bytes, request_id: int, timeout: float) -> bool:
    sock.settimeout(timeout)
    try:
        sock.sendto(build_get_sysdescr(community, request_id), addr)
        data, _ = sock.recvfrom(2048)
        return len(data) > 0
    except socket.timeout:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host")
    parser.add_argument("port", nargs="?", type=int, default=1161)
    parser.add_argument("--community", default="public")
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()

    addr = (args.host, args.port)
    community = args.community.encode("ascii")
    corpus = build_full_corpus()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"Baseline liveness check against {addr} ...")
    if not probe_alive(sock, addr, community, 0, args.timeout):
        print("FAIL: agent did not respond to a legitimate request before fuzzing even started -- "
              "check host/port/community before continuing.")
        return 1
    print("OK: agent responds normally.\n")

    failures = 0
    for i, (name, payload) in enumerate(corpus, start=1):
        try:
            sock.settimeout(args.timeout)
            sock.sendto(payload, addr)
            # A malformed/adversarial datagram should either be dropped
            # (no response, i.e. this recv times out) or -- if it happens
            # to parse as something the agent legitimately answers --
            # get an ordinary response. Neither is a failure by itself;
            # what matters is the liveness probe right after.
            try:
                sock.recvfrom(2048)
            except socket.timeout:
                pass
        except OSError as exc:
            # A raw socket-level error while just sending/receiving bytes
            # (as opposed to a timeout) is itself noteworthy.
            print(f"[{i}/{len(corpus)}] {name}: socket error sending fuzz payload: {exc}")

        if not probe_alive(sock, addr, community, i % 128, args.timeout):
            failures += 1
            print(f"[{i}/{len(corpus)}] {name} ({len(payload)} bytes): "
                  f"FAIL -- agent did not respond to the liveness probe afterward")
        # else: silent on success, to keep a big corpus run's output readable.

        time.sleep(0.01)  # give a real device's UDP task a moment to recover between cases

    print(f"\n{len(corpus)} fuzz datagram(s) replayed, {failures} liveness check(s) failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
