"""Malformed/adversarial SNMP datagram corpus, shared between
fuzz_replay.py (sends these over a real UDP socket at a real target --
hardware or tools/dev_agent/dev_agent.c) and anyone poking at the agent
interactively. This is the network-facing counterpart to
host_tests/test_fuzz_corpus.c's corpus; the two aren't required to be
byte-identical, but they cover the same categories of malformed input on
purpose.

Each entry is (name, bytes). Entries with no comment are self-explanatory
from their construction; trickier ones note what they're specifically
targeting.
"""

def _ber_len(n: int) -> bytes:
    """Definite-length BER length octets for content length `n`."""
    if n < 0x80:
        return bytes([n])
    b = bytearray()
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _ber_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(content)) + content


def _ber_pos_int(value: int, tag: int = 0x02) -> bytes:
    """Minimal encoding for a non-negative integer (the only kind these
    table-shaped corpus entries below need -- request-id/error-status/
    error-index/max-repetitions are all >= 0)."""
    if value == 0:
        content = bytes([0])
    else:
        b = bytearray()
        v = value
        while v:
            b.insert(0, v & 0xFF)
            v >>= 8
        if b[0] & 0x80:
            b.insert(0, 0x00)  # pad so it isn't read as negative
        content = bytes(b)
    return _ber_tlv(tag, content)


def _ber_oid(arcs) -> bytes:
    """BER OID content for `arcs` (a list of ints, arbitrary precision --
    deliberately not clamped to 32 bits, so passing an arc >= 2**32 here
    produces a real base-128 VLQ overflow case the same way a hostile
    packet would, without hand-deriving the byte layout."""
    first = arcs[0] * 40 + arcs[1]
    body = bytearray([first])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(chunk)
    return _ber_tlv(0x06, bytes(body))


def _null() -> bytes:
    return bytes([0x05, 0x00])


def _varbind(oid_bytes: bytes, value_bytes: bytes = None) -> bytes:
    return _ber_tlv(0x30, oid_bytes + (value_bytes if value_bytes is not None else _null()))


def _pdu(tag: int, request_id: int, field2: int, field3: int, varbinds) -> bytes:
    content = (
        _ber_pos_int(request_id)
        + _ber_pos_int(field2)
        + _ber_pos_int(field3)
        + _ber_tlv(0x30, b"".join(varbinds))
    )
    return _ber_tlv(tag, content)


def _message(version: int, community: str, pdu_bytes: bytes) -> bytes:
    content = _ber_pos_int(version) + _ber_tlv(0x04, community.encode("ascii")) + pdu_bytes
    return _ber_tlv(0x30, content)


GET_REQUEST = 0xA0
GET_BULK_REQUEST = 0xA5

CORPUS = [
    ("empty", b""),
    ("single_byte_sequence_tag", bytes([0x30])),
    ("truncated_long_form_length", bytes([0x30, 0x81])),
    ("indefinite_length", bytes([0x30, 0x80, 0x00, 0x00])),
    ("length_exceeds_buffer", bytes([0x30, 0x7F, 0x02, 0x01, 0x00])),
    (
        "random_noise_64b",
        bytes(((0xC0FFEE * 1103515245 + 12345 * i) >> 16) & 0xFF for i in range(64)),
    ),
    (
        "plausible_get_request_v2c_public",
        # SEQUENCE { version=1(v2c), community="public", GetRequest {
        #   request-id=1, error-status=0, error-index=0,
        #   varbind-list { { sysDescr.0, NULL } } } }
        bytes(
            [
                0x30, 0x29,
                0x02, 0x01, 0x01,
                0x04, 0x06, ord("p"), ord("u"), ord("b"), ord("l"), ord("i"), ord("c"),
                0xA0, 0x1C,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x00,
                0x02, 0x01, 0x00,
                0x30, 0x0E,
                0x30, 0x0C,
                0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
                0x05, 0x00,
            ]
        ),
    ),
    (
        # Table-shaped hostile input (docs/PLAN-TABLES.md Phase 14), the
        # network-facing counterpart of host_tests/test_fuzz_corpus.c's
        # equivalent cases -- runnable against tools/dev_agent/dev_agent.c,
        # which has real ifTable/ifXTable/wespeSensorTable rows to walk
        # into. Absurd row index: wespeSensorTable's entry + column 1 +
        # the largest single-sub-identifier row index.
        "table_cell_max_uint32_index",
        _message(1, "public", _pdu(GET_REQUEST, 1, 0, 0, [
            _varbind(_ber_oid([1, 3, 6, 1, 4, 1, 99999, 2, 6, 1, 1, 0xFFFFFFFF]))
        ])),
    ),
    (
        # An OID whose last arc needs more than 5 base-128 groups to
        # encode -- unrepresentable in a uint32_t sub-identifier. Must be
        # rejected cleanly by ber_decode_oid()'s overflow guard, not
        # wrap/truncate/read out of bounds.
        "oid_arc_exceeds_uint32",
        _message(1, "public", _pdu(GET_REQUEST, 1, 0, 0, [
            _varbind(_ber_oid([1, 3, 2**40]))
        ])),
    ),
    (
        # GETBULK with max-repetitions far exceeding any real table's
        # size, aimed at wespeSensorTable's actual entry OID -- must
        # truncate cleanly (SNMP_MAX_VARBINDS), not attempt to build a
        # response sized for a million repetitions.
        "getbulk_huge_max_repetitions_over_table",
        _message(1, "public", _pdu(GET_BULK_REQUEST, 1, 0, 1000000, [
            _varbind(_ber_oid([1, 3, 6, 1, 4, 1, 99999, 2, 6, 1]))
        ])),
    ),
]


def with_corrupted_last_byte(entry_bytes: bytes) -> bytes:
    """Flips the high bit of the final byte -- a cheap, generic way to
    turn any well-formed packet into a plausible malformed one (a
    corrupted length/continuation bit, garbage trailing content, etc.)
    without hand-deriving a new byte layout per case."""
    if not entry_bytes:
        return entry_bytes
    return entry_bytes[:-1] + bytes([entry_bytes[-1] ^ 0x80])


def build_full_corpus():
    """The static CORPUS list, plus a corrupted variant of the one
    plausible-looking well-formed request, and every prefix-truncation of
    it -- the same "truncate a good packet at every length" technique
    host_tests/test_fuzz_corpus.c uses, here exercised over a real socket."""
    entries = list(CORPUS)
    good = dict(CORPUS)["plausible_get_request_v2c_public"]
    entries.append(("corrupted_plausible_request", with_corrupted_last_byte(good)))
    for n in range(len(good) + 1):
        entries.append((f"truncated_plausible_request_{n}b", good[:n]))
    return entries
