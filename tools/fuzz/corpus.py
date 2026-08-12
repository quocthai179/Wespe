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
