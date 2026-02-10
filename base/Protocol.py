import random, Flags

MAX_PACKAGE_LEN = 50 # TODO: change that into Meshtastic constant
MAX_BITS_ADDR = 32
ADDR_BYTES = MAX_BITS_ADDR // 8   # = 4 bytes
PSK_BYTES = 2
MAX_PACKET_LEN = 1

def encode_addr(n: int) -> bytes:
    return n.to_bytes(ADDR_BYTES, byteorder="big")


def decode_addr(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def check_signature(payload) -> bool:
    return (b'!mesh' == payload[0:5] and 9 + 2*ADDR_BYTES <= len(payload))


def generate_psk() -> bytes:
    return random.randrange(65535).to_bytes(PSK_BYTES, byteorder="big")


def verify_psk(psk) -> bool:
    return bytes == type(psk) and 2 == len(psk)


def build_packet(src: int, dst: int, flag: int, payload: bytes, psk=None) -> tuple:
    """ Construct a set of N >= 1 frames based on a given payload. """

    flag_byte = bytes([flag & 0xFF])
    if None == psk or not verify_psk(psk):
        psk = generate_psk()

    head = (
        '!mesh'.encode()
        + flag_byte
        + encode_addr(src)
        + encode_addr(dst)
        + psk
    )

    if 0 == len(payload):
        return head

    if bytes != type(payload):
        payload = payload.encode()

    counter = 0
    x = MAX_PACKAGE_LEN - len(head)
    frame = []

    if 15*MAX_PACKET_LEN < int(len(payload) / x) + 1:
        print(f"error: too long (longer than {15*MAX_PACKET_LEN})")

    if Flags.DATA == int.from_bytes(flag_byte):
        for i in range(0, len(payload), x):
            frame.append(head + counter.to_bytes(1) + payload[0+i:x+i])
            counter += 1

        frame.append(head + counter.to_bytes(1) + b'!finish')
    else:
        frame.append(head + b'0' + payload)

    return frame, psk


def parse_frame(raw: bytes) -> dict:
    """
        Parse a given frame.
        returns a dict with (src, dst, flag, PSK, payload)
    """
    raw = raw if isinstance(raw, (bytes, bytearray)) else raw.encode()

    response = {
        "flag": raw[5],
        "src": decode_addr(raw[6: (6 + ADDR_BYTES)]),
        "dst": decode_addr(raw[(6 + ADDR_BYTES):(6 + 2*ADDR_BYTES)]),
        "psk": decode_addr(raw[(6 + 2*ADDR_BYTES):(8 + 2*ADDR_BYTES)])
    }

    if (8 + 2*ADDR_BYTES) < len(raw):
        response["counter"] = raw[(8 + 2*ADDR_BYTES)]
        response["payload"] = raw[(9 + 2*ADDR_BYTES):]

    return response
