import Flags
import Protocol
import pytest

# Offsets within a frame (all frames share this header layout):
#   !mesh(5) | flag(1) | src(4) | dst(4) | psk(2) | counter(1) | payload(...)
_SRC_START = 6
_DST_START = _SRC_START + Protocol.ADDR_BYTES
_PSK_START = _DST_START + Protocol.ADDR_BYTES
_PSK_END = _PSK_START + Protocol.PSK_BYTES
_COUNTER_POS = _PSK_END
_PAYLOAD_START = _COUNTER_POS + 1


def _make_raw_frame(src, dst, flag, psk, counter, payload=b""):
    """Manually build a valid MeshLora frame without calling build_packet."""
    return (
        b"!mesh"
        + bytes([flag & 0xFF])
        + Protocol.encode_addr(src)
        + Protocol.encode_addr(dst)
        + psk
        + bytes([counter])
        + payload
    )


class TestEncodeAddr:
    def test_zero(self):
        assert Protocol.encode_addr(0) == b"\x00\x00\x00\x00"

    def test_one(self):
        assert Protocol.encode_addr(1) == b"\x00\x00\x00\x01"

    def test_256(self):
        assert Protocol.encode_addr(256) == b"\x00\x00\x01\x00"

    def test_max_address(self):
        assert Protocol.encode_addr(2**32 - 1) == b"\xff\xff\xff\xff"

    def test_output_is_bytes(self):
        assert isinstance(Protocol.encode_addr(0), bytes)

    def test_output_length(self):
        assert len(Protocol.encode_addr(99999)) == Protocol.ADDR_BYTES

    def test_big_endian_byte_order(self):
        # Most significant byte comes first
        assert Protocol.encode_addr(0x01020304) == b"\x01\x02\x03\x04"


class TestDecodeAddr:
    def test_zero(self):
        assert Protocol.decode_addr(b"\x00\x00\x00\x00") == 0

    def test_one(self):
        assert Protocol.decode_addr(b"\x00\x00\x00\x01") == 1

    def test_max(self):
        assert Protocol.decode_addr(b"\xff\xff\xff\xff") == 2**32 - 1

    def test_output_is_int(self):
        assert isinstance(Protocol.decode_addr(b"\x00\x00\x00\x05"), int)

    def test_big_endian_byte_order(self):
        assert Protocol.decode_addr(b"\x01\x02\x03\x04") == 0x01020304


class TestAddrRoundtrip:
    @pytest.mark.parametrize(
        "addr",
        [0, 1, 255, 256, 65535, 65536, 2956785160, 2**32 - 1],
    )
    def test_encode_then_decode(self, addr):
        assert Protocol.decode_addr(Protocol.encode_addr(addr)) == addr


class TestCheckSignature:
    # Minimum valid frame length: 9 + 2 * ADDR_BYTES = 17
    MIN_LEN = 9 + 2 * Protocol.ADDR_BYTES

    def _at_min_length(self):
        return b"!mesh" + b"\x00" * (self.MIN_LEN - 5)

    def test_valid_minimal_frame(self):
        assert Protocol.check_signature(self._at_min_length()) is True

    def test_valid_with_payload(self):
        assert Protocol.check_signature(self._at_min_length() + b"hello") is True

    def test_wrong_magic(self):
        frame = b"XXXXX" + b"\x00" * (self.MIN_LEN - 5)
        assert Protocol.check_signature(frame) is False

    def test_partial_magic(self):
        frame = b"!mes" + b"\x00" * (self.MIN_LEN - 4)
        assert Protocol.check_signature(frame) is False

    def test_empty(self):
        assert Protocol.check_signature(b"") is False

    def test_magic_only(self):
        assert Protocol.check_signature(b"!mesh") is False

    def test_one_below_minimum(self):
        frame = b"!mesh" + b"\x00" * (self.MIN_LEN - 5 - 1)
        assert Protocol.check_signature(frame) is False

    def test_accepts_bytearray(self):
        assert Protocol.check_signature(bytearray(self._at_min_length())) is True


class TestVerifyPsk:
    def test_valid_two_bytes(self):
        assert Protocol.verify_psk(b"\xAB\xCD") is True

    def test_valid_zeros(self):
        assert Protocol.verify_psk(b"\x00\x00") is True

    def test_wrong_type_int(self):
        assert Protocol.verify_psk(0xABCD) is False

    def test_wrong_type_str(self):
        assert Protocol.verify_psk("ab") is False

    def test_wrong_type_none(self):
        assert Protocol.verify_psk(None) is False

    def test_empty_bytes(self):
        assert Protocol.verify_psk(b"") is False

    def test_one_byte(self):
        assert Protocol.verify_psk(b"\x01") is False

    def test_three_bytes(self):
        assert Protocol.verify_psk(b"\x01\x02\x03") is False


class TestGeneratePsk:
    def test_returns_bytes(self):
        assert isinstance(Protocol.generate_psk(), bytes)

    def test_correct_length(self):
        assert len(Protocol.generate_psk()) == Protocol.PSK_BYTES

    def test_passes_verify(self):
        assert Protocol.verify_psk(Protocol.generate_psk()) is True

    def test_values_differ_across_calls(self):
        # With 65535 possible values, 20 calls should not all be identical
        results = {Protocol.generate_psk() for _ in range(20)}
        assert len(results) > 1


class TestBuildPacket:
    SRC = 100
    DST = 200
    PSK = b"\x12\x34"

    def test_returns_two_element_tuple(self):
        result = Protocol.build_packet(self.SRC, self.DST, Flags.DATA, b"hi", self.PSK)
        assert isinstance(result, tuple) and len(result) == 2

    def test_returns_provided_psk(self):
        _, psk = Protocol.build_packet(self.SRC, self.DST, Flags.DATA, b"hi", self.PSK)
        assert psk == self.PSK

    def test_generates_psk_when_none(self):
        _, psk = Protocol.build_packet(self.SRC, self.DST, Flags.DATA, b"hi")
        assert Protocol.verify_psk(psk)

    def test_data_frames_is_list(self):
        frames, _ = Protocol.build_packet(self.SRC, self.DST, Flags.DATA, b"hi", self.PSK)
        assert isinstance(frames, list)

    def test_data_last_frame_ends_with_finish(self):
        frames, _ = Protocol.build_packet(self.SRC, self.DST, Flags.DATA, b"hi", self.PSK)
        assert frames[-1].endswith(b"!finish")

    def test_all_frames_start_with_mesh_signature(self):
        frames, _ = Protocol.build_packet(self.SRC, self.DST, Flags.DATA, b"hi", self.PSK)
        for frame in frames:
            assert frame[:5] == b"!mesh"

    def test_non_data_flag_produces_one_frame(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.KEY_SEED, b'{"g":2,"p":7}', self.PSK
        )
        assert len(frames) == 1

    def test_non_data_frame_flag_byte(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.KEY_SEED, b"payload", self.PSK
        )
        assert frames[0][5] == Flags.KEY_SEED

    def test_non_data_frame_src_encoded(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.KEY_SEED, b"payload", self.PSK
        )
        src_bytes = frames[0][_SRC_START : _SRC_START + Protocol.ADDR_BYTES]
        assert Protocol.decode_addr(src_bytes) == self.SRC

    def test_non_data_frame_dst_encoded(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.KEY_SEED, b"payload", self.PSK
        )
        dst_bytes = frames[0][_DST_START : _DST_START + Protocol.ADDR_BYTES]
        assert Protocol.decode_addr(dst_bytes) == self.DST

    def test_string_payload_converted_to_bytes(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.KEY_SEED, "hello", self.PSK
        )
        assert isinstance(frames[0], bytes)

    def test_long_data_produces_multiple_frames(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.DATA, b"X" * 200, self.PSK
        )
        # Expect data frames + finish frame - at least 3 total
        assert len(frames) > 2

    def test_data_counters_start_at_zero_and_increment(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.DATA, b"X" * 100, self.PSK
        )
        # Exclude the finish frame
        counters = [frame[_COUNTER_POS] for frame in frames[:-1]]
        assert counters == list(range(len(counters)))

    def test_all_data_frames_pass_check_signature(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.DATA, b"hello world", self.PSK
        )
        for frame in frames:
            assert Protocol.check_signature(frame)


class TestParseFrame:
    """
    Tests use manually built frames so they do not depend on build_packet.
    A separate set of roundtrip tests combines both functions.
    """

    SRC = 100
    DST = 200
    PSK = b"\x12\x34"
    PSK_INT = 0x1234

    def _frame(self, flag=Flags.KEY_SEED, counter=0, payload=b"data"):
        return _make_raw_frame(self.SRC, self.DST, flag, self.PSK, counter, payload)

    def test_parse_src(self):
        assert Protocol.parse_frame(self._frame())["src"] == self.SRC

    def test_parse_dst(self):
        assert Protocol.parse_frame(self._frame())["dst"] == self.DST

    def test_parse_flag(self):
        assert Protocol.parse_frame(self._frame(flag=Flags.KEY_ACK))["flag"] == Flags.KEY_ACK

    def test_parse_psk_as_int(self):
        assert Protocol.parse_frame(self._frame())["psk"] == self.PSK_INT

    def test_parse_counter(self):
        assert Protocol.parse_frame(self._frame(counter=7))["counter"] == 7

    def test_parse_payload(self):
        assert Protocol.parse_frame(self._frame(payload=b"hello"))["payload"] == b"hello"

    def test_accepts_bytearray(self):
        frame = bytearray(self._frame())
        assert Protocol.parse_frame(frame)["src"] == self.SRC

    def test_frame_without_payload_has_no_payload_key(self):
        # A frame at exactly the counter position with nothing after
        frame = b"!mesh" + bytes([Flags.KEY_SEED]) + Protocol.encode_addr(self.SRC) + Protocol.encode_addr(self.DST) + self.PSK
        parsed = Protocol.parse_frame(frame)
        assert "payload" not in parsed

    def test_all_data_flag_values(self):
        for flag in [Flags.NDP, Flags.CONTROL, Flags.ACK, Flags.DATA, Flags.KEY_SEED, Flags.KEY_ACK, Flags.KEY_ERROR]:
            parsed = Protocol.parse_frame(self._frame(flag=flag))
            assert parsed["flag"] == flag


class TestBuildParseRoundtrip:
    """End-to-end tests combining build_packet and parse_frame."""

    SRC = 300
    DST = 400
    PSK = b"\xAB\xCD"

    def _build_and_parse_first(self, flag, payload):
        frames, _ = Protocol.build_packet(self.SRC, self.DST, flag, payload, self.PSK)
        return Protocol.parse_frame(frames[0])

    def test_roundtrip_src(self):
        parsed = self._build_and_parse_first(Flags.KEY_SEED, b"test")
        assert parsed["src"] == self.SRC

    def test_roundtrip_dst(self):
        parsed = self._build_and_parse_first(Flags.KEY_SEED, b"test")
        assert parsed["dst"] == self.DST

    def test_roundtrip_flag(self):
        parsed = self._build_and_parse_first(Flags.KEY_SEED, b"test")
        assert parsed["flag"] == Flags.KEY_SEED

    def test_roundtrip_psk_value(self):
        parsed = self._build_and_parse_first(Flags.KEY_SEED, b"test")
        assert parsed["psk"] == int.from_bytes(self.PSK, byteorder="big")

    def test_roundtrip_data_payload_present(self):
        parsed = self._build_and_parse_first(Flags.DATA, b"hello")
        assert "payload" in parsed

    def test_data_frames_counters_sequential(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.DATA, b"A" * 100, self.PSK
        )
        counters = [Protocol.parse_frame(f)["counter"] for f in frames[:-1]]
        assert counters == list(range(len(counters)))

    def test_finish_frame_ends_with_finish_bytes(self):
        frames, _ = Protocol.build_packet(
            self.SRC, self.DST, Flags.DATA, b"hello", self.PSK
        )
        finish = Protocol.parse_frame(frames[-1])
        assert finish["payload"] == b"!finish"
