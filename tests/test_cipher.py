import Cipher
import pytest
from cryptography.exceptions import InvalidTag


class TestPrimeFactorsDistinct:
    def test_returns_list(self):
        assert isinstance(Cipher.prime_factors_distinct(6), list)

    def test_prime_number(self):
        assert Cipher.prime_factors_distinct(7) == [7]

    def test_one_returns_empty(self):
        assert Cipher.prime_factors_distinct(1) == []

    def test_two(self):
        assert Cipher.prime_factors_distinct(2) == [2]

    def test_prime_squared_returns_single_factor(self):
        assert Cipher.prime_factors_distinct(4) == [2]

    def test_composite(self):
        assert Cipher.prime_factors_distinct(12) == [2, 3]

    def test_product_of_distinct_primes(self):
        assert Cipher.prime_factors_distinct(2 * 3 * 5 * 7) == [2, 3, 5, 7]

    def test_high_power_of_prime(self):
        assert Cipher.prime_factors_distinct(2**10) == [2]

    def test_large_prime(self):
        # 104729 is prime
        assert Cipher.prime_factors_distinct(104729) == [104729]

    def test_factors_are_prime(self):
        # Every returned factor should itself be prime
        factors = Cipher.prime_factors_distinct(360)
        for f in factors:
            assert Cipher.prime_factors_distinct(f) == [f]

    def test_factors_are_unique(self):
        result = Cipher.prime_factors_distinct(8)
        assert len(result) == len(set(result))


class TestFindGeneratorModPrime:
    def _is_primitive_root(self, g, p):
        """Return True if g is a primitive root modulo prime p."""
        phi = p - 1
        qs = Cipher.prime_factors_distinct(phi)
        return all(pow(g, phi // q, p) != 1 for q in qs)

    def test_raises_for_p_less_than_3(self):
        with pytest.raises(ValueError):
            Cipher.find_generator_mod_prime(2)

    def test_result_is_primitive_root_p5(self):
        g = Cipher.find_generator_mod_prime(5)
        assert self._is_primitive_root(g, 5)

    def test_result_is_primitive_root_p7(self):
        g = Cipher.find_generator_mod_prime(7)
        assert self._is_primitive_root(g, 7)

    def test_result_is_primitive_root_p11(self):
        g = Cipher.find_generator_mod_prime(11)
        assert self._is_primitive_root(g, 11)

    def test_result_is_primitive_root_p23(self):
        g = Cipher.find_generator_mod_prime(23)
        assert self._is_primitive_root(g, 23)

    def test_result_in_valid_range(self):
        p = 23
        g = Cipher.find_generator_mod_prime(p)
        assert 2 <= g <= p - 2

    def test_result_is_int(self):
        assert isinstance(Cipher.find_generator_mod_prime(7), int)

    def test_generates_full_group_p7(self):
        p = 7
        g = Cipher.find_generator_mod_prime(p)
        powers = {pow(g, k, p) for k in range(1, p)}
        assert powers == set(range(1, p))

    def test_generates_full_group_p11(self):
        p = 11
        g = Cipher.find_generator_mod_prime(p)
        powers = {pow(g, k, p) for k in range(1, p)}
        assert powers == set(range(1, p))

    def test_prime_from_project_range(self):
        # 1019 is a prime, referenced in the commented example in Cipher.py
        p = 1019
        g = Cipher.find_generator_mod_prime(p)
        assert self._is_primitive_root(g, p)

    def test_dh_shared_secret_symmetric(self):
        # Both sides of a Diffie-Hellman exchange must derive the same secret
        p = 1019
        g = Cipher.find_generator_mod_prime(p)
        a, b = 42, 137
        A = pow(g, a, p)
        B = pow(g, b, p)
        assert pow(A, b, p) == pow(B, a, p)


class TestDeriveSessionKey:
    def test_returns_32_bytes(self):
        key = Cipher.derive_session_key(123456789, b"\xab\xcd")
        assert len(key) == 32

    def test_returns_bytes(self):
        key = Cipher.derive_session_key(123456789, b"\xab\xcd")
        assert isinstance(key, bytes)

    def test_same_inputs_same_key(self):
        k1 = Cipher.derive_session_key(999, b"\x01\x02")
        k2 = Cipher.derive_session_key(999, b"\x01\x02")
        assert k1 == k2

    def test_different_psk_different_key(self):
        k1 = Cipher.derive_session_key(999, b"\x01\x02")
        k2 = Cipher.derive_session_key(999, b"\x03\x04")
        assert k1 != k2

    def test_different_shared_secret_different_key(self):
        k1 = Cipher.derive_session_key(111, b"\x01\x02")
        k2 = Cipher.derive_session_key(222, b"\x01\x02")
        assert k1 != k2

    def test_dh_symmetric_keys_match(self):
        # Keys derived from DH-symmetric shared secrets must be equal
        p, a, b = 1019, 42, 137
        g = Cipher.find_generator_mod_prime(p)
        shared_ab = pow(pow(g, a, p), b, p)
        shared_ba = pow(pow(g, b, p), a, p)
        psk = b"\xde\xad"
        assert Cipher.derive_session_key(shared_ab, psk) == Cipher.derive_session_key(
            shared_ba, psk
        )


class TestBuildNonce:
    def test_returns_12_bytes(self):
        nonce = Cipher.build_nonce(1, 2, b"\xaa\xbb")
        assert len(nonce) == 12

    def test_returns_bytes(self):
        assert isinstance(Cipher.build_nonce(1, 2, b"\xaa\xbb"), bytes)

    def test_starts_with_psk(self):
        psk = b"\x12\x34"
        nonce = Cipher.build_nonce(0, 0, psk)
        assert nonce[:2] == psk

    def test_encodes_src_big_endian(self):
        nonce = Cipher.build_nonce(src=0x01020304, dst=0, psk=b"\x00\x00")
        assert nonce[2:6] == b"\x01\x02\x03\x04"

    def test_encodes_dst_big_endian(self):
        nonce = Cipher.build_nonce(src=0, dst=0xAABBCCDD, psk=b"\x00\x00")
        assert nonce[6:10] == b"\xaa\xbb\xcc\xdd"

    def test_ends_with_two_zero_bytes(self):
        nonce = Cipher.build_nonce(1, 2, b"\x00\x01")
        assert nonce[10:] == b"\x00\x00"

    def test_different_src_different_nonce(self):
        n1 = Cipher.build_nonce(1, 2, b"\x00\x00")
        n2 = Cipher.build_nonce(3, 2, b"\x00\x00")
        assert n1 != n2

    def test_different_dst_different_nonce(self):
        n1 = Cipher.build_nonce(1, 2, b"\x00\x00")
        n2 = Cipher.build_nonce(1, 9, b"\x00\x00")
        assert n1 != n2


class TestEncryptDecryptPayload:
    _KEY = bytes(32)
    _NONCE = bytes(12)

    def test_encrypt_returns_bytes(self):
        ct = Cipher.encrypt_payload(self._KEY, self._NONCE, b"hello")
        assert isinstance(ct, bytes)

    def test_ciphertext_longer_than_plaintext_by_tag(self):
        # ChaCha20-Poly1305 appends a 16-byte authentication tag
        pt = b"hello world"
        ct = Cipher.encrypt_payload(self._KEY, self._NONCE, pt)
        assert len(ct) == len(pt) + 16

    def test_roundtrip(self):
        pt = b"secret message"
        ct = Cipher.encrypt_payload(self._KEY, self._NONCE, pt)
        assert Cipher.decrypt_payload(self._KEY, self._NONCE, ct) == pt

    def test_roundtrip_empty_payload(self):
        pt = b""
        ct = Cipher.encrypt_payload(self._KEY, self._NONCE, pt)
        assert Cipher.decrypt_payload(self._KEY, self._NONCE, ct) == pt

    def test_roundtrip_long_payload(self):
        pt = b"A" * 200
        ct = Cipher.encrypt_payload(self._KEY, self._NONCE, pt)
        assert Cipher.decrypt_payload(self._KEY, self._NONCE, ct) == pt

    def test_different_keys_different_ciphertext(self):
        key2 = bytes([1] * 32)
        ct1 = Cipher.encrypt_payload(self._KEY, self._NONCE, b"data")
        ct2 = Cipher.encrypt_payload(key2, self._NONCE, b"data")
        assert ct1 != ct2

    def test_tampered_ciphertext_raises(self):
        ct = Cipher.encrypt_payload(self._KEY, self._NONCE, b"secret")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            Cipher.decrypt_payload(self._KEY, self._NONCE, bytes(tampered))

    def test_wrong_key_raises(self):
        ct = Cipher.encrypt_payload(self._KEY, self._NONCE, b"secret")
        wrong_key = bytes([0xFF] * 32)
        with pytest.raises(InvalidTag):
            Cipher.decrypt_payload(wrong_key, self._NONCE, ct)

    def test_wrong_nonce_raises(self):
        ct = Cipher.encrypt_payload(self._KEY, self._NONCE, b"secret")
        wrong_nonce = bytes([0xFF] * 12)
        with pytest.raises(InvalidTag):
            Cipher.decrypt_payload(self._KEY, wrong_nonce, ct)

    def test_full_aead_roundtrip_with_dh(self):
        # Simulate a full DH + HKDF + AEAD roundtrip
        p, a, b = 1019, 42, 137
        g = Cipher.find_generator_mod_prime(p)
        shared = pow(pow(g, a, p), b, p)
        psk = b"\xca\xfe"
        src, dst = 0xAAAAAAAA, 0xBBBBBBBB

        key = Cipher.derive_session_key(shared, psk)
        nonce = Cipher.build_nonce(src, dst, psk)

        plaintext = b"hello from DH"
        ct = Cipher.encrypt_payload(key, nonce, plaintext)
        assert Cipher.decrypt_payload(key, nonce, ct) == plaintext
