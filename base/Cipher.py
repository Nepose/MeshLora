from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def prime_factors_distinct(n: int) -> list[int]:
    """Return distinct prime factors of n."""
    factors = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2  # 2, then odd divisors
    if n > 1:
        factors.append(n)
    return factors


def find_generator_mod_prime(p: int) -> int:
    """Find a primitive root modulo prime p (generator of Z_p*)."""
    if p < 3:
        raise ValueError("p must be an odd prime >= 3")
    phi = p - 1
    qs = prime_factors_distinct(phi)

    for g in range(2, p - 1):
        # g is a generator iff g^(phi/q) != 1 mod p for all prime factors q of phi
        if all(pow(g, phi // q, p) != 1 for q in qs):
            return g

    raise RuntimeError("No generator found (p might not be prime?)")


def derive_session_key(shared_secret: int, psk: bytes) -> bytes:
    """Derive a 32-byte session key from DH shared secret and PSK via HKDF-SHA256."""
    key_material = shared_secret.to_bytes(8, byteorder="big")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=psk)
    return hkdf.derive(key_material)


def build_nonce(src: int, dst: int, psk: bytes) -> bytes:
    """Build a 12-byte deterministic nonce: psk(2) || src(4) || dst(4) || 0x0000(2)."""
    return psk + src.to_bytes(4, byteorder="big") + dst.to_bytes(4, byteorder="big") + b"\x00\x00"


def encrypt_payload(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with ChaCha20-Poly1305 AEAD."""
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)


def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with ChaCha20-Poly1305 AEAD. Raises InvalidTag on failure."""
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
