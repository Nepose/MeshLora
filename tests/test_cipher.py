import Cipher
import pytest


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
