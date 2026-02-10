from math import isqrt

def prime_factors_distinct(n: int) -> list[int]:
    """ Return distinct prime factors of n. """
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
    """ Find a primitive root modulo prime p (generator of Z_p*). """
    if p < 3:
        raise ValueError("p must be an odd prime >= 3")
    phi = p - 1
    qs = prime_factors_distinct(phi)

    for g in range(2, p - 1):
        # g is a generator iff g^(phi/q) != 1 mod p for all prime factors q of phi
        if all(pow(g, phi // q, p) != 1 for q in qs):
            return g

    raise RuntimeError("No generator found (p might not be prime?)")

#p = 1019  # example prime in your range
#g = find_generator_mod_prime(p)
#print("p =", p, "g =", g)

