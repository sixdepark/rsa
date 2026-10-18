"""Wiener's attack against RSA public keys with a small private exponent."""

from math import isqrt


def continued_fraction(numerator, denominator):
    """Return the simple continued fraction expansion of numerator/denominator."""
    if not isinstance(numerator, int) or isinstance(numerator, bool):
        raise TypeError("numerator must be an integer")
    if not isinstance(denominator, int) or isinstance(denominator, bool):
        raise TypeError("denominator must be an integer")
    if numerator < 0:
        raise ValueError("numerator must be non-negative")
    if denominator <= 0:
        raise ValueError("denominator must be positive")

    terms = []
    while denominator:
        quotient, remainder = divmod(numerator, denominator)
        terms.append(quotient)
        numerator, denominator = denominator, remainder

    return terms


def convergents(terms):
    """Yield (numerator, denominator) pairs for continued fraction terms."""
    previous_numerator, numerator = 0, 1
    previous_denominator, denominator = 1, 0

    for term in terms:
        if not isinstance(term, int) or isinstance(term, bool) or term < 0:
            raise ValueError("continued fraction terms must be non-negative integers")

        next_numerator = term * numerator + previous_numerator
        next_denominator = term * denominator + previous_denominator
        yield next_numerator, next_denominator

        previous_numerator, numerator = numerator, next_numerator
        previous_denominator, denominator = denominator, next_denominator


def recover_private_key(e, n):
    """Recover d and the RSA factors from public values e and n, if vulnerable.

    The returned dictionary contains ``d``, ``p``, ``q``, ``phi``, and ``k``.
    ``None`` is returned when no convergent produces valid RSA factors.
    """
    if not isinstance(e, int) or isinstance(e, bool):
        raise TypeError("e must be an integer")
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError("n must be an integer")
    if n <= 2:
        raise ValueError("n must be greater than 2")
    if not 1 < e < n:
        raise ValueError("e must satisfy 1 < e < n")

    # For a vulnerable key, a convergent k/d of e/n also satisfies
    # e*d - k*phi(n) = 1.
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or d == 0:
            continue

        ed_minus_one = e * d - 1
        if ed_minus_one % k != 0:
            continue

        phi = ed_minus_one // k
        if phi <= 0:
            continue

        # Since phi(n) = n - (p + q) + 1, p and q are the roots of
        # x^2 - (n - phi + 1)x + n = 0.
        factor_sum = n - phi + 1
        discriminant = factor_sum * factor_sum - 4 * n
        if discriminant < 0:
            continue

        square_root = isqrt(discriminant)
        if square_root * square_root != discriminant:
            continue
        if (factor_sum + square_root) % 2 != 0:
            continue

        p = (factor_sum + square_root) // 2
        q = (factor_sum - square_root) // 2
        if p > 1 and q > 1 and p * q == n:
            return {
                "d": d,
                "p": p,
                "q": q,
                "phi": phi,
                "k": k,
            }

    return None


def wiener_attack(e, n):
    """Return the recovered private exponent d, or None if the attack fails."""
    result = recover_private_key(e, n)
    return None if result is None else result["d"]
