"""Generate and validate the fixed public fixture for the RSA-2048 demo."""

import argparse
import json
from math import gcd, isqrt
from pathlib import Path

from wiener_attack import recover_private_key


MODULUS_BITS = 2048
PRIME_BITS = MODULUS_BITS // 2
MESSAGE = 42
FIXTURE_PATH = (
    Path(__file__).resolve().parent / "results" / "wiener_demo_public.json"
)


def wiener_bound(n):
    """Return floor(n^(1/4) / 3), Wiener's classical sufficient bound."""
    return isqrt(isqrt(n)) // 3


def next_coprime_odd(value, phi):
    """Return an odd private exponent at or above value and coprime to phi."""
    candidate = max(3, value | 1)
    while gcd(candidate, phi) != 1:
        candidate += 2
    return candidate


def generate_fixture():
    """Generate a vulnerable key and return public data after full validation."""
    try:
        from Crypto.Util.number import getPrime
    except ImportError as error:
        raise RuntimeError(
            "PyCryptodome is required; run: python -m pip install -r requirements.txt"
        ) from error

    while True:
        p = getPrime(PRIME_BITS)
        q = getPrime(PRIME_BITS)
        n = p * q

        if p == q or n.bit_length() != MODULUS_BITS:
            continue
        if max(p, q) >= 2 * min(p, q):
            continue
        break

    phi = (p - 1) * (q - 1)
    bound = wiener_bound(n)

    # One eighth of the sufficient bound gives a comfortably vulnerable key
    # while retaining a large, realistic-looking private exponent.
    d = next_coprime_odd(bound // 8, phi)
    if not d < bound or gcd(d, phi) != 1:
        raise AssertionError("generated private exponent is not Wiener-vulnerable")

    e = pow(d, -1, phi)
    ciphertext = pow(MESSAGE, e, n)

    # Preparation-time validation compares against the original secrets. None
    # of p, q, phi, or d is written to the public fixture.
    recovered = recover_private_key(e, n)
    if recovered is None:
        raise AssertionError("Wiener attack did not recover the generated key")
    if recovered["d"] != d:
        raise AssertionError("recovered private exponent is incorrect")
    if {recovered["p"], recovered["q"]} != {p, q}:
        raise AssertionError("recovered prime factors are incorrect")
    if pow(ciphertext, recovered["d"], n) != MESSAGE:
        raise AssertionError("recovered key did not decrypt the test ciphertext")

    public_fixture = {
        "description": "Intentionally vulnerable RSA-2048 Wiener demo key",
        "modulus_bits": MODULUS_BITS,
        "public_exponent": str(e),
        "modulus": str(n),
        "ciphertext": str(ciphertext),
        "expected_plaintext": MESSAGE,
    }
    preparation_details = {
        "private_exponent_bits": d.bit_length(),
        "wiener_bound_bits": bound.bit_length(),
        "d_to_bound": d / bound,
    }
    return public_fixture, preparation_details


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing public demo fixture",
    )
    return parser.parse_args()


def main():
    arguments = parse_arguments()
    if FIXTURE_PATH.exists() and not arguments.force:
        raise SystemExit(
            f"Fixture already exists: {FIXTURE_PATH}\n"
            "Use --force only when intentionally preparing a new demo key."
        )

    public_fixture, details = generate_fixture()
    FIXTURE_PATH.parent.mkdir(exist_ok=True)
    with FIXTURE_PATH.open("w", encoding="utf-8") as file:
        json.dump(public_fixture, file, indent=2)
        file.write("\n")

    print("=== Wiener RSA-2048 Fixture Preparation ===")
    print(f"Public fixture: {FIXTURE_PATH}")
    print(f"RSA modulus size: {public_fixture['modulus_bits']} bits")
    print(f"Private exponent size: {details['private_exponent_bits']} bits")
    print(f"Wiener bound size: {details['wiener_bound_bits']} bits")
    print(f"d / Wiener bound: {details['d_to_bound']:.6f}")
    print("Original d, p, and q were not saved.")
    print("RESULT: FIXTURE VALIDATED")


if __name__ == "__main__":
    main()
