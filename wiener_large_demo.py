"""Presentation-ready Wiener attack demo using a fixed public RSA-2048 key."""

import json
from pathlib import Path
from time import perf_counter

from rsa_core import decrypt
from wiener_attack import recover_private_key


FIXTURE_PATH = (
    Path(__file__).resolve().parent / "results" / "wiener_demo_public.json"
)
REQUIRED_FIELDS = {
    "public_exponent",
    "modulus",
    "ciphertext",
    "expected_plaintext",
}
PRIVATE_FIELDS = {"d", "p", "q", "phi", "private_exponent"}


def shortened_hex(value, visible_digits=16):
    """Return a readable hexadecimal prefix and suffix for a large integer."""
    digits = format(value, "x")
    if len(digits) <= 2 * visible_digits:
        return f"0x{digits}"
    return f"0x{digits[:visible_digits]}...{digits[-visible_digits:]}"


def load_public_fixture(path):
    """Load public values and reject missing or accidentally private fields."""
    with path.open(encoding="utf-8") as file:
        fixture = json.load(file)

    missing = REQUIRED_FIELDS.difference(fixture)
    forbidden = PRIVATE_FIELDS.intersection(fixture)
    if missing:
        raise ValueError(f"fixture is missing required fields: {sorted(missing)}")
    if forbidden:
        raise ValueError(f"fixture contains private fields: {sorted(forbidden)}")

    return {
        "e": int(fixture["public_exponent"]),
        "n": int(fixture["modulus"]),
        "ciphertext": int(fixture["ciphertext"]),
        "expected_plaintext": int(fixture["expected_plaintext"]),
    }


def fail(message, attack_time_ms=None):
    """Print a presentation-friendly failure and return a nonzero exit code."""
    print(f"\nVerification failed: {message}")
    if attack_time_ms is not None:
        print(f"Attack Time: {attack_time_ms:.4f} ms")
    print("\nRESULT: FAIL")
    return 1


def main():
    try:
        public = load_public_fixture(FIXTURE_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("=== Wiener Attack: 2048-bit RSA Demo ===")
        return fail(f"could not load the public fixture ({error})")

    e = public["e"]
    n = public["n"]
    ciphertext = public["ciphertext"]
    expected_plaintext = public["expected_plaintext"]

    print("=== Wiener Attack: 2048-bit RSA Demo ===\n")
    print(f"RSA Modulus Size: {n.bit_length()} bits\n")
    if n.bit_length() != 2048:
        return fail("the fixture modulus is not exactly 2048 bits")

    print("Public Key:")
    print(f"n = {shortened_hex(n)}")
    print(f"e = {shortened_hex(e)}\n")
    print("Attack Target:")
    print("Intentionally vulnerable RSA-2048 key with a small private exponent")
    print("The attack receives only the public values e and n.\n")
    print("Starting Wiener Attack...\n")

    start = perf_counter()
    recovered = recover_private_key(e, n)
    attack_time_ms = (perf_counter() - start) * 1000
    print("[1] Continued fraction analysis completed")

    if recovered is None:
        return fail("no private exponent was recovered", attack_time_ms)
    print("[2] Private exponent recovered")

    factors_correct = recovered["p"] * recovered["q"] == n
    if not factors_correct:
        return fail("recovered factors do not multiply to n", attack_time_ms)
    print("[3] RSA prime factors recovered")

    recovered_phi = (recovered["p"] - 1) * (recovered["q"] - 1)
    key_equation_valid = (
        recovered_phi == recovered["phi"]
        and (e * recovered["d"]) % recovered_phi == 1
    )
    if not key_equation_valid:
        return fail("recovered values do not satisfy the RSA key equation", attack_time_ms)
    print("[4] Private key verified")

    decrypted_message = decrypt(ciphertext, recovered["d"], n)
    if decrypted_message != expected_plaintext:
        return fail("decrypted plaintext does not match", attack_time_ms)
    print("[5] Ciphertext successfully decrypted\n")

    print(f"Recovered Private Exponent Size: {recovered['d'].bit_length()} bits")
    print(f"Recovered Private Exponent: {shortened_hex(recovered['d'])}")
    print(
        "Recovered Prime Sizes: "
        f"{recovered['p'].bit_length()} bits and {recovered['q'].bit_length()} bits"
    )
    print(f"Original Message: {expected_plaintext}")
    print(f"Decrypted Message: {decrypted_message}")
    print(f"\nAttack Time: {attack_time_ms:.4f} ms")
    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
