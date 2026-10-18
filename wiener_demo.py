"""Live demonstration of Wiener's attack on an intentionally weak RSA key."""

from math import gcd

from rsa_core import decrypt, encrypt, generate_keypair
from wiener_attack import recover_private_key


def main():
    # These balanced primes make n hard for neither classroom attack, but the
    # Wiener weakness is created specifically by choosing a very small d.
    p = 1009
    q = 1013
    phi = (p - 1) * (q - 1)
    d = 5

    if gcd(d, phi) != 1:
        raise ValueError("the demonstration d must be coprime to phi")

    # generate_keypair normally accepts e, so compute e from the deliberately
    # selected d and then use the shared RSA key-generation function.
    e = pow(d, -1, phi)
    key = generate_keypair(p, q, e)

    message = 42
    ciphertext = encrypt(message, key["e"], key["n"])

    print("=== Wiener Attack Demo ===")
    print("Construction: balanced primes are used, then d=5 is chosen first.")
    print("The public exponent e is computed as the inverse of d modulo phi(n).")
    print(f"Public key (e, n): ({key['e']}, {key['n']})")
    print(f"Original message: {message}")
    print(f"Ciphertext: {ciphertext}")

    # The attack receives public information only.
    recovered = recover_private_key(key["e"], key["n"])
    if recovered is None:
        print("Recovered private exponent: none")
        print("FAIL: Wiener attack did not recover the private key.")
        return

    recovered_message = decrypt(ciphertext, recovered["d"], key["n"])
    print(f"Recovered p, q: {recovered['p']}, {recovered['q']}")
    print(f"Recovered private exponent d: {recovered['d']}")
    print(f"Recovered plaintext: {recovered_message}")

    passed = (
        recovered["d"] == key["d"]
        and recovered["p"] * recovered["q"] == key["n"]
        and recovered_message == message
    )
    print("PASS: Private key recovered and message decrypted." if passed else
          "FAIL: Recovered values did not pass verification.")


if __name__ == "__main__":
    main()
