"""Automated tests for the Wiener attack implementation."""

import unittest
from math import gcd

from rsa_core import decrypt, encrypt, generate_keypair
from wiener_attack import (
    continued_fraction,
    convergents,
    recover_private_key,
    wiener_attack,
)


class WienerAttackTests(unittest.TestCase):
    @staticmethod
    def weak_key():
        p, q, d = 1009, 1013, 5
        phi = (p - 1) * (q - 1)
        if gcd(d, phi) != 1:
            raise AssertionError("invalid test fixture")
        e = pow(d, -1, phi)
        return generate_keypair(p, q, e)

    def test_continued_fraction(self):
        self.assertEqual(continued_fraction(43, 19), [2, 3, 1, 4])
        self.assertEqual(continued_fraction(17, 3233)[0], 0)

    def test_convergents(self):
        self.assertEqual(
            list(convergents([2, 3, 1, 4])),
            [(2, 1), (7, 3), (9, 4), (43, 19)],
        )

    def test_recovers_weak_private_exponent_and_factors(self):
        key = self.weak_key()
        result = recover_private_key(key["e"], key["n"])

        self.assertIsNotNone(result)
        self.assertEqual(result["d"], key["d"])
        self.assertEqual(result["p"] * result["q"], key["n"])
        self.assertEqual({result["p"], result["q"]}, {key["p"], key["q"]})
        self.assertEqual(wiener_attack(key["e"], key["n"]), key["d"])

    def test_decryption_with_recovered_private_key(self):
        key = self.weak_key()
        message = 42
        ciphertext = encrypt(message, key["e"], key["n"])
        recovered_d = wiener_attack(key["e"], key["n"])

        self.assertEqual(decrypt(ciphertext, recovered_d, key["n"]), message)

    def test_non_vulnerable_key_returns_none(self):
        key = generate_keypair(61, 53, e=17)
        self.assertIsNone(recover_private_key(key["e"], key["n"]))
        self.assertIsNone(wiener_attack(key["e"], key["n"]))

    def test_invalid_attack_inputs(self):
        invalid_values = [
            (1, 3233),
            (17, 2),
            (3233, 3233),
            (-17, 3233),
        ]
        for e, n in invalid_values:
            with self.subTest(e=e, n=n):
                with self.assertRaises(ValueError):
                    wiener_attack(e, n)

        with self.assertRaises(TypeError):
            wiener_attack(17.0, 3233)
        with self.assertRaises(TypeError):
            wiener_attack(True, 3233)

    def test_invalid_continued_fraction_inputs(self):
        with self.assertRaises(ValueError):
            continued_fraction(1, 0)
        with self.assertRaises(ValueError):
            continued_fraction(-1, 2)
        with self.assertRaises(TypeError):
            continued_fraction(1, 2.0)


if __name__ == "__main__":
    unittest.main()
