import csv
from math import gcd
from pathlib import Path
from secrets import randbits
from statistics import median
from time import perf_counter

from sympy import nextprime
from fermat_attack import fermat_factor
from rsa_core import encrypt, decrypt


def generate_large_weak_key(prime_bits):
    """生成大位数、但两个因子刻意接近的实验密钥。"""
    e = 65537

    while True:
        # 设置最高两位，保证乘积有目标位数
        candidate = randbits(prime_bits)
        candidate |= 3 << (prime_bits - 2)
        candidate |= 1

        p = int(nextprime(candidate))
        q = int(nextprime(p))

        n = p * q
        phi = (p - 1) * (q - 1)

        if (
            p.bit_length() == prime_bits
            and q.bit_length() == prime_bits
            and n.bit_length() == 2 * prime_bits
            and gcd(e, phi) == 1
        ):
            d = pow(e, -1, phi)
            return p, q, n, e, d


def main():
    rows = []
    output = Path(__file__).resolve().parent / "results"
    output.mkdir(exist_ok=True)

    for prime_bits in (512, 1024):
        for trial in range(1, 4):
            target_bits = 2 * prime_bits
            print(
                f"\nGenerating {target_bits}-bit weak key "
                f"{trial}/3...",
                flush=True,
            )

            start = perf_counter()
            p, q, n, e, d = generate_large_weak_key(prime_bits)
            generation_seconds = perf_counter() - start

            ciphertext = encrypt(42, e, n)
            times = []

            for _ in range(5):
                # 分解函数只收到公开的 n 和检查上限
                start = perf_counter()
                result = fermat_factor(n, max_checks=10000)
                times.append(perf_counter() - start)

                if result is None:
                    raise RuntimeError("Factorization limit reached")

                recovered_p, recovered_q, checks = result
                recovered_phi = (
                    (recovered_p - 1) * (recovered_q - 1)
                )
                recovered_d = pow(e, -1, recovered_phi)

                # 核对因子、私钥及解密结果
                assert {recovered_p, recovered_q} == {p, q}
                assert recovered_d == d
                assert decrypt(ciphertext, recovered_d, n) == 42

            row = {
                "n_bits": n.bit_length(),
                "trial": trial,
                "gap": q - p,
                "checks": checks,
                "repeats": 5,
                "median_factor_seconds": median(times),
                "generation_seconds": generation_seconds,
                "verified": True,
                # 大整数用十六进制保存，便于精确复现实验
                "p_hex": hex(p),
                "q_hex": hex(q),
                "n_hex": hex(n),
                "e": e,
            }
            rows.append(row)

            print(f"Actual modulus bits: {n.bit_length()}")
            print(f"Prime gap: {q - p}")
            print(f"Checks: {checks}")
            print(f"Median factorization time: {median(times):.8f} s")
            print("PASS: factors, private key and decryption verified")

    csv_path = output / "fermat_large_results.csv"

    with csv_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nResults saved to: {csv_path}")


if __name__ == "__main__":
    main()