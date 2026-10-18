import csv
from pathlib import Path
from statistics import median
from time import perf_counter

from rsa_core import generate_keypair, encrypt, decrypt
from fermat_attack import fermat_factor


def main():
    # 五组质数：模数位数相同，质数间距逐渐增加
    cases = [
        (1000003, 1000033),
        (999007, 1001003),
        (990001, 1010003),
        (900001, 1100009),
        (700001, 1300021),
    ]

    max_checks = 10000
    repeats = 5
    rows = []

    print("=== Fermat Parameter Experiment ===")
    print(f"Check limit: {max_checks}; runs per case: {repeats}")
    print()

    for p, q in cases:
        key = generate_keypair(p, q, e=65537)
        ciphertext = encrypt(42, key["e"], key["n"])
        times = []

        for _ in range(repeats):
            # 计时仅包括因子分解，不包括密钥生成
            start = perf_counter()
            result = fermat_factor(key["n"], max_checks)
            times.append(perf_counter() - start)

        if result is None:
            status = "limit_reached"
            checks = max_checks
        else:
            recovered_p, recovered_q, checks = result
            recovered_phi = (recovered_p - 1) * (recovered_q - 1)
            recovered_d = pow(key["e"], -1, recovered_phi)

            assert recovered_p * recovered_q == key["n"]
            assert decrypt(ciphertext, recovered_d, key["n"]) == 42
            status = "recovered"

        row = {
            "p": p,
            "q": q,
            "gap": abs(p - q),
            "n": key["n"],
            "n_bits": key["n"].bit_length(),
            "status": status,
            "checks": checks,
            "max_checks": max_checks,
            "repeats": repeats,
            "median_seconds": median(times),
        }
        rows.append(row)

        print(
            f"gap={row['gap']:>6} | "
            f"bits={row['n_bits']} | "
            f"checks={checks:>5} | "
            f"{status} | "
            f"{row['median_seconds']:.8f} s"
        )

    output = Path(__file__).resolve().parent / "results"
    output.mkdir(exist_ok=True)
    csv_path = output / "fermat_results.csv"

    with csv_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nResults saved to: {csv_path}")


if __name__ == "__main__":
    main()