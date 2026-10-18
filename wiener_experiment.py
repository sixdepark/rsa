"""Small and large-key experiments for Wiener's RSA attack."""

import argparse
import csv
import random
from collections import defaultdict
from decimal import Decimal, localcontext
from math import gcd, isqrt
from pathlib import Path
from statistics import median
from time import perf_counter

from rsa_core import generate_keypair
from wiener_attack import recover_private_key


RESULTS_DIRECTORY = Path(__file__).resolve().parent / "results"
LARGE_KEY_SIZES = (512, 1024, 2048)
BOUNDARY_PROFILES = (
    ("below_bound", 4, 5),
    ("at_bound", 1, 1),
    ("above_bound", 6, 5),
)


def wiener_bound(n):
    """Return floor(n^(1/4) / 3), the classical Wiener threshold."""
    return isqrt(isqrt(n)) // 3


def next_coprime_odd(value, phi):
    """Return the first odd integer at or above value that is coprime to phi."""
    candidate = max(3, value | 1)
    while candidate < phi and gcd(candidate, phi) != 1:
        candidate += 2
    if candidate >= phi:
        raise ValueError("could not choose a private exponent below phi")
    return candidate


def build_weak_key(p, q, minimum_d):
    """Build a teaching key by choosing a small d first, then calculating e."""
    phi = (p - 1) * (q - 1)
    d = next_coprime_odd(minimum_d, phi)
    e = pow(d, -1, phi)
    return {"p": p, "q": q, "n": p * q, "phi": phi, "e": e, "d": d}


def time_attack(key, repeats):
    """Attack a key repeatedly and return the final result and median time."""
    times_ms = []
    result = None

    for _ in range(repeats):
        start = perf_counter()
        # Only the public values are provided to the attack.
        result = recover_private_key(key["e"], key["n"])
        times_ms.append((perf_counter() - start) * 1000)

    return result, median(times_ms)


def run_small_experiments(timing_repeats):
    """Run and save the original fixed-prime classroom experiments."""
    prime_pairs = [
        (1009, 1013, 5),
        (10007, 10009, 17),
        (65537, 65539, 47),
        (1000003, 1000033, 131),
    ]

    rows = []
    print("=== Original Small-Key Wiener Experiments ===")

    for p, q, minimum_d in prime_pairs:
        cases = [
            (build_weak_key(p, q, minimum_d), True),
            (generate_keypair(p, q, e=65537), False),
        ]

        for key, vulnerable in cases:
            result, median_time_ms = time_attack(key, timing_repeats)
            success = result is not None
            row = {
                "key_size_bits": key["n"].bit_length(),
                "private_exponent_bits": key["d"].bit_length(),
                "vulnerable": vulnerable,
                "attack_success": success,
                "recovered_d_correct": success and result["d"] == key["d"],
                "execution_time_ms": f"{median_time_ms:.6f}",
                "wiener_bound": wiener_bound(key["n"]),
                "private_exponent": key["d"],
                "public_exponent": key["e"],
                "modulus": key["n"],
                "repeats": timing_repeats,
            }
            rows.append(row)
            print(
                f"bits={row['key_size_bits']:>2} | "
                f"d_bits={row['private_exponent_bits']:>2} | "
                f"label={'weak' if vulnerable else 'control':>7} | "
                f"success={str(success):>5} | {median_time_ms:.6f} ms"
            )

    csv_path = RESULTS_DIRECTORY / "wiener_results.csv"
    write_csv(csv_path, rows)
    print(f"Small-key results saved to: {csv_path}\n")
    return rows


def deterministic_randfunc(seed):
    """Create a reproducible byte source for classroom experiments only."""
    generator = random.Random(seed)
    return generator.randbytes


def generate_balanced_prime_pair(modulus_bits, randfunc):
    """Generate distinct balanced primes whose product has exactly modulus_bits."""
    try:
        from Crypto.Util.number import getPrime
    except ImportError as error:
        raise RuntimeError(
            "PyCryptodome is required; run: python -m pip install -r requirements.txt"
        ) from error

    p_bits = modulus_bits // 2
    q_bits = modulus_bits - p_bits

    while True:
        p = getPrime(p_bits, randfunc=randfunc)
        q = getPrime(q_bits, randfunc=randfunc)
        n = p * q
        phi = (p - 1) * (q - 1)

        if p == q or n.bit_length() != modulus_bits:
            continue
        if max(p, q) >= 2 * min(p, q):
            continue
        if gcd(65537, phi) != 1:
            continue
        return p, q


def make_profile_keys(p, q, modulus_bits):
    """Construct several d sizes for one fixed, balanced RSA modulus."""
    n = p * q
    phi = (p - 1) * (q - 1)
    bound = wiener_bound(n)
    keys = []

    # Roughly n^(1/8): far smaller than the n^(1/4)/3 Wiener threshold.
    very_small_target = 1 << max(2, modulus_bits // 8)
    profile_targets = [("very_small", very_small_target, "well_below")]

    for name, numerator, denominator in BOUNDARY_PROFILES:
        target = bound * numerator // denominator
        if numerator < denominator:
            relation = "below"
        elif numerator == denominator:
            relation = "at"
        else:
            relation = "above"
        profile_targets.append((name, target, relation))

    for profile, target, intended_relation in profile_targets:
        d = next_coprime_odd(target, phi)
        e = pow(d, -1, phi)
        keys.append(
            (
                profile,
                intended_relation,
                {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d},
            )
        )

    normal_e = 65537
    normal_d = pow(normal_e, -1, phi)
    keys.append(
        (
            "normal_control",
            "well_above",
            {
                "p": p,
                "q": q,
                "n": n,
                "phi": phi,
                "e": normal_e,
                "d": normal_d,
            },
        )
    )
    return keys


def validate_generated_key(key, requested_bits):
    """Check every large-key construction requirement before attacking it."""
    p = key["p"]
    q = key["q"]
    valid = (
        p != q
        and key["n"] == p * q
        and key["n"].bit_length() == requested_bits
        and max(p, q) < 2 * min(p, q)
        and key["phi"] == (p - 1) * (q - 1)
        and gcd(key["d"], key["phi"]) == 1
        and (key["e"] * key["d"]) % key["phi"] == 1
    )
    if not valid:
        raise AssertionError("generated RSA key failed construction validation")


def run_large_case(
    key,
    requested_bits,
    sample_number,
    profile,
    intended_relation,
    generation_time_ms,
    timing_repeats,
):
    """Attack and validate one large-key profile."""
    validate_generated_key(key, requested_bits)
    bound = wiener_bound(key["n"])
    result, attack_time_ms = time_attack(key, timing_repeats)
    success = result is not None
    d_correct = success and result["d"] == key["d"]
    factors_correct = success and {
        result["p"], result["q"]
    } == {key["p"], key["q"]}

    if success and not (d_correct and factors_correct):
        raise AssertionError("attack returned an incorrect private key or factors")

    # Decimal avoids overflow for a normal 2048-bit d and preserves tiny ratios.
    with localcontext() as context:
        context.prec = 12
        actual_ratio = Decimal(key["d"]) / Decimal(bound)
    if key["d"] < bound:
        actual_relation = "below"
    elif key["d"] == bound:
        actual_relation = "at"
    else:
        actual_relation = "above"

    return {
        "requested_modulus_bits": requested_bits,
        "actual_modulus_bits": key["n"].bit_length(),
        "sample": sample_number,
        "d_profile": profile,
        "private_exponent_bits": key["d"].bit_length(),
        "wiener_bound_bits": bound.bit_length(),
        "intended_bound_relation": intended_relation,
        "actual_bound_relation": actual_relation,
        "d_to_wiener_bound": f"{actual_ratio:.8E}",
        "balanced_primes": max(key["p"], key["q"]) < 2 * min(key["p"], key["q"]),
        "gcd_d_phi_is_one": gcd(key["d"], key["phi"]) == 1,
        "attack_success": success,
        "recovered_d_correct": d_correct,
        "recovered_factors_correct": factors_correct,
        "key_generation_time_ms": f"{generation_time_ms:.6f}",
        "median_attack_time_ms": f"{attack_time_ms:.6f}",
        "timing_repeats": timing_repeats,
    }


def summarise_large_results(rows):
    """Aggregate trial rows by modulus size and private-exponent profile."""
    groups = defaultdict(list)
    for row in rows:
        groups[(row["requested_modulus_bits"], row["d_profile"])].append(row)

    summary = []
    for (modulus_bits, profile), group in sorted(groups.items()):
        successes = sum(row["attack_success"] for row in group)
        correct = sum(
            row["recovered_d_correct"] and row["recovered_factors_correct"]
            for row in group
        )
        summary.append(
            {
                "rsa_modulus_bits": modulus_bits,
                "d_profile": profile,
                "keys_tested": len(group),
                "median_private_exponent_bits": f"{median(row['private_exponent_bits'] for row in group):.1f}",
                "median_d_to_wiener_bound": f"{median(Decimal(row['d_to_wiener_bound']) for row in group):.8E}",
                "attack_successes": successes,
                "success_rate_percent": f"{100 * successes / len(group):.2f}",
                "correct_recoveries": correct,
                "median_attack_time_ms": f"{median(float(row['median_attack_time_ms']) for row in group):.6f}",
                "median_key_generation_time_ms": f"{median(float(row['key_generation_time_ms']) for row in group):.6f}",
            }
        )
    return summary


def generate_graphs(summary_rows):
    """Create the two requested graphs from measured summary data."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as error:
        raise RuntimeError(
            "Matplotlib is required; run: python -m pip install -r requirements.txt"
        ) from error

    by_modulus = defaultdict(list)
    by_profile = defaultdict(list)
    for row in summary_rows:
        by_modulus[row["rsa_modulus_bits"]].append(row)
        by_profile[row["d_profile"]].append(row)

    figure, axis = plt.subplots(figsize=(9, 5.5))
    for modulus_bits, rows in sorted(by_modulus.items()):
        points = sorted(
            (
                float(row["median_private_exponent_bits"]),
                float(row["success_rate_percent"]),
            )
            for row in rows
        )
        axis.plot(
            [point[0] for point in points],
            [point[1] for point in points],
            marker="o",
            label=f"{modulus_bits}-bit RSA",
        )
    axis.set_title("Wiener Attack Success Rate vs Private Exponent Size")
    axis.set_xlabel("Median private exponent size (bits)")
    axis.set_ylabel("Attack success rate (%)")
    axis.set_ylim(-5, 105)
    axis.grid(True, alpha=0.3)
    axis.legend()
    figure.tight_layout()
    success_graph = RESULTS_DIRECTORY / "wiener_success_rate.png"
    figure.savefig(success_graph, dpi=160)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(9, 5.5))
    for profile, rows in sorted(by_profile.items()):
        points = sorted(
            (
                row["rsa_modulus_bits"],
                float(row["median_attack_time_ms"]),
            )
            for row in rows
        )
        axis.plot(
            [point[0] for point in points],
            [point[1] for point in points],
            marker="o",
            label=profile.replace("_", " ").title(),
        )
    axis.set_title("Wiener Attack Execution Time vs RSA Modulus Size")
    axis.set_xlabel("RSA modulus size (bits)")
    axis.set_ylabel("Median attack time (milliseconds)")
    axis.grid(True, alpha=0.3)
    axis.legend()
    figure.tight_layout()
    timing_graph = RESULTS_DIRECTORY / "wiener_execution_time.png"
    figure.savefig(timing_graph, dpi=160)
    plt.close(figure)
    return success_graph, timing_graph


def run_large_experiments(samples, timing_repeats, seed):
    """Generate, attack, save, and plot the 512- to 2048-bit experiments."""
    randfunc = deterministic_randfunc(seed)
    rows = []

    print("=== Large-Key Wiener Experiments ===")
    print(
        f"sizes={LARGE_KEY_SIZES}, samples/profile={samples}, "
        f"timing repeats={timing_repeats}, seed={seed}"
    )

    for modulus_bits in LARGE_KEY_SIZES:
        for sample_number in range(1, samples + 1):
            generation_start = perf_counter()
            p, q = generate_balanced_prime_pair(modulus_bits, randfunc)
            generation_time_ms = (perf_counter() - generation_start) * 1000

            for profile, intended_relation, key in make_profile_keys(
                p, q, modulus_bits
            ):
                row = run_large_case(
                    key,
                    modulus_bits,
                    sample_number,
                    profile,
                    intended_relation,
                    generation_time_ms,
                    timing_repeats,
                )
                rows.append(row)
                print(
                    f"bits={modulus_bits:>4} | sample={sample_number} | "
                    f"profile={profile:>14} | "
                    f"d/bound={row['d_to_wiener_bound']:>12} | "
                    f"success={str(row['attack_success']):>5} | "
                    f"{row['median_attack_time_ms']} ms"
                )

    trial_csv = RESULTS_DIRECTORY / "wiener_large_results.csv"
    write_csv(trial_csv, rows)

    summary = summarise_large_results(rows)
    summary_csv = RESULTS_DIRECTORY / "wiener_large_summary.csv"
    write_csv(summary_csv, summary)
    success_graph, timing_graph = generate_graphs(summary)

    print(f"\nLarge-key trial results saved to: {trial_csv}")
    print(f"Large-key summary saved to: {summary_csv}")
    print(f"Success-rate graph saved to: {success_graph}")
    print(f"Execution-time graph saved to: {timing_graph}")
    return rows, summary


def write_csv(path, rows):
    """Write dictionaries to a UTF-8 CSV file."""
    if not rows:
        raise ValueError("cannot write an empty result set")
    path.parent.mkdir(exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--small-only", action="store_true", help="run only the original cases"
    )
    mode.add_argument(
        "--large-only", action="store_true", help="run only 512- to 2048-bit cases"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=5,
        help="independent large keys per size/profile (default: 5)",
    )
    parser.add_argument(
        "--timing-repeats",
        type=int,
        default=5,
        help="attack timings per key (default: 5)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=6104,
        help="deterministic large-prime experiment seed (default: 6104)",
    )
    arguments = parser.parse_args()
    if arguments.samples < 1 or arguments.timing_repeats < 1:
        parser.error("--samples and --timing-repeats must be positive")
    return arguments


def main():
    arguments = parse_arguments()
    RESULTS_DIRECTORY.mkdir(exist_ok=True)

    if not arguments.large_only:
        run_small_experiments(arguments.timing_repeats)
    if not arguments.small_only:
        run_large_experiments(
            arguments.samples, arguments.timing_repeats, arguments.seed
        )


if __name__ == "__main__":
    main()
