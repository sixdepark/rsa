"""Generate presentation-ready Wiener Attack graphs from the summary CSV."""

import csv
from pathlib import Path


RESULTS_DIRECTORY = Path(__file__).resolve().parent / "results"
SUMMARY_CSV = RESULTS_DIRECTORY / "wiener_large_summary.csv"

MODULUS_SIZES = (512, 1024, 2048)
PROFILE_ORDER = (
    "very_small",
    "below_bound",
    "at_bound",
    "above_bound",
    "normal_control",
)
PROFILE_LABELS = {
    "very_small": "Very Small",
    "below_bound": "Below Bound",
    "at_bound": "Near Bound",
    "above_bound": "Above Bound",
    "normal_control": "Normal Control",
}


def read_summary(path):
    """Read and validate the experimental summary rows used by the graphs."""
    with path.open(newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))

    indexed = {
        (int(row["rsa_modulus_bits"]), row["d_profile"]): row for row in rows
    }
    expected = {
        (modulus_bits, profile)
        for modulus_bits in MODULUS_SIZES
        for profile in PROFILE_ORDER
    }
    missing = expected.difference(indexed)
    if missing:
        raise ValueError(f"summary CSV is missing graph data: {sorted(missing)}")
    return indexed


def configure_matplotlib():
    """Load Matplotlib with a non-interactive backend."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as error:
        raise RuntimeError(
            "Matplotlib is required; run: python -m pip install -r requirements.txt"
        ) from error
    return plt


def create_success_rate_graph(plt, rows):
    """Create a grouped success-rate bar chart from actual summary values."""
    figure, axis = plt.subplots(figsize=(12, 6.75))
    positions = list(range(len(PROFILE_ORDER)))
    bar_width = 0.24
    offsets = (-bar_width, 0, bar_width)
    colors = ("#4472C4", "#ED7D31", "#70AD47")

    for modulus_bits, offset, color in zip(MODULUS_SIZES, offsets, colors):
        values = [
            float(rows[(modulus_bits, profile)]["success_rate_percent"])
            for profile in PROFILE_ORDER
        ]
        bars = axis.bar(
            [position + offset for position in positions],
            values,
            width=bar_width,
            color=color,
            label=f"{modulus_bits}-bit",
        )
        axis.bar_label(bars, labels=[f"{value:.0f}%" for value in values], padding=4)

    axis.set_title(
        "Wiener Attack Success Rate by Private Exponent Profile",
        fontsize=20,
        pad=18,
        weight="bold",
    )
    axis.set_xlabel("Private Exponent Profile", fontsize=14, labelpad=12)
    axis.set_ylabel("Success Rate (%)", fontsize=14, labelpad=12)
    axis.set_xticks(positions, [PROFILE_LABELS[profile] for profile in PROFILE_ORDER])
    axis.set_ylim(0, 112)
    axis.tick_params(axis="both", labelsize=12)
    axis.grid(axis="y", alpha=0.25)
    axis.set_axisbelow(True)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.legend(loc="upper right", frameon=False, fontsize=12, ncols=3)
    figure.tight_layout()

    output = RESULTS_DIRECTORY / "wiener_success_rate_ppt.png"
    figure.savefig(output, dpi=200, facecolor="white")
    plt.close(figure)
    return output


def create_execution_time_graph(plt, rows):
    """Create the near-bound median attack-time graph."""
    values = [
        float(rows[(modulus_bits, "at_bound")]["median_attack_time_ms"])
        for modulus_bits in MODULUS_SIZES
    ]
    positions = list(range(len(MODULUS_SIZES)))

    figure, axis = plt.subplots(figsize=(12, 6.75))
    axis.plot(
        positions,
        values,
        color="#4472C4",
        linewidth=3,
        marker="o",
        markersize=10,
    )

    for position, value in zip(positions, values):
        axis.annotate(
            f"{value:.4f} ms",
            (position, value),
            xytext=(0, 12),
            textcoords="offset points",
            ha="center",
            fontsize=12,
            weight="bold",
        )

    axis.set_title(
        "Median Wiener Attack Time vs RSA Modulus Size",
        fontsize=20,
        pad=18,
        weight="bold",
    )
    axis.set_xlabel("RSA Modulus Size", fontsize=14, labelpad=12)
    axis.set_ylabel("Median Attack Time (ms)", fontsize=14, labelpad=12)
    axis.set_xticks(positions, [f"{size}-bit" for size in MODULUS_SIZES])
    axis.set_ylim(0, max(values) * 1.25)
    axis.tick_params(axis="both", labelsize=12)
    axis.grid(axis="y", alpha=0.25)
    axis.set_axisbelow(True)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    figure.tight_layout()

    output = RESULTS_DIRECTORY / "wiener_execution_time_ppt.png"
    figure.savefig(output, dpi=200, facecolor="white")
    plt.close(figure)
    return output


def main():
    rows = read_summary(SUMMARY_CSV)
    plt = configure_matplotlib()
    success_output = create_success_rate_graph(plt, rows)
    time_output = create_execution_time_graph(plt, rows)
    print(f"Success-rate graph saved to: {success_output}")
    print(f"Execution-time graph saved to: {time_output}")


if __name__ == "__main__":
    main()
