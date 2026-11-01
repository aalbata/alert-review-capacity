"""Figures 2 and 3 for the CTU-13 replay, drawn from the result files."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from review_capacity import COLORS, GRAY, save, style  # noqa: E402

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
TREE = "#3A7D6B"
STYLE = {("A", "fifo"): "-", ("A", "score"): "-.", ("B", "fifo"): "-", ("B", "score"): ":"}
ORDER = {"fifo": "arrival order", "score": "score order"}
LOGISTIC = "#8A8A8A"


def display_subset(p):
    """At most one attainable point per small cell of log alert volume and detection, for drawing only."""
    cell = pd.DataFrame({"x": np.round(np.log10(p["alerts_per_hour"]) * 200), "y": np.round(p["detection"] * 500)})
    return p.loc[~cell.duplicated().to_numpy()]


def figure2(res, outdir):
    settings = pd.read_csv(res / "ctu13_settings.csv").set_index(["model", "setting"])
    points = pd.read_csv(res / "ctu13_operating_points.csv")
    queue = pd.read_csv(res / "ctu13_queue.csv")
    budget = pd.read_csv(res / "ctu13_budget_thresholds.csv")
    capacity = CONFIG["illustrative_capacity_per_hour"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.5, 3.0))
    for kind, color, name in [("gbt", TREE, "Trees"), ("logreg", LOGISTIC, "Logistic")]:
        p = display_subset(points[points["model"].eq(kind)])
        ax1.plot(p["alerts_per_hour"], 100 * p["detection"], linestyle="none", marker="o", markersize=1.2,
                 color=color, label=f"{name}, attainable thresholds")
    b = budget[budget["model"].eq("gbt") & budget["seed"].eq(CONFIG["model_seed"])
               & budget["budget_per_hour"].eq(CONFIG["alert_budgets_per_hour"][0])].iloc[0]
    marks = [(settings.loc[("logreg", "A")], "s", COLORS["A"], "Logistic, 90% target"),
             (settings.loc[("logreg", "B")], "o", COLORS["B"], "Logistic, 95% target"),
             (b, "D", TREE, f"Trees, budget {CONFIG['alert_budgets_per_hour'][0]} per training hour")]
    for row, marker, color, lab in marks:
        ax1.plot([row["test_alerts_per_hour"]], [100 * row["test_detection"]], marker=marker, color=color,
                 markersize=5, linestyle="none", markeredgecolor="black", markeredgewidth=0.4, label=lab)
    ax1.axvline(capacity, color=GRAY, linestyle="--", linewidth=0.8)
    ax1.set_xscale("log")
    ax1.set_xlim(0.03, 3000)
    ax1.set_xticks([0.1, 1, 10, 100, 1000], ["0.1", "1", "10", "100", "1,000"])
    ax1.minorticks_off()
    ax1.set_ylim(0, 102)
    ax1.set_xlabel("Alerts per hour on the later captures (log scale)")
    ax1.set_ylabel("Botnet host-windows alerted (%)")
    ax1.grid(linewidth=0.4, color="#DDDDDD")
    ax1.set_title("(a) Detection versus alert volume", loc="left")
    ax1.legend(loc="upper left", frameon=False, fontsize=6, handlelength=1.3, markerscale=1.0)

    for name, policy in [("A", "fifo"), ("A", "score"), ("B", "fifo"), ("B", "score")]:
        q = queue[queue["model"].eq("logreg") & queue["setting"].eq(name) & queue["policy"].eq(policy)]
        q = q.sort_values("capacity_per_hour")
        n = q["pos_windows"].iloc[0]
        target = "90%" if name == "A" else "95%"
        order = ORDER[policy]
        ax2.fill_between(q["capacity_per_hour"], 100 * q["pos_windows_ontime_min"] / n,
                         100 * q["pos_windows_ontime_max"] / n, color=COLORS[name], alpha=0.25, linewidth=0)
        ax2.plot(q["capacity_per_hour"], 100 * q["pos_windows_ontime_median"] / n, color=COLORS[name],
                 linestyle=STYLE[(name, policy)], marker="o", markersize=1.8, label=f"{target}, {order}")
    ax2.axvline(capacity, color=GRAY, linestyle="--", linewidth=0.8)
    ax2.text(capacity * 1.05, 50, f"{capacity} per hour", fontsize=6.5, color=GRAY, rotation=90, va="center")
    ax2.set_xscale("log")
    ax2.set_xticks([10, 20, 50, 100, 200, 400], ["10", "20", "50", "100", "200", "400"])
    ax2.minorticks_off()
    ax2.set_ylim(0, 102)
    ax2.set_xlabel("Review capacity (alerts per hour, log scale)")
    ax2.set_ylabel("Botnet host-windows reviewed\nwithin 60 minutes of the alert (%)")
    ax2.grid(linewidth=0.4, color="#DDDDDD")
    ax2.set_title("(b) Logistic detector, on-time review", loc="left")
    ax2.legend(loc="upper right", frameon=False, fontsize=6, handlelength=2.2)
    fig.tight_layout(w_pad=1.2)
    save(fig, outdir, "fig2_ctu13_measured")


def ecdf(values, grid, n):
    v = np.sort(np.asarray(values, dtype=float))
    v = v[~np.isnan(v)]
    return np.searchsorted(v, grid, side="right") / n


def figure3(res, outdir):
    timing = pd.read_csv(res / "ctu13_infection_timing.csv")
    seed0 = timing[timing["tie_seed"].eq(CONFIG["tie_seeds"][0])]
    deadline = CONFIG["deadline_minutes"]
    upper = max(3000.0, 1.05 * float(timing["time_to_review_min"].max()))
    grid = np.geomspace(1, upper, 800)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.5, 2.8), sharey=True)
    for name, ls in [("A", "-"), ("B", "-")]:
        d = seed0[seed0["model"].eq("logreg") & seed0["setting"].eq(name) & seed0["policy"].eq("fifo")]
        n = len(d)
        target = "90%" if name == "A" else "95%"
        ax1.plot(grid, 100 * ecdf(d["detection_delay_min"], grid, n), color=COLORS[name], linestyle=ls,
                 label=f"{target} target")
    for name, policy in [("A", "fifo"), ("A", "score"), ("B", "fifo"), ("B", "score")]:
        ls = STYLE[(name, policy)]
        d = seed0[seed0["model"].eq("logreg") & seed0["setting"].eq(name) & seed0["policy"].eq(policy)]
        n = len(d)
        target = "90%" if name == "A" else "95%"
        order = ORDER[policy]
        ax2.plot(grid, 100 * ecdf(d["time_to_review_min"].where(d["detected"]), grid, n), color=COLORS[name],
                 linestyle=ls, label=f"{target}, {order}")
    for ax, title in [(ax1, "(a) Time to first botnet alert"), (ax2, "(b) Time to first review of a botnet alert")]:
        ax.axvline(deadline, color=GRAY, linestyle="--", linewidth=0.8)
        ax.set_xscale("log")
        ticks = [t for t in [1, 10, 60, 600, 3000, 6000] if t <= upper]
        ax.set_xticks(ticks, [f"{t:,}" for t in ticks])
        ax.minorticks_off()
        ax.set_xlim(1, upper)
        ax.set_ylim(0, 102)
        ax.grid(linewidth=0.4, color="#DDDDDD")
        ax.set_xlabel("Minutes after documented infection (log scale)")
        ax.set_title(title, loc="left")
    ax1.set_ylabel(f"Infections, cumulative (% of {n})")
    ax1.legend(loc="upper left", frameon=False, fontsize=6)
    ax2.legend(loc="upper left", frameon=False, fontsize=6, handlelength=2.2)
    fig.tight_layout(w_pad=1.0)
    save(fig, outdir, "fig3_ctu13_timing")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, default=HERE / "results")
    ap.add_argument("--figures", type=Path, default=HERE / "figures")
    args = ap.parse_args()
    style()
    figure2(args.results, args.figures)
    figure3(args.results, args.figures)


if __name__ == "__main__":
    main()
