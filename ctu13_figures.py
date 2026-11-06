"""Figures 2, 3, and 4 for the CTU-13 replay, drawn from the result files."""

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

from review_capacity import GRAY, save, style  # noqa: E402

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
CAPACITY = CONFIG["illustrative_capacity_per_hour"]
DEADLINE = CONFIG["deadline_minutes"]
SEED = CONFIG["model_seed"]
DETECTOR = {"logreg": ("Logistic regression", "#27455C"), "gbt": ("Gradient-boosted trees", "#3A7D6B"),
            "iforest": ("Isolation forest", "#B5533C")}
POLICY = {"fifo": "Each alert, arrival order", "score": "Each alert, highest score first",
          "fifo-host": "Grouped by computer, arrival order", "score-host": "Grouped by computer, highest score first"}
BUDGET_SHADES = {10: "#C6DBEF", 30: "#9ECAE1", 60: "#4292C6", 120: "#2171B5", 300: "#08306B"}
GRID = {"linewidth": 0.4, "color": "#DDDDDD"}


def display_subset(p):
    """At most one attainable point per small cell of log alert volume and detection, for drawing only."""
    cell = pd.DataFrame({"x": np.round(np.log10(p["alerts_per_hour"]) * 200), "y": np.round(p["detection"] * 500)})
    return p.loc[~cell.duplicated().to_numpy()]


def log_axis(ax, ticks, lim):
    ax.set_xscale("log")
    ax.set_xlim(*lim)
    ax.set_xticks(ticks, [f"{t:,}" if t >= 1 else f"{t:g}" for t in ticks])
    ax.minorticks_off()


def figure2(res, outdir):
    st = pd.read_csv(res / "ctu13_settings.csv")
    pts = pd.read_csv(res / "ctu13_operating_points.csv")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.5, 3.0))

    for kind, (name, color) in DETECTOR.items():
        d = st[st["model"].eq(kind) & np.isfinite(st["threshold"])]
        for rule, marker in (("alert budget", "o"), ("detection target", "^")):
            e = d[d["rule"].eq(rule)]
            if len(e):
                ax1.plot(e["train_alerts_per_hour"].clip(lower=0.1), e["test_alerts_per_hour"].clip(lower=0.1),
                         linestyle="none", marker=marker, markersize=3.2, markerfacecolor="white" if rule ==
                         "detection target" else color, markeredgecolor=color, markeredgewidth=0.7,
                         label=f"{name}, {'target' if rule == 'detection target' else 'budget'}")
    lim = (1, 5000)
    ax1.plot(lim, lim, color=GRAY, linewidth=0.7, linestyle=":")
    ax1.axhline(CAPACITY, color=GRAY, linestyle="--", linewidth=0.8)
    ax1.text(1.2, CAPACITY * 1.12, f"{CAPACITY} reviews per hour", fontsize=6.5, color=GRAY)
    log_axis(ax1, [1, 10, 100, 1000], lim)
    ax1.set_yscale("log")
    ax1.set_ylim(*lim)
    ax1.set_yticks([1, 10, 100, 1000], ["1", "10", "100", "1,000"])
    ax1.minorticks_off()
    ax1.set_xlabel("Alerts per hour on training captures (log scale)")
    ax1.set_ylabel("Alerts per hour on later captures (log scale)")
    ax1.grid(**GRID)
    ax1.set_title("(a) Alert volume, training and later captures", loc="left")
    ax1.legend(loc="upper left", frameon=False, fontsize=5.8, handlelength=1.0, borderaxespad=0.2)

    for kind, (name, color) in DETECTOR.items():
        p = display_subset(pts[pts["model"].eq(kind)])
        ax2.plot(p["alerts_per_hour"], 100 * p["detection"], linestyle="none", marker="o", markersize=0.9,
                 color=color, alpha=0.6)
        d = st[st["model"].eq(kind) & st["seed"].eq(SEED) & st["rule"].eq("alert budget")]
        ax2.plot(d["test_alerts_per_hour"], 100 * d["test_detection"], linestyle="none", marker="o", markersize=3.4,
                 color=color, markeredgecolor="black", markeredgewidth=0.4, label=name)
    ax2.axvline(CAPACITY, color=GRAY, linestyle="--", linewidth=0.8)
    log_axis(ax2, [0.1, 1, 10, 100, 1000], (0.05, 3000))
    ax2.set_ylim(0, 102)
    ax2.set_xlabel("Alerts per hour on later captures (log scale)")
    ax2.set_ylabel("Botnet windows alerted (%)")
    ax2.grid(**GRID)
    ax2.set_title("(b) Detection against alert volume", loc="left")
    ax2.legend(loc="upper left", frameon=False, fontsize=6, handlelength=1.0)
    fig.tight_layout(w_pad=1.2)
    save(fig, outdir, "fig2_ctu13_volume")


def figure3(res, outdir, models=("logreg", "iforest"), seed=SEED):
    qu = pd.read_csv(res / "ctu13_queue.csv")
    qu = qu[qu["seed"].eq(seed)]
    total = int(qu["infections"].iloc[0])
    fig, axes = plt.subplots(len(models), 4, figsize=(6.5, 4.3), sharey=True, sharex=True)
    for row, model in zip(axes, models):
        q_model = qu[qu["model"].eq(model)]
        for ax, (policy, title) in zip(row, POLICY.items()):
            curves = []
            for b, color in BUDGET_SHADES.items():
                q = q_model[q_model["setting"].eq(f"B{b}") & q_model["policy"].eq(policy)].sort_values(
                    "capacity_per_hour")
                curves.append(tuple(q["infections_ontime_median"]))
                ax.fill_between(q["capacity_per_hour"], q["infections_ontime_min"], q["infections_ontime_max"],
                                color=color, alpha=0.3, linewidth=0)
                ax.plot(q["capacity_per_hour"], q["infections_ontime_median"], color=color, marker="o",
                        markersize=1.6, linewidth=1.1, label=f"{b} per training hour")
            if len(set(curves)) == 1:
                ax.text(12, total - 2.5, "All five budgets\ncoincide", fontsize=6, color=GRAY, va="top")
            ax.axvline(CAPACITY, color=GRAY, linestyle="--", linewidth=0.8)
            log_axis(ax, [10, 30, 100, 400], (9, 450))
            ax.grid(**GRID)
            if model == models[0]:
                ax.set_title(title.replace(", ", ",\n"), loc="left", fontsize=7)
            if model == models[-1]:
                ax.set_xlabel("Reviews per hour")
        row[0].set_ylabel(f"{DETECTOR[model][0]}\nInfections reviewed\nwithin {DEADLINE} minutes (of {total})",
                          fontsize=7)
    axes[0][0].set_ylim(0, total + 1)
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=5, frameon=False, fontsize=6.2, handlelength=1.4,
               title="Alert budget fixed on the training captures", title_fontsize=6.4, bbox_to_anchor=(0.5, 0.0))
    fig.tight_layout(w_pad=0.6, h_pad=0.8, rect=(0, 0.08, 1, 1))
    save(fig, outdir, "fig3_ctu13_capacity")


def ecdf(values, grid, n):
    v = np.sort(np.asarray(values, dtype=float))
    v = v[~np.isnan(v)]
    return np.searchsorted(v, grid, side="right") / n


def figure4(res, outdir, model="logreg", setting="B60"):
    tim = pd.read_csv(res / "ctu13_infection_timing.csv")
    d0 = tim[tim["tie_seed"].eq(CONFIG["tie_seeds"][0]) & tim["seed"].eq(SEED)]
    upper = max(3000.0, 1.05 * float(d0["time_to_review_min"].max()))
    grid = np.geomspace(1, upper, 800)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.5, 2.8), sharey=True)
    for kind, (name, color) in DETECTOR.items():
        d = d0[d0["model"].eq(kind) & d0["setting"].eq(setting) & d0["policy"].eq("fifo")]
        ax1.plot(grid, 100 * ecdf(d["detection_delay_min"], grid, len(d)), color=color, label=name)
    styles = {"fifo": ("-", "#27455C"), "score": ("-.", "#27455C"), "fifo-host": ("-", "#B5533C"),
              "score-host": ("-.", "#B5533C")}
    for policy, title in POLICY.items():
        d = d0[d0["model"].eq(model) & d0["setting"].eq(setting) & d0["policy"].eq(policy)]
        ls, color = styles[policy]
        ax2.plot(grid, 100 * ecdf(d["time_to_review_min"].where(d["detected"]), grid, len(d)), color=color,
                 linestyle=ls, label=title)
    for ax, title in [(ax1, "(a) Time to first botnet alert"), (ax2, "(b) Time to first review of a botnet alert")]:
        ax.axvline(DEADLINE, color=GRAY, linestyle="--", linewidth=0.8)
        ticks = [t for t in [1, 10, 60, 600, 3000] if t <= upper]
        log_axis(ax, ticks, (1, upper))
        ax.set_ylim(0, 102)
        ax.grid(**GRID)
        ax.set_xlabel("Minutes after documented infection (log scale)")
        ax.set_title(title, loc="left")
    n = int(len(d0[d0["model"].eq(model) & d0["setting"].eq(setting) & d0["policy"].eq("fifo")]))
    ax1.set_ylabel(f"Infections, cumulative (% of {n})")
    ax1.legend(loc="upper left", frameon=False, fontsize=6)
    ax2.legend(loc="upper left", frameon=False, fontsize=5.8, handlelength=2.0)
    fig.tight_layout(w_pad=1.0)
    save(fig, outdir, "fig4_ctu13_timing")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, default=HERE / "results")
    ap.add_argument("--figures", type=Path, default=HERE / "figures")
    args = ap.parse_args()
    args.figures.mkdir(parents=True, exist_ok=True)
    style()
    figure2(args.results, args.figures)
    figure3(args.results, args.figures)
    figure4(args.results, args.figures)


if __name__ == "__main__":
    main()
