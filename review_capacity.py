"""Worked example of alert workload and review capacity, and Figure 1.

All inputs are hypothetical. Settings A and B are two invented operating points
of an email detector; they are not measurements of any product or deployment.

Assumptions: alert counts are daily expectations; every alert takes the same
review time; the 60 analyst-hours are spread evenly over the day, so the team
reviews alerts at a constant rate; unfinished alerts carry over to the next day.
When the queue is overloaded, the alerts reviewed each day are assumed to carry
the same threat share as the alerts arriving, which holds for random review order
or for first-in, first-out review when the threat share does not change over time.

Running this script writes
    calculations.csv          every quantity quoted in the article
    backlog.csv               end-of-day backlog for setting B, days 0 to 7
    fig1_alert_load.{svg,pdf,png}
to the output directories (default: figures/ next to this file for the
figures and this directory for the CSV files).
"""

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

# Hypothetical inputs
MESSAGES_PER_DAY = 1_000_000
THREATS_PER_DAY = 1_000
ANALYST_HOURS_PER_DAY = 60.0
MINUTES_PER_ALERT = 3.0
DAYS = 7
SETTINGS = {
    "A": {"detection_rate": 0.90, "false_positive_rate": 0.0001},
    "B": {"detection_rate": 0.95, "false_positive_rate": 0.001},
}

COLORS = {"A": "#27455C", "B": "#B5533C"}
GRAY = "#6B6B6B"


def capacity_alerts(minutes_per_alert):
    """Alerts the team can review per day at a given mean review time."""
    return ANALYST_HOURS_PER_DAY * 60.0 / minutes_per_alert


def expected_alerts(setting):
    """Expected true and false alerts per day for one setting."""
    p = SETTINGS[setting]
    legit = MESSAGES_PER_DAY - THREATS_PER_DAY
    true_alerts = THREATS_PER_DAY * p["detection_rate"]
    false_alerts = legit * p["false_positive_rate"]
    return true_alerts, false_alerts


def threats_examined(setting, minutes_per_alert, prioritized=False):
    """Detected threats reviewed per day once reviews run at full capacity.

    Without prioritization the reviewed alerts are assumed to carry the threat
    share of the arriving alerts (see the module assumptions). With perfect
    prioritization every true alert is reviewed before any false alert, which is
    an upper bound rather than an achievable policy. An overloaded queue that
    carries work over keeps growing, so these are daily review counts, not a
    steady state of the queue.
    """
    tp, fp = expected_alerts(setting)
    cap = capacity_alerts(minutes_per_alert)
    if prioritized:
        return np.minimum(tp, cap)
    return tp * np.minimum(1.0, cap / (tp + fp))


def backlog(setting, days=DAYS):
    """End-of-day unreviewed alerts, starting from an empty queue."""
    tp, fp = expected_alerts(setting)
    cap = capacity_alerts(MINUTES_PER_ALERT)
    queue = [0.0]
    for _ in range(days):
        queue.append(max(0.0, queue[-1] + tp + fp - cap))
    return queue


def calculations():
    rows = []

    def add(name, value, unit, note):
        rows.append({"quantity": name, "value": value, "unit": unit, "note": note})

    cap = capacity_alerts(MINUTES_PER_ALERT)
    add("messages_per_day", MESSAGES_PER_DAY, "messages/day", "input")
    add("threats_per_day", THREATS_PER_DAY, "messages/day", "input")
    add("legitimate_per_day", MESSAGES_PER_DAY - THREATS_PER_DAY, "messages/day", "derived")
    add("analyst_hours_per_day", ANALYST_HOURS_PER_DAY, "hours/day", "input")
    add("minutes_per_alert", MINUTES_PER_ALERT, "minutes", "input")
    add("capacity_alerts_per_day", cap, "alerts/day", "analyst hours x 60 / minutes per alert")
    for s, p in SETTINGS.items():
        tp, fp = expected_alerts(s)
        total = tp + fp
        add(f"{s}_detection_rate", p["detection_rate"], "fraction", "input")
        add(f"{s}_false_positive_rate", p["false_positive_rate"], "fraction", "input")
        add(f"{s}_true_alerts", tp, "alerts/day", "threats x detection rate")
        add(f"{s}_false_alerts", fp, "alerts/day", "legitimate x false-positive rate")
        add(f"{s}_total_alerts", total, "alerts/day", "true + false")
        add(f"{s}_precision", tp / total, "fraction", "true / total alerts")
        add(f"{s}_review_hours", total * MINUTES_PER_ALERT / 60.0, "analyst-hours/day", "total x minutes / 60")
        add(f"{s}_utilization", total / cap, "fraction", "total alerts / capacity")
        add(f"{s}_daily_excess", max(0.0, total - cap), "alerts/day", "total - capacity, if positive")
        add(f"{s}_threats_examined_unprioritized", float(threats_examined(s, MINUTES_PER_ALERT)),
            "threats/day", "per day at full capacity; reviewed alerts carry the arrival threat share")
        add(f"{s}_threats_examined_prioritized", float(threats_examined(s, MINUTES_PER_ALERT, True)),
            "threats/day", "upper bound, all true alerts reviewed first")
        add(f"{s}_backlog_day_{DAYS}", backlog(s)[-1], "alerts", "end of day, empty queue at day 0")
    tpa, fpa = expected_alerts("A")
    tpb, fpb = expected_alerts("B")
    add("extra_true_alerts_B_vs_A", tpb - tpa, "alerts/day", "B - A")
    add("extra_false_alerts_B_vs_A", fpb - fpa, "alerts/day", "B - A")
    add("extra_false_per_extra_threat", (fpb - fpa) / (tpb - tpa), "alerts", "ratio")
    add("extra_review_minutes_per_extra_threat", (fpb - fpa + tpb - tpa) * MINUTES_PER_ALERT / (tpb - tpa),
        "minutes", "all extra alerts x minutes / extra threats")
    add("total_alert_ratio_B_over_A", (tpb + fpb) / (tpa + fpa), "ratio", "B / A")
    add("fpr_difference_percentage_points",
        (SETTINGS["B"]["false_positive_rate"] - SETTINGS["A"]["false_positive_rate"]) * 100,
        "percentage points", "B - A")
    add("B_threats_unexamined_unprioritized", tpb - float(threats_examined("B", MINUTES_PER_ALERT)),
        "threats/day", "detected by B but not reviewed that day; never reviewed if the surplus is dropped")
    add("B_shortfall_vs_A_unprioritized",
        float(threats_examined("A", MINUTES_PER_ALERT)) - float(threats_examined("B", MINUTES_PER_ALERT)),
        "threats/day", "A examined - B examined")
    add("B_minutes_to_fit_capacity", ANALYST_HOURS_PER_DAY * 60.0 / (tpb + fpb), "minutes",
        "mean review time at which B load equals capacity")
    add("B_minutes_to_match_A_unprioritized", ANALYST_HOURS_PER_DAY * 60.0 * tpb / ((tpb + fpb) * tpa),
        "minutes", "mean review time below which B examines more threats than A")
    add("A_minutes_to_fit_capacity", ANALYST_HOURS_PER_DAY * 60.0 / (tpa + fpa), "minutes",
        "mean review time at which A load equals capacity")
    add("B_extra_analyst_hours_needed", (tpb + fpb) * MINUTES_PER_ALERT / 60.0 - ANALYST_HOURS_PER_DAY,
        "analyst-hours/day", "B review hours - available hours")
    add(f"B_wait_days_after_day_{DAYS}", backlog("B")[-1] / cap, "days",
        "first-in first-out wait of an alert arriving at the end of the day behind the backlog")
    add("B_backlog_growth_per_day", (tpb + fpb) - cap, "alerts/day", "arrivals - capacity")
    add("B_wait_growth_days_per_day", ((tpb + fpb) - cap) / cap, "days/day",
        "first-in first-out wait added per day of operation")
    add("B_days_until_wait_exceeds_one_day", cap / ((tpb + fpb) - cap), "days",
        "after this time every new alert waits more than a day under first in, first out")
    return rows


def style():
    plt.rcParams.update({
        "font.family": "DejaVu Serif",
        "font.size": 8,
        "axes.titlesize": 8,
        "axes.labelsize": 8,
        "xtick.labelsize": 7.5,
        "ytick.labelsize": 7.5,
        "legend.fontsize": 7.5,
        "axes.linewidth": 0.6,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "lines.linewidth": 1.4,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "svg.fonttype": "none",
        "svg.hashsalt": "review-capacity",
        "pdf.fonttype": 42,
    })


def save(fig, outdir, stem):
    meta_pdf = {"Creator": "Matplotlib", "Producer": "Matplotlib", "Title": None, "Author": None, "CreationDate": None}
    fig.savefig(outdir / f"{stem}.svg", metadata={"Creator": "Matplotlib", "Date": None})
    fig.savefig(outdir / f"{stem}.pdf", metadata=meta_pdf)
    fig.savefig(outdir / f"{stem}.png", dpi=300, metadata={"Software": "Matplotlib"})
    plt.close(fig)


def figure1(outdir):
    cap = capacity_alerts(MINUTES_PER_ALERT)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.5, 2.7), gridspec_kw={"width_ratios": [1, 1.25]})

    names = list(SETTINGS)
    x = np.arange(len(names)) * 1.3
    tps = [expected_alerts(s)[0] for s in names]
    fps = [expected_alerts(s)[1] for s in names]
    ax1.bar(x, tps, width=0.55, color=[COLORS[s] for s in names], label="Alerts on real threats")
    ax1.bar(x, fps, width=0.55, bottom=tps, color="white", edgecolor=[COLORS[s] for s in names],
            hatch="////", linewidth=0.8, label="False alarms")
    for xi, tp, fp in zip(x, tps, fps):
        ax1.text(xi, tp + fp + 40, f"{tp + fp:,.0f} total", ha="center", va="bottom", fontsize=7.5)
        ax1.text(xi, tp / 2, f"{tp:,.0f}\nthreats", ha="center", va="center", fontsize=7, color="white")
        ax1.text(xi + 0.30, tp + fp / 2, f"{fp:,.0f} false", ha="left", va="center", fontsize=7)
    ax1.axhline(cap, color=GRAY, linestyle="--", linewidth=0.9)
    ax1.text(-0.45, cap + 30, f"Capacity {cap:,.0f}/day", fontsize=7, color=GRAY,
             ha="left", va="bottom")
    ax1.set_xticks(x, [f"Setting {s}" for s in names])
    ax1.set_xlim(-0.5, 2.3)
    ax1.set_ylim(0, 2700)
    ax1.set_ylabel("Expected alerts per day")
    ax1.set_title("(a) Daily alert load", loc="left")
    handles = [plt.Rectangle((0, 0), 1, 1, color=GRAY),
               plt.Rectangle((0, 0), 1, 1, facecolor="white", edgecolor=GRAY, hatch="////", linewidth=0.8)]
    ax1.legend(handles, ["Alerts on real threats", "False alarms"], loc="upper left", frameon=False,
               ncol=2, handlelength=1.4, columnspacing=1.0, bbox_to_anchor=(-0.02, 1.0))

    days = np.arange(DAYS + 1)
    for s in names:
        ax2.plot(days, backlog(s), color=COLORS[s], marker="o", markersize=2.5,
                 linestyle="-" if s == "B" else "--", label=f"Setting {s}")
    b = backlog("B")
    ax2.annotate(f"{b[-1]:,.0f}", (days[-1], b[-1]), textcoords="offset points", xytext=(-4, 4),
                 ha="right", fontsize=7.5)
    ax2.text(4.3, 2300, f"B grows by {b[1]:,.0f}\nalerts per day", fontsize=7, color=COLORS["B"], ha="left")
    ax2.text(4.3, 180, "A stays at 0", fontsize=7, color=COLORS["A"], ha="left")
    ax2.set_xlabel("Day, starting from an empty queue")
    ax2.set_ylabel("Unreviewed alerts at end of day")
    ax2.set_xlim(0, DAYS + 0.2)
    ax2.set_ylim(0, 6000)
    ax2.set_xticks(days)
    ax2.grid(axis="y", linewidth=0.4, color="#DDDDDD")
    ax2.set_title("(b) Backlog at 3 minutes per alert", loc="left")
    ax2.legend(loc="upper left", frameon=False)
    fig.tight_layout(w_pad=2.0)
    save(fig, outdir, "fig1_alert_load")


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--figures", type=Path, default=here / "figures")
    ap.add_argument("--data", type=Path, default=here)
    args = ap.parse_args()
    args.figures.mkdir(parents=True, exist_ok=True)
    args.data.mkdir(parents=True, exist_ok=True)

    rows = calculations()
    with open(args.data / "calculations.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["quantity", "value", "unit", "note"], lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({**r, "value": repr(float(r["value"]))})
    with open(args.data / "backlog.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["day", "backlog_A", "backlog_B"])
        for d, (a, b) in enumerate(zip(backlog("A"), backlog("B"))):
            w.writerow([d, repr(a), repr(b)])

    style()
    figure1(args.figures)
    for r in rows:
        print(f"{r['quantity']:45s} {float(r['value']):14.4f}  {r['unit']}")


if __name__ == "__main__":
    main()
