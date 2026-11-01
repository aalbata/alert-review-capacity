"""Offline replay of alert workload on the CTU-13 botnet captures.

Stage 1, run with --raw DIR: read the 13 labeled bidirectional Argus flow files and build, for each
export delay d in EXPORT_DELAYS_S, one row per internal source host (147.32.0.0/16) and five-minute
window of record availability. A flow record is treated as available d seconds after its end time
(start plus duration): its statistics cannot exist before the record's last packet, and the CTU-13
Argus configuration reports a long-lived flow at most once an hour (ARGUS_FLOW_STATUS_INTERVAL=3600).
A window's features use only records that became available inside it, the window is positive if it
contains a record labeled From-Botnet that starts at or after the host's infection onset, and its alert
time is the end of the window. The onset of each infection (a capture and host with From-Botnet records)
is the infection time documented in the capture's README, listed in config.json; where none is documented,
it is the start of the host's first From-Botnet record. From-Botnet records that start before the onset
are treated as ordinary traffic. Host addresses are replaced by per-capture identifiers (h0, h1, ...); botnet
source addresses are listed under identifiers (b0, b1, ...) that are consistent across captures.

Stage 2, the default: train detectors on the six earliest captures, set each alert threshold on those
captures only (a detection target or an alert budget, by leave-one-capture-out), apply the thresholds
unchanged to the seven later captures, and replay each test capture's alerts through a single review
queue with a fixed number of reviews per hour. All times are seconds or minutes from the start of the
capture.
"""

import argparse
import heapq
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
WINDOW_S = CONFIG["window_minutes"] * 60
EXPORT_DELAYS_S = CONFIG["export_delays_s"]
MAIN_DELAY_S = CONFIG["main_export_delay_s"]
DEADLINE_MIN = CONFIG["deadline_minutes"]
TRAIN = CONFIG["train_scenarios"]
TEST = CONFIG["test_scenarios"]
TARGETS = CONFIG["detection_targets"]
CAPACITY_GRID = CONFIG["capacity_grid_per_hour"]
BUDGETS = CONFIG["alert_budgets_per_hour"]
MODEL_SEED = CONFIG["model_seed"]
MODEL_SEEDS = CONFIG["model_seed_range"]
TIE_SEEDS = CONFIG["tie_seeds"]
INTERNAL_PREFIX = CONFIG["internal_prefix"]
FAMILY = {int(k): v for k, v in CONFIG["family_from_capture_readme"].items()}
INFECTION_TIMES = {int(k): v for k, v in CONFIG["infection_times_cest"].items()}

COUNT_COLS = ["n_flows", "n_dst", "n_dport", "n_sport", "bytes_src", "bytes", "pkts"]
FRAC_COLS = ["f_tcp", "f_udp", "f_icmp", "f_small", "f_tcp_fail", "f_p25", "f_p53", "f_web", "f_irc",
             "f_high"]
FEATURES = COUNT_COLS + ["dur_mean"] + FRAC_COLS
RAW_DTYPES = {"Sport": str, "Dport": str, "State": str, "Proto": str, "SrcAddr": str, "DstAddr": str,
              "Label": str, "Dir": str}


# Stage 1: flow records to host windows

def read_flows(path):
    """Read one flow file; return internal-source records with start and end in seconds, and metadata."""
    df = pd.read_csv(path, dtype=RAW_DTYPES)
    start = pd.to_datetime(df["StartTime"], format="%Y/%m/%d %H:%M:%S.%f")
    t0 = start.min()
    df["t_start"] = (start - t0).dt.total_seconds()
    df["t_end"] = df["t_start"] + df["Dur"].fillna(0.0)
    meta = {"start": str(t0), "records": len(df), "last_start_s": float(df["t_start"].max()),
            "last_end_s": float(df["t_end"].max()), "max_duration_s": float(df["Dur"].max())}
    df = df[df["SrcAddr"].str.startswith(INTERNAL_PREFIX)].reset_index(drop=True)
    return df, meta


def flow_flags(df, onset_s=None):
    """Per-record indicator columns used by the window features.

    A record is botnet traffic if its label starts with From-Botnet and, when `onset_s` maps the source
    address to an infection onset, it starts at or after that onset.
    """
    proto = df["Proto"].str.lower()
    dport = pd.to_numeric(df["Dport"], errors="coerce")
    state = df["State"].fillna("")
    parts = state.str.split("_", n=1, expand=True).reindex(columns=[0, 1]).fillna("")
    established = parts[0].str.contains("A") & parts[1].str.contains("A")
    out = pd.DataFrame(index=df.index)
    out["f_tcp"] = proto.eq("tcp")
    out["f_udp"] = proto.eq("udp")
    out["f_icmp"] = proto.eq("icmp")
    out["f_small"] = df["TotPkts"] <= 2
    out["f_tcp_fail"] = out["f_tcp"] & ~established
    out["f_p25"] = dport.eq(25)
    out["f_p53"] = dport.eq(53)
    out["f_web"] = dport.isin([80, 443])
    out["f_irc"] = dport.between(6660, 6669)
    out["f_high"] = dport.gt(1024)
    out["pos"] = df["Label"].str.contains("From-Botnet", regex=False)
    if onset_s is not None:
        out["pos"] &= df["t_start"] >= df["SrcAddr"].map(onset_s).fillna(np.inf)
    return out


def aggregate_windows(df, flags, delay_s):
    """One row per host and availability window; a record joins the window holding t_end + delay_s."""
    work = pd.concat([df[["SrcAddr", "DstAddr", "Dport", "Sport", "SrcBytes", "TotBytes", "TotPkts", "Dur"]],
                      flags], axis=1)
    work["win"] = ((df["t_end"] + delay_s) // WINDOW_S).astype(int)
    g = work.groupby(["SrcAddr", "win"], sort=True)
    out = pd.DataFrame({
        "n_flows": g.size(),
        "n_dst": g["DstAddr"].nunique(),
        "n_dport": g["Dport"].nunique(),
        "n_sport": g["Sport"].nunique(),
        "bytes_src": g["SrcBytes"].sum(),
        "bytes": g["TotBytes"].sum(),
        "pkts": g["TotPkts"].sum(),
        "dur_mean": g["Dur"].mean(),
    })
    for c in FRAC_COLS:
        out[c] = g[c].mean()
    out["pos"] = g["pos"].max().astype(int)
    return out.reset_index()


def infection_onsets(df, scenario, t0):
    """Onset in seconds from capture start for every address with From-Botnet records, and its source."""
    labeled = df["Label"].str.contains("From-Botnet", regex=False)
    onset, source = {}, {}
    documented = INFECTION_TIMES.get(scenario, {})
    for addr in pd.unique(df.loc[labeled, "SrcAddr"]):
        if addr in documented:
            onset[addr] = (pd.Timestamp(documented[addr]) - t0).total_seconds()
            source[addr] = "capture README"
        else:
            onset[addr] = float(df.loc[labeled & df["SrcAddr"].eq(addr), "t_start"].min())
            source[addr] = "first From-Botnet record"
    return onset, source


def build_windows(raw_dir, data_dir):
    host_frames = {d: [] for d in EXPORT_DELAYS_S}
    captures, infections, botnet_ids = [], [], {}
    for path in sorted(Path(raw_dir).glob("s*_capture*.binetflow")):
        scenario = int(path.name.split("_")[0][1:])
        df, meta = read_flows(path)
        onset_s, source = infection_onsets(df, scenario, pd.Timestamp(meta["start"]))
        flags = flow_flags(df, onset_s)
        labeled = df["Label"].str.contains("From-Botnet", regex=False)
        hosts = {a: f"h{i}" for i, a in enumerate(pd.unique(df["SrcAddr"]))}
        bot = df[flags["pos"]]
        for addr in sorted(bot["SrcAddr"].unique()):
            botnet_ids.setdefault(addr, f"b{len(botnet_ids)}")
        for addr, rec in bot.groupby("SrcAddr"):
            infections.append({"scenario": scenario, "host": hosts[addr], "botnet_source": botnet_ids[addr],
                               "onset_s": float(onset_s[addr]), "onset_source": source[addr],
                               "first_botnet_record_start_s": float(rec["t_start"].min()),
                               "first_botnet_record_end_s": float(rec["t_end"].min()),
                               "botnet_records": len(rec),
                               "labeled_records_before_onset": int((labeled & df["SrcAddr"].eq(addr)
                                                                    & ~flags["pos"]).sum())})
        for d in EXPORT_DELAYS_S:
            w = aggregate_windows(df, flags, d)
            w["SrcAddr"] = w["SrcAddr"].map(hosts)
            w = w.rename(columns={"SrcAddr": "host"})
            w.insert(0, "scenario", scenario)
            host_frames[d].append(w)
        captures.append({"scenario": scenario, "family": FAMILY[scenario], **meta,
                         "internal_records": len(df), "botnet_records": int(flags["pos"].sum()),
                         "labeled_records_before_onset": int((labeled & ~flags["pos"]).sum()),
                         "internal_records_over_300s": int((df["Dur"] > 300).sum()),
                         "botnet_sources": ";".join(sorted({botnet_ids[a] for a in bot["SrcAddr"].unique()},
                                                           key=lambda x: int(x[1:])))})
        print(f"scenario {scenario}: {len(df)} internal records, {int(flags['pos'].sum())} botnet records")
    data_dir.mkdir(parents=True, exist_ok=True)
    for d in EXPORT_DELAYS_S:
        pd.concat(host_frames[d], ignore_index=True).to_csv(
            data_dir / f"ctu13_windows_d{d}.csv.gz", index=False, compression={"method": "gzip", "mtime": 0})
    pd.DataFrame(captures).sort_values("scenario").to_csv(data_dir / "ctu13_captures.csv", index=False)
    pd.DataFrame(infections).sort_values(["scenario", "host"]).to_csv(data_dir / "ctu13_infections.csv",
                                                                       index=False)


# Stage 2: detection, thresholds, queue replay

def model(kind, seed=MODEL_SEED):
    if kind == "gbt":
        return HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, random_state=seed)
    return make_pipeline(StandardScaler(), LogisticRegression(max_iter=5000))


def design(df):
    x = df[FEATURES].astype(float).copy()
    for c in COUNT_COLS:
        x[c] = np.log1p(x[c])
    x["dur_mean"] = np.log1p(x["dur_mean"].clip(lower=0))
    return x.to_numpy()


def threshold_for_detection(pos_scores, rate):
    """Largest score t such that at least `rate` of the given positive scores satisfy score >= t."""
    s = np.sort(np.asarray(pos_scores))[::-1]
    k = max(1, int(math.ceil(rate * len(s) - 1e-12)))
    return float(s[k - 1])


def threshold_for_budget(scores, hours, budget_per_hour):
    """Smallest distinct score t with count(score >= t) / hours <= budget; inf if even the top tie exceeds it."""
    vals, counts = np.unique(np.asarray(scores), return_counts=True)
    vals, counts = vals[::-1], counts[::-1]
    cum = np.cumsum(counts)
    ok = cum <= budget_per_hour * hours
    return float(vals[ok][-1]) if ok.any() else float("inf")


def operating_points(scores, labels):
    """Attainable points of the rule score >= t at every distinct score t, ties included."""
    scores, labels = np.asarray(scores), np.asarray(labels).astype(int)
    order = np.argsort(-scores, kind="stable")
    s, y = scores[order], labels[order]
    last = np.r_[s[1:] != s[:-1], True]
    alerts = np.arange(1, len(s) + 1)[last]
    true_alerts = np.cumsum(y)[last]
    return pd.DataFrame({"threshold": s[last], "alerts": alerts, "true_alerts": true_alerts})


def loco_scores(train, kind, seed=MODEL_SEED):
    oof = np.zeros(len(train))
    for s in TRAIN:
        m = train["scenario"].eq(s).to_numpy()
        clf = model(kind, seed).fit(design(train[~m]), train.loc[~m, "pos"])
        oof[m] = clf.predict_proba(design(train[m]))[:, 1]
    return oof


def tie_ranks(n, seed):
    """Label-independent random ranks used to order alerts that are otherwise tied."""
    return np.random.default_rng(seed).permutation(n)


def replay(arrival_min, score, capacity_per_hour, policy, ranks):
    """Single work-conserving review queue; returns the completion minute of every alert.

    The queue starts empty, serves one alert at a time at capacity_per_hour, and keeps working after
    the last arrival until it is empty. Policy "fifo" serves the earliest alert time first and
    "score" serves the highest detector score first; remaining ties follow `ranks`.
    """
    service = 60.0 / capacity_per_hour
    arr = np.asarray(arrival_min, dtype=float)
    order = np.lexsort((ranks, arr))
    done = np.full(len(arr), np.nan)
    heap, t, i = [], 0.0, 0
    while i < len(order) or heap:
        if not heap:
            t = max(t, arr[order[i]])
        while i < len(order) and arr[order[i]] <= t:
            k = order[i]
            key = (arr[k], ranks[k], k) if policy == "fifo" else (-score[k], arr[k], ranks[k], k)
            heapq.heappush(heap, key)
            i += 1
        k = heapq.heappop(heap)[-1]
        t += service
        done[k] = t
    return done


def infection_outcomes(alerts, infections, deadline_min=DEADLINE_MIN):
    """Per infection: first review of a botnet-positive alert of that host, measured from onset.

    `alerts` has columns host, alert_min, completion_min, pos; `infections` has host, onset_min.
    Only alerts on botnet-positive windows qualify, so a review of an earlier benign alert from the
    same host never counts.
    """
    rows = []
    for inf in infections.itertuples():
        q = alerts[(alerts["host"] == inf.host) & (alerts["pos"] == 1)]
        if len(q) == 0:
            rows.append({"host": inf.host, "detected": False, "on_time": False, "detection_delay_min": np.nan,
                         "queue_delay_min": np.nan, "time_to_review_min": np.nan})
            continue
        assert (q["alert_min"] >= inf.onset_min - 1e-9).all()
        j = q["completion_min"].idxmin()
        review = q.at[j, "completion_min"]
        rows.append({"host": inf.host, "detected": True,
                     "on_time": bool(review - inf.onset_min <= deadline_min),
                     "detection_delay_min": float(q["alert_min"].min() - inf.onset_min),
                     "queue_delay_min": float(review - q.at[j, "alert_min"]),
                     "time_to_review_min": float(review - inf.onset_min)})
    return pd.DataFrame(rows, columns=["host", "detected", "on_time", "detection_delay_min", "queue_delay_min",
                                       "time_to_review_min"])


def capture_alerts(cap, flag, score):
    """Alerts of one capture, ordered by host and window, with alert time at the window end."""
    f = flag[cap.index]
    return pd.DataFrame({"host": cap["host"].to_numpy()[f],
                         "alert_min": (cap["win"].to_numpy()[f] + 1) * WINDOW_S / 60.0,
                         "score": score[cap.index][f], "pos": cap["pos"].to_numpy()[f]}).reset_index(drop=True)


def evaluate_queue(test, infections, flag, score, capacity, policy, tie_seed, detail=False):
    """Queue outcomes summed over test captures, each replayed from an empty queue."""
    out = {"pos_windows": 0, "pos_windows_alerted": 0, "pos_windows_ontime": 0, "alerts": 0,
           "alerts_ontime": 0, "infections": 0, "infections_detected": 0, "infections_ontime": 0}
    per_inf = []
    for s in TEST:
        cap = test[test["scenario"].eq(s)]
        al = capture_alerts(cap, flag, score)
        ranks = tie_ranks(len(al), tie_seed * 1000 + s)
        al["completion_min"] = (replay(al["alert_min"].to_numpy(), al["score"].to_numpy(), capacity, policy, ranks)
                                if len(al) else np.array([]))
        ontime = (al["completion_min"] - al["alert_min"]) <= DEADLINE_MIN
        out["pos_windows"] += int(cap["pos"].sum())
        out["pos_windows_alerted"] += int(al["pos"].sum())
        out["pos_windows_ontime"] += int((ontime & al["pos"].eq(1)).sum())
        out["alerts"] += len(al)
        out["alerts_ontime"] += int(ontime.sum())
        inf = infections[infections["scenario"].eq(s)].copy()
        inf["onset_min"] = inf["onset_s"] / 60.0
        res = infection_outcomes(al, inf)
        out["infections"] += len(res)
        out["infections_detected"] += int(res["detected"].sum())
        out["infections_ontime"] += int(res["on_time"].sum())
        if detail:
            res.insert(0, "scenario", s)
            per_inf.append(res)
    return (out, pd.concat(per_inf, ignore_index=True)) if detail else out


def fit_settings(train, test, hours, kind, seed):
    """Leave-one-capture-out thresholds for each detection target, applied to the test captures."""
    oof = loco_scores(train, kind, seed)
    clf = model(kind, seed).fit(design(train), train["pos"])
    sc = clf.predict_proba(design(test))[:, 1]
    ytr = train["pos"].to_numpy().astype(bool)
    rows = []
    for name, rate in TARGETS.items():
        thr = threshold_for_detection(oof[ytr], rate)
        rows.append({"model": kind, "seed": seed, "setting": name, "train_target_detection": rate,
                     "threshold": thr, **test_metrics(test, hours, sc, thr),
                     "train_loco_detection": float((oof[ytr] >= thr).mean()),
                     "train_loco_false_alert_rate": float((oof[~ytr] >= thr).mean())})
    return rows, oof, sc


def test_metrics(test, hours, sc, thr):
    y = test["pos"].to_numpy().astype(bool)
    flag = sc >= thr
    test_hours = float(hours.loc[TEST].sum())
    hourly = pd.Series(flag.astype(int)).groupby([test["scenario"], ((test["win"] + 1) * WINDOW_S) // 3600]).sum()
    return {"test_detection": float(flag[y].mean()), "test_alerts": int(flag.sum()),
            "test_alerts_per_hour": float(flag.sum() / test_hours),
            "test_peak_alerts_in_hour": int(hourly.max()) if len(hourly) else 0,
            "test_precision": float(y[flag].mean()) if flag.any() else float("nan"),
            "test_false_alert_rate": float(flag[~y].mean())}


def detection_at_false_alert_rate(scores, labels, far):
    """Highest detection among attainable thresholds whose false-alert rate is at most `far`."""
    labels = np.asarray(labels).astype(int)
    p = operating_points(scores, labels)
    pos, neg = labels.sum(), len(labels) - labels.sum()
    ok = (p["alerts"] - p["true_alerts"]) / neg <= far
    return float(p.loc[ok, "true_alerts"].max() / pos) if ok.any() else 0.0


def split_comparison(all_windows, test, test_scores, kind, seed):
    """Ranking quality on the time-ordered test captures and on a random half of all windows.

    Both are retrospective: the false-alert rate is fixed on the evaluated set itself, so the comparison
    concerns how well each split's model ranks botnet windows, not how a threshold transfers.
    """
    far = CONFIG["comparison_false_alert_rate"]
    rng = np.random.default_rng(seed)
    m = rng.random(len(all_windows)) < 0.5
    tr, te = all_windows[m].reset_index(drop=True), all_windows[~m].reset_index(drop=True)
    sc = model(kind, seed).fit(design(tr), tr["pos"]).predict_proba(design(te))[:, 1]
    return {"model": kind, "seed": seed, "false_alert_rate": far,
            "time_split_detection": detection_at_false_alert_rate(test_scores, test["pos"], far),
            "time_split_average_precision": float(average_precision_score(test["pos"], test_scores)),
            "random_split_detection": detection_at_false_alert_rate(sc, te["pos"], far),
            "random_split_average_precision": float(average_precision_score(te["pos"], sc))}


def run_delay(data_dir, delay_s, full, capacity):
    windows = pd.read_csv(data_dir / f"ctu13_windows_d{delay_s}.csv.gz")
    captures = pd.read_csv(data_dir / "ctu13_captures.csv")
    infections = pd.read_csv(data_dir / "ctu13_infections.csv")
    infections = infections[infections["scenario"].isin(TEST)].reset_index(drop=True)
    hours = (captures.set_index("scenario")["last_end_s"] + delay_s) / 3600.0
    train = windows[windows["scenario"].isin(TRAIN)].reset_index(drop=True)
    test = windows[windows["scenario"].isin(TEST)].reset_index(drop=True)

    settings, scores, oofs = [], {}, {}
    for kind in ["gbt", "logreg"]:
        rows, oof, sc = fit_settings(train, test, hours, kind, MODEL_SEED)
        settings += rows
        scores[kind], oofs[kind] = sc, oof
    settings = pd.DataFrame(settings)

    grid = sorted(set(CAPACITY_GRID) | {capacity}) if full else [capacity]
    queue = []
    for row in settings.itertuples():
        flag = scores[row.model] >= row.threshold
        for policy in ["fifo", "score"]:
            for c in grid:
                for ts in TIE_SEEDS:
                    r = evaluate_queue(test, infections, flag, scores[row.model], c, policy, ts)
                    queue.append({"model": row.model, "setting": row.setting, "policy": policy,
                                  "capacity_per_hour": c, "tie_seed": ts, **r})
    return {"settings": settings, "queue": pd.DataFrame(queue), "scores": scores, "oofs": oofs,
            "infections": infections, "train": train, "test": test, "hours": hours,
            "train_hours": float(hours.loc[TRAIN].sum()), "test_hours": float(hours.loc[TEST].sum())}


def train_test_gap_minutes(captures):
    """Minutes between the last training-record end and the first test-record start."""
    c = captures.set_index("scenario")
    start = pd.to_datetime(c["start"])
    train_end = (start.loc[TRAIN] + pd.to_timedelta(c.loc[TRAIN, "last_end_s"], unit="s")).max()
    return float((start.loc[TEST].min() - train_end).total_seconds() / 60.0)


def summarize_queue(queue):
    q = queue.copy()
    q["share_pos_windows_ontime"] = q["pos_windows_ontime"] / q["pos_windows"]
    q["share_infections_ontime"] = q["infections_ontime"] / q["infections"]
    keys = ["model", "setting", "policy", "capacity_per_hour"]
    agg = q.groupby(keys).agg(
        pos_windows=("pos_windows", "first"), pos_windows_alerted=("pos_windows_alerted", "first"),
        pos_windows_ontime_median=("pos_windows_ontime", "median"),
        pos_windows_ontime_min=("pos_windows_ontime", "min"), pos_windows_ontime_max=("pos_windows_ontime", "max"),
        infections=("infections", "first"), infections_detected=("infections_detected", "first"),
        infections_ontime_median=("infections_ontime", "median"),
        infections_ontime_min=("infections_ontime", "min"), infections_ontime_max=("infections_ontime", "max"),
        alerts=("alerts", "first"), tie_seeds=("tie_seed", "nunique")).reset_index()
    return q, agg


def run(data_dir, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    capacity = CONFIG["illustrative_capacity_per_hour"]
    main = run_delay(data_dir, MAIN_DELAY_S, full=True, capacity=capacity)
    settings, test, train, hours = main["settings"], main["test"], main["train"], main["hours"]
    queue, queue_summary = summarize_queue(main["queue"])

    # Seed variation, training-budget thresholds, and split comparison
    seed_rows, budget_rows, split_rows = [], [], []
    all_windows = pd.concat([train, test]).reset_index(drop=True)
    for kind, seeds in (("gbt", MODEL_SEEDS), ("logreg", [MODEL_SEED])):
        for seed in seeds:
            rows, oof, sc = fit_settings(train, test, hours, kind, seed)
            seed_rows += rows
            for b in BUDGETS:
                thr = threshold_for_budget(oof, main["train_hours"], b)
                budget_rows.append({"model": kind, "seed": seed, "budget_per_hour": b, "threshold": thr,
                                    "train_loco_alerts_per_hour": float((oof >= thr).sum() / main["train_hours"]),
                                    **test_metrics(test, hours, sc, thr)})
            split_rows.append(split_comparison(all_windows, test, sc, kind, seed))
    seed_rows, budget_rows, split_rows = map(pd.DataFrame, (seed_rows, budget_rows, split_rows))

    # Operating points at distinct thresholds (retrospective, test captures)
    pts = []
    for kind, sc in main["scores"].items():
        p = operating_points(sc, test["pos"].to_numpy())
        p.insert(0, "model", kind)
        p["alerts_per_hour"] = p["alerts"] / main["test_hours"]
        p["detection"] = p["true_alerts"] / int(test["pos"].sum())
        pts.append(p)
    pts = pd.concat(pts, ignore_index=True)

    # Per-infection timing at the illustrative capacity, every tie seed
    details = []
    for row in settings.itertuples():
        flag = main["scores"][row.model] >= row.threshold
        for policy in ["fifo", "score"]:
            for ts in TIE_SEEDS:
                _, d = evaluate_queue(test, main["infections"], flag, main["scores"][row.model], capacity, policy,
                                      ts, detail=True)
                d.insert(0, "tie_seed", ts)
                d.insert(0, "policy", policy)
                d.insert(0, "setting", row.setting)
                d.insert(0, "model", row.model)
                details.append(d)
    details = pd.concat(details, ignore_index=True)

    # Per-capture detection and load
    per_capture = []
    for row in settings.itertuples():
        flag = main["scores"][row.model] >= row.threshold
        for s in TEST:
            m = test["scenario"].eq(s).to_numpy()
            y = test["pos"].to_numpy()[m].astype(bool)
            hourly = pd.Series(flag[m].astype(int)).groupby(((test["win"].to_numpy()[m] + 1) * WINDOW_S) // 3600).sum()
            per_capture.append({"model": row.model, "setting": row.setting, "scenario": s, "family": FAMILY[s],
                                "infections": int(main["infections"]["scenario"].eq(s).sum()),
                                "positive_windows": int(y.sum()), "detected": int(flag[m][y].sum()),
                                "alerts": int(flag[m].sum()), "peak_alerts_in_hour": int(hourly.max()),
                                "hours": float(hours.loc[s])})
    per_capture = pd.DataFrame(per_capture)

    # Export-delay sensitivity at the illustrative capacity
    sens = []
    for d in EXPORT_DELAYS_S:
        r = main if d == MAIN_DELAY_S else run_delay(data_dir, d, full=False, capacity=capacity)
        _, qs = summarize_queue(r["queue"])
        qs = qs[qs["capacity_per_hour"].eq(capacity)]
        for row in r["settings"].itertuples():
            for policy in ["fifo", "score"]:
                z = qs[qs["model"].eq(row.model) & qs["setting"].eq(row.setting) & qs["policy"].eq(policy)]
                sens.append({"export_delay_s": d, "model": row.model, "setting": row.setting, "policy": policy,
                             "capacity_per_hour": capacity, "threshold": row.threshold,
                             "test_detection": row.test_detection, "test_alerts_per_hour": row.test_alerts_per_hour,
                             "pos_windows": int(z["pos_windows"].iloc[0]),
                             "pos_windows_ontime_median": float(z["pos_windows_ontime_median"].iloc[0]),
                             "pos_windows_ontime_min": int(z["pos_windows_ontime_min"].iloc[0]),
                             "pos_windows_ontime_max": int(z["pos_windows_ontime_max"].iloc[0]),
                             "infections": int(z["infections"].iloc[0]),
                             "infections_ontime_median": float(z["infections_ontime_median"].iloc[0]),
                             "infections_ontime_min": int(z["infections_ontime_min"].iloc[0]),
                             "infections_ontime_max": int(z["infections_ontime_max"].iloc[0])})
    sens = pd.DataFrame(sens)

    infections_all = pd.read_csv(data_dir / "ctu13_infections.csv")
    captures = pd.read_csv(data_dir / "ctu13_captures.csv")
    summary = {
        "main_export_delay_s": MAIN_DELAY_S, "window_minutes": WINDOW_S / 60, "deadline_minutes": DEADLINE_MIN,
        "illustrative_capacity_per_hour": capacity, "tie_seeds": len(TIE_SEEDS),
        "test_hours": main["test_hours"], "train_hours": main["train_hours"],
        "internal_records": int(captures["internal_records"].sum()),
        "botnet_records_relabeled_before_onset": int(captures["labeled_records_before_onset"].sum()),
        "max_record_duration_s": float(captures["max_duration_s"].max()),
        "train_windows": len(train), "train_positive_windows": int(train["pos"].sum()),
        "test_windows": len(test), "test_positive_windows": int(test["pos"].sum()),
        "test_windows_dur_mean_over_300s": int((test["dur_mean"] > 300).sum()),
        "test_families": len({FAMILY[s] for s in TEST}),
        "test_families_unseen": len({FAMILY[s] for s in TEST} - {FAMILY[s] for s in TRAIN}),
        "test_infections": int(infections_all["scenario"].isin(TEST).sum()),
        "test_infections_onset_from_readme": int((infections_all["scenario"].isin(TEST)
                                                  & infections_all["onset_source"].eq("capture README")).sum()),
        "test_distinct_botnet_sources": int(infections_all.loc[infections_all["scenario"].isin(TEST),
                                                               "botnet_source"].nunique()),
        "train_test_gap_minutes": train_test_gap_minutes(captures),
    }

    settings.to_csv(out_dir / "ctu13_settings.csv", index=False)
    seed_rows.to_csv(out_dir / "ctu13_target_thresholds_by_seed.csv", index=False)
    budget_rows.to_csv(out_dir / "ctu13_budget_thresholds.csv", index=False)
    split_rows.to_csv(out_dir / "ctu13_split_comparison.csv", index=False)
    pts.to_csv(out_dir / "ctu13_operating_points.csv", index=False)
    queue.to_csv(out_dir / "ctu13_queue_by_seed.csv", index=False)
    queue_summary.to_csv(out_dir / "ctu13_queue.csv", index=False)
    details.to_csv(out_dir / "ctu13_infection_timing.csv", index=False)
    per_capture.to_csv(out_dir / "ctu13_per_capture.csv", index=False)
    sens.to_csv(out_dir / "ctu13_export_delay_sensitivity.csv", index=False)
    pd.Series(summary).to_csv(out_dir / "ctu13_summary.csv", header=["value"], index_label="quantity")
    with pd.option_context("display.width", 250, "display.max_columns", 40):
        print(settings.round(4).to_string(index=False))
        print(queue_summary[queue_summary["capacity_per_hour"].eq(capacity)].to_string(index=False))
        print(seed_rows[["model", "seed", "setting", "test_detection", "test_alerts_per_hour"]].round(4)
              .to_string(index=False))
        print(budget_rows.round(4).to_string(index=False))
        print(split_rows.round(4).to_string(index=False))
        print(sens.round(4).to_string(index=False))
        print(pd.Series(summary))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raw", type=Path, help="directory with the 13 CTU-13 .binetflow files")
    ap.add_argument("--data", type=Path, default=HERE / "data")
    ap.add_argument("--out", type=Path, default=HERE / "results")
    args = ap.parse_args()
    if args.raw:
        build_windows(args.raw, args.data)
    run(args.data, args.out)


if __name__ == "__main__":
    main()
