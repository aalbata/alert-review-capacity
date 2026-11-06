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

Stage 2, the default: train three detectors (logistic regression, gradient-boosted trees, and an
unsupervised isolation forest) on the six earliest captures, set each alert threshold on those captures
only, by leave-one-capture-out, either to reach a detection target (supervised detectors) or to stay
within an alert budget per training hour, apply the thresholds unchanged to the seven later captures,
and replay each test capture's alerts through a single review queue with a fixed number of reviews per
hour under four review policies (alert_replay.py). All times are seconds or minutes from the start of
the capture.
"""

import argparse
import concurrent.futures as cf
import json
import math
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

sys.path.insert(0, str(Path(__file__).resolve().parent))

from alert_replay import POLICIES, replay, threat_outcomes, tie_ranks  # noqa: E402

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
WINDOW_S = CONFIG["window_minutes"] * 60
EXPORT_DELAYS_S = CONFIG["export_delays_s"]
MAIN_DELAY_S = CONFIG["main_export_delay_s"]
DEADLINE_MIN = CONFIG["deadline_minutes"]
TRAIN = CONFIG["train_scenarios"]
TEST = CONFIG["test_scenarios"]
TARGETS = CONFIG["detection_targets"]
CAPACITY = CONFIG["illustrative_capacity_per_hour"]
CAPACITY_GRID = CONFIG["capacity_grid_per_hour"]
BUDGETS = CONFIG["alert_budgets_per_hour"]
MODEL_SEED = CONFIG["model_seed"]
MODEL_SEEDS = CONFIG["model_seed_range"]
TIE_SEEDS = CONFIG["tie_seeds"]
GRID_TIE_SEEDS = TIE_SEEDS[:CONFIG["capacity_grid_tie_seeds"]]
INTERNAL_PREFIX = CONFIG["internal_prefix"]
FAMILY = {int(k): v for k, v in CONFIG["family_from_capture_readme"].items()}
INFECTION_TIMES = {int(k): v for k, v in CONFIG["infection_times_cest"].items()}
DETECTORS = [("logreg", [MODEL_SEED]), ("gbt", MODEL_SEEDS), ("iforest", MODEL_SEEDS)]
SUPERVISED = ("logreg", "gbt")

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
    if kind == "iforest":
        return IsolationForest(n_estimators=CONFIG["isolation_forest_trees"], random_state=seed)
    return make_pipeline(StandardScaler(), LogisticRegression(max_iter=5000))


def design(df):
    x = df[FEATURES].astype(float).copy()
    for c in COUNT_COLS:
        x[c] = np.log1p(x[c])
    x["dur_mean"] = np.log1p(x["dur_mean"].clip(lower=0))
    return x.to_numpy()


def fit_score(kind, seed, x_fit, y_fit, x_score):
    """Scores where higher means more suspicious; the isolation forest ignores the labels."""
    m = model(kind, seed)
    if kind == "iforest":
        return -m.fit(x_fit).score_samples(x_score)
    return m.fit(x_fit, y_fit).predict_proba(x_score)[:, 1]


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
    """Out-of-capture scores: each training capture scored by a model fitted on the other five."""
    x, y = design(train), train["pos"].to_numpy()
    oof = np.zeros(len(train))
    for s in TRAIN:
        m = train["scenario"].eq(s).to_numpy()
        oof[m] = fit_score(kind, seed, x[~m], y[~m], x[m])
    return oof


def infection_outcomes(alerts, infections, deadline_min=DEADLINE_MIN):
    """Per infection: first review of a botnet-positive alert of that host, measured from onset.

    `alerts` has columns host, alert_min, completion_min, pos; `infections` has host, onset_min.
    Only alerts on botnet-positive windows qualify, so a review of an earlier benign alert from the
    same host never counts.
    """
    out = threat_outcomes(alerts.rename(columns={"host": "entity", "pos": "threat"}),
                          infections.rename(columns={"host": "entity"}), deadline_min)
    return out.rename(columns={"entity": "host"})


def capture_alerts(cap, flag, score):
    """Alerts of one capture, ordered by host and window, with alert time at the window end."""
    f = flag[cap.index]
    return pd.DataFrame({"host": cap["host"].to_numpy()[f],
                         "alert_min": (cap["win"].to_numpy()[f] + 1) * WINDOW_S / 60.0,
                         "score": score[cap.index][f], "pos": cap["pos"].to_numpy()[f]}).reset_index(drop=True)


def capture_index(test, infections):
    """Per test capture: window positions in `test` (in test order), alert times, labels, and infections."""
    scen, host, win, pos = (test[c].to_numpy() for c in ("scenario", "host", "win", "pos"))
    out = {}
    for s in TEST:
        idx = np.flatnonzero(scen == s)
        inf = infections[infections["scenario"].eq(s)]
        out[s] = {"idx": idx, "host": host[idx], "alert_min": (win[idx] + 1) * WINDOW_S / 60.0, "pos": pos[idx],
                  "inf_host": inf["host"].to_numpy(), "inf_onset_min": inf["onset_s"].to_numpy() / 60.0}
    return out


def infection_rows(host, pos, alert_min, done, inf_host, inf_onset_min, deadline_min=DEADLINE_MIN):
    """Array version of infection_outcomes for alerts of one capture in their original order."""
    rows = []
    for h, onset in zip(inf_host, inf_onset_min):
        m = (host == h) & (pos == 1)
        if not m.any():
            rows.append((h, False, False, np.nan, np.nan, np.nan))
            continue
        a, d = alert_min[m], done[m]
        if not (a >= onset - 1e-9).all():
            raise ValueError(f"botnet alert before onset for host {h}")
        j = int(np.argmin(d))
        rows.append((h, True, bool(d[j] - onset <= deadline_min), float(a.min() - onset), float(d[j] - a[j]),
                     float(d[j] - onset)))
    return rows


def evaluate_queue(test, infections, flag, score, capacity, policy, tie_seed, detail=False, index=None):
    """Queue outcomes summed over test captures, each replayed from an empty queue."""
    index = index if index is not None else capture_index(test, infections)
    out = {"pos_windows": 0, "pos_windows_alerted": 0, "pos_windows_ontime": 0, "alerts": 0, "reviews": 0,
           "alerts_ontime": 0, "max_wait_min": 0.0, "infections": 0, "infections_detected": 0,
           "infections_ontime": 0}
    per_inf = []
    for s in TEST:
        c = index[s]
        f = flag[c["idx"]]
        host, amin, sc, pos = c["host"][f], c["alert_min"][f], score[c["idx"]][f], c["pos"][f]
        done = (replay(amin, sc, capacity, policy, tie_ranks(len(amin), tie_seed * 1000 + s), host)
                if len(amin) else np.array([]))
        wait = done - amin
        ontime = wait <= DEADLINE_MIN
        out["pos_windows"] += int(c["pos"].sum())
        out["pos_windows_alerted"] += int(pos.sum())
        out["pos_windows_ontime"] += int((ontime & (pos == 1)).sum())
        out["alerts"] += len(amin)
        out["reviews"] += int(np.unique(done).size)
        out["alerts_ontime"] += int(ontime.sum())
        out["max_wait_min"] = max(out["max_wait_min"], float(wait.max()) if len(amin) else 0.0)
        rows = infection_rows(host, pos, amin, done, c["inf_host"], c["inf_onset_min"])
        out["infections"] += len(rows)
        out["infections_detected"] += sum(r[1] for r in rows)
        out["infections_ontime"] += sum(r[2] for r in rows)
        if detail:
            res = pd.DataFrame(rows, columns=["host", "detected", "on_time", "detection_delay_min", "queue_delay_min",
                                              "time_to_review_min"])
            res.insert(0, "scenario", s)
            per_inf.append(res)
    return (out, pd.concat(per_inf, ignore_index=True)) if detail else out


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


def detector_settings(train, test, hours, train_hours, kind, seed):
    """Thresholds fixed on out-of-capture training scores, and their effect on the test captures."""
    oof = loco_scores(train, kind, seed)
    sc = fit_score(kind, seed, design(train), train["pos"].to_numpy(), design(test))
    ytr = train["pos"].to_numpy().astype(bool)
    rules = []
    if kind in SUPERVISED:
        rules += [(f"T{round(100 * r)}", "detection target", r, threshold_for_detection(oof[ytr], r)) for r in TARGETS]
    rules += [(f"B{b}", "alert budget", b, threshold_for_budget(oof, train_hours, b)) for b in BUDGETS]
    rows = []
    for name, rule, value, thr in rules:
        rows.append({"model": kind, "seed": seed, "setting": name, "rule": rule, "rule_value": value,
                     "threshold": thr, "train_alerts_per_hour": float((oof >= thr).sum() / train_hours),
                     "train_detection": float((oof[ytr] >= thr).mean()),
                     "train_false_alert_rate": float((oof[~ytr] >= thr).mean()),
                     **test_metrics(test, hours, sc, thr)})
    return rows, oof, sc


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
    sc = fit_score(kind, seed, design(tr), tr["pos"].to_numpy(), design(te))
    return {"model": kind, "seed": seed, "false_alert_rate": far,
            "time_split_detection": detection_at_false_alert_rate(test_scores, test["pos"], far),
            "time_split_average_precision": float(average_precision_score(test["pos"], test_scores)),
            "random_split_detection": detection_at_false_alert_rate(sc, te["pos"], far),
            "random_split_average_precision": float(average_precision_score(te["pos"], sc))}


_WORKER = {}


def _worker_init(data_dir):
    _WORKER["data_dir"], _WORKER["cache"] = Path(data_dir), {}


def _delay_data(delay_s):
    """Data of one export delay, read once per process."""
    cache = _WORKER["cache"]
    if delay_s not in cache:
        d = load_delay(_WORKER["data_dir"], delay_s)
        d["index"] = capture_index(d["test"], d["infections"])
        cache[delay_s] = d
    return cache[delay_s]


def _fit_job(job):
    """One detector and seed, fitted with one thread so that scores do not depend on the machine."""
    kind, seed, delay_s, with_split = job
    d = _delay_data(delay_s)
    with threadpool_limits(limits=1):
        rows, _, sc = detector_settings(d["train"], d["test"], d["hours"], d["train_hours"], kind, seed)
        split = None
        if with_split:
            all_windows = pd.concat([d["train"], d["test"]]).reset_index(drop=True)
            split = split_comparison(all_windows, d["test"], sc, kind, seed)
    return rows, sc, split


def _queue_job(job):
    """Replays of one setting under one policy at every capacity of the grid."""
    key, delay_s, flag, score, policy, grid = job
    d = _delay_data(delay_s)
    rows = []
    for c in grid:
        for ts in (TIE_SEEDS if c == CAPACITY else GRID_TIE_SEEDS):
            r = evaluate_queue(d["test"], d["infections"], flag, score, c, policy, ts, index=d["index"])
            rows.append({**key, "policy": policy, "capacity_per_hour": c, "tie_seed": ts, **r})
    return rows


def _detail_job(job):
    key, delay_s, flag, score, policy = job
    d = _delay_data(delay_s)
    out = []
    for ts in TIE_SEEDS:
        _, res = evaluate_queue(d["test"], d["infections"], flag, score, CAPACITY, policy, ts, detail=True,
                                index=d["index"])
        for col, val in [("tie_seed", ts), ("policy", policy), ("setting", key["setting"]), ("seed", key["seed"]),
                         ("model", key["model"])]:
            res.insert(0, col, val)
        out.append(res)
    return out


class Runner:
    """One pool of worker processes for the whole run; each worker reads the derived tables itself."""

    def __init__(self, data_dir, workers):
        self.ex = None
        if workers > 1:
            self.ex = cf.ProcessPoolExecutor(workers, initializer=_worker_init, initargs=(str(data_dir),))
        else:
            _worker_init(data_dir)

    def map(self, fn, jobs):
        return list(self.ex.map(fn, jobs, chunksize=1)) if self.ex else [fn(j) for j in jobs]

    def close(self):
        if self.ex:
            self.ex.shutdown()


def load_delay(data_dir, delay_s):
    windows = pd.read_csv(data_dir / f"ctu13_windows_d{delay_s}.csv.gz")
    captures = pd.read_csv(data_dir / "ctu13_captures.csv")
    infections = pd.read_csv(data_dir / "ctu13_infections.csv")
    infections = infections[infections["scenario"].isin(TEST)].reset_index(drop=True)
    hours = (captures.set_index("scenario")["last_end_s"] + delay_s) / 3600.0
    train = windows[windows["scenario"].isin(TRAIN)].reset_index(drop=True)
    test = windows[windows["scenario"].isin(TEST)].reset_index(drop=True)
    return {"train": train, "test": test, "infections": infections, "hours": hours,
            "train_hours": float(hours.loc[TRAIN].sum()), "test_hours": float(hours.loc[TEST].sum())}


def fit_all(runner, delay_s, detectors, with_split=False):
    """Fit every detector and seed; return settings, test scores, and the split comparison rows."""
    jobs = [(kind, seed, delay_s, with_split) for kind, seeds in detectors for seed in seeds]
    settings, scores, split = [], {}, []
    for (kind, seed, _, _), (rows, sc, sp) in zip(jobs, runner.map(_fit_job, jobs)):
        settings += rows
        scores[(kind, seed)] = sc
        if sp is not None:
            split.append(sp)
    return pd.DataFrame(settings), scores, pd.DataFrame(split)


def queue_jobs(settings, scores, grid, delay_s, keys=("model", "seed", "setting")):
    jobs = []
    for row in settings.itertuples():
        sc = scores[(row.model, row.seed)]
        flag = sc >= row.threshold
        key = {k: getattr(row, k) for k in keys}
        for policy in POLICIES:
            jobs.append((key, delay_s, flag, sc, policy, grid))
    return jobs


def train_test_gap_minutes(captures):
    """Minutes between the last training-record end and the first test-record start."""
    c = captures.set_index("scenario")
    start = pd.to_datetime(c["start"])
    train_end = (start.loc[TRAIN] + pd.to_timedelta(c.loc[TRAIN, "last_end_s"], unit="s")).max()
    return float((start.loc[TEST].min() - train_end).total_seconds() / 60.0)


def summarize_queue(queue, keys):
    agg = queue.groupby(keys).agg(
        pos_windows=("pos_windows", "first"), pos_windows_alerted=("pos_windows_alerted", "first"),
        pos_windows_ontime_median=("pos_windows_ontime", "median"),
        pos_windows_ontime_min=("pos_windows_ontime", "min"), pos_windows_ontime_max=("pos_windows_ontime", "max"),
        infections=("infections", "first"), infections_detected=("infections_detected", "first"),
        infections_ontime_median=("infections_ontime", "median"),
        infections_ontime_min=("infections_ontime", "min"), infections_ontime_max=("infections_ontime", "max"),
        alerts=("alerts", "first"), reviews_median=("reviews", "median"),
        max_wait_min_median=("max_wait_min", "median"), tie_seeds=("tie_seed", "nunique")).reset_index()
    return agg


def hourly_alerts(test, flag):
    """Alerts and botnet-positive alerts per capture and hour of the capture."""
    hour = ((test["win"] + 1) * WINDOW_S) // 3600
    df = pd.DataFrame({"scenario": test["scenario"], "hour": hour, "alerts": flag.astype(int),
                       "botnet_alerts": (flag & test["pos"].eq(1).to_numpy()).astype(int)})
    return df.groupby(["scenario", "hour"]).sum().reset_index()


def run(data_dir, out_dir, workers):
    out_dir.mkdir(parents=True, exist_ok=True)
    main = load_delay(data_dir, MAIN_DELAY_S)
    train, test, hours, infections = main["train"], main["test"], main["hours"], main["infections"]
    runner = Runner(data_dir, workers)
    settings, scores, split_rows = fit_all(runner, MAIN_DELAY_S, DETECTORS, with_split=True)
    grid = sorted(set(CAPACITY_GRID) | {CAPACITY})

    rows = runner.map(_queue_job, queue_jobs(settings, scores, grid, MAIN_DELAY_S))
    queue = pd.DataFrame([r for block in rows for r in block])
    keys = ["model", "seed", "setting", "policy", "capacity_per_hour"]
    queue = queue.sort_values(keys + ["tie_seed"], kind="stable").reset_index(drop=True)
    queue_summary = summarize_queue(queue, keys)

    seed0 = settings[settings["seed"].eq(MODEL_SEED)]
    jobs = [job[:5] for job in queue_jobs(seed0, scores, [CAPACITY], MAIN_DELAY_S)]
    details = pd.concat([d for block in runner.map(_detail_job, jobs) for d in block], ignore_index=True)

    pts = []
    for kind, _ in DETECTORS:
        sc = scores[(kind, MODEL_SEED)]
        p = operating_points(sc, test["pos"].to_numpy())
        p.insert(0, "model", kind)
        p["alerts_per_hour"] = p["alerts"] / main["test_hours"]
        p["detection"] = p["true_alerts"] / int(test["pos"].sum())
        pts.append(p)
    pts = pd.concat(pts, ignore_index=True)

    per_capture, hourly = [], []
    for row in seed0.itertuples():
        flag = scores[(row.model, row.seed)] >= row.threshold
        h = hourly_alerts(test, flag)
        h.insert(0, "setting", row.setting)
        h.insert(0, "model", row.model)
        hourly.append(h)
        for s in TEST:
            m = test["scenario"].eq(s).to_numpy()
            y = test["pos"].to_numpy()[m].astype(bool)
            hs = h[h["scenario"].eq(s)]
            per_capture.append({"model": row.model, "setting": row.setting, "scenario": s, "family": FAMILY[s],
                                "infections": int(infections["scenario"].eq(s).sum()),
                                "positive_windows": int(y.sum()), "detected": int(flag[m][y].sum()),
                                "alerts": int(flag[m].sum()), "peak_alerts_in_hour": int(hs["alerts"].max()),
                                "hours": float(hours.loc[s])})
    per_capture, hourly = pd.DataFrame(per_capture), pd.concat(hourly, ignore_index=True)

    sens = []
    for d in EXPORT_DELAYS_S:
        if d == MAIN_DELAY_S:
            dsettings, dscores = seed0, scores
        else:
            dsettings, dscores, _ = fit_all(runner, d, [(kind, [MODEL_SEED]) for kind, _ in DETECTORS])
        blocks = runner.map(_queue_job, queue_jobs(dsettings, dscores, [CAPACITY], d))
        q = summarize_queue(pd.DataFrame([r for block in blocks for r in block]), keys)
        q = q.merge(dsettings[["model", "seed", "setting", "threshold", "test_detection", "test_alerts_per_hour"]],
                    on=["model", "seed", "setting"])
        q.insert(0, "export_delay_s", d)
        sens.append(q)
    sens = pd.concat(sens, ignore_index=True)
    runner.close()

    infections_all = pd.read_csv(data_dir / "ctu13_infections.csv")
    captures = pd.read_csv(data_dir / "ctu13_captures.csv")
    summary = {
        "main_export_delay_s": MAIN_DELAY_S, "window_minutes": WINDOW_S / 60, "deadline_minutes": DEADLINE_MIN,
        "illustrative_capacity_per_hour": CAPACITY, "tie_seeds": len(TIE_SEEDS),
        "capacity_grid_tie_seeds": len(GRID_TIE_SEEDS),
        "test_hours": main["test_hours"], "train_hours": main["train_hours"],
        "internal_records": int(captures["internal_records"].sum()),
        "botnet_records_relabeled_before_onset": int(captures["labeled_records_before_onset"].sum()),
        "max_record_duration_s": float(captures["max_duration_s"].max()),
        "train_windows": len(train), "train_positive_windows": int(train["pos"].sum()),
        "test_windows": len(test), "test_positive_windows": int(test["pos"].sum()),
        "test_hosts": int(test.groupby("scenario")["host"].nunique().sum()),
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
    split_rows.to_csv(out_dir / "ctu13_split_comparison.csv", index=False)
    pts.to_csv(out_dir / "ctu13_operating_points.csv", index=False)
    queue.to_csv(out_dir / "ctu13_queue_by_seed.csv", index=False)
    queue_summary.to_csv(out_dir / "ctu13_queue.csv", index=False)
    details.to_csv(out_dir / "ctu13_infection_timing.csv", index=False)
    per_capture.to_csv(out_dir / "ctu13_per_capture.csv", index=False)
    hourly.to_csv(out_dir / "ctu13_hourly_alerts.csv", index=False)
    sens.to_csv(out_dir / "ctu13_export_delay_sensitivity.csv", index=False)
    pd.Series(summary).to_csv(out_dir / "ctu13_summary.csv", header=["value"], index_label="quantity")
    with pd.option_context("display.width", 250, "display.max_columns", 40, "display.max_rows", 400):
        cols = ["model", "seed", "setting", "train_alerts_per_hour", "train_false_alert_rate", "test_detection",
                "test_alerts_per_hour", "test_peak_alerts_in_hour"]
        print(settings[cols].round(4).to_string(index=False))
        at = queue_summary[queue_summary["capacity_per_hour"].eq(CAPACITY) & queue_summary["seed"].eq(MODEL_SEED)]
        print(at.to_string(index=False))
        print(split_rows.round(4).to_string(index=False))
        print(pd.Series(summary))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raw", type=Path, help="directory with the 13 CTU-13 .binetflow files")
    ap.add_argument("--data", type=Path, default=HERE / "data")
    ap.add_argument("--out", type=Path, default=HERE / "results")
    ap.add_argument("--workers", type=int, default=max(1, min(8, (os.cpu_count() or 2) - 1)),
                    help="processes for the queue replays (results do not depend on it)")
    args = ap.parse_args()
    if args.raw:
        build_windows(args.raw, args.data)
    run(args.data, args.out, args.workers)


if __name__ == "__main__":
    main()
