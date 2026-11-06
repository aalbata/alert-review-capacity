"""Replay a time-stamped alert log through a review queue with a fixed review capacity.

Every alert has an alert time in minutes, an entity (a host, account, or mailbox), a detector score
and, for evaluation, a flag that marks alerts raised on threat activity. Every threat has an entity and
an onset time. The queue starts empty, performs one review at a time, each taking 60 / capacity
minutes, and keeps working after the last alert until it is empty.

Review policies
  fifo        each alert is reviewed on its own, earliest alert first
  score       each alert is reviewed on its own, highest score first
  fifo-host   the waiting alerts of one entity form a case that is reviewed once, earliest case first
  score-host  as fifo-host, with the case holding the highest score first

A case keeps taking new alerts of its entity until its review starts; the entity's next alert then
opens a new case. Alerts that are still tied are ordered by label-free random ranks.

A threat counts as reviewed in time when a review that covers one of its threat alerts ends within
the deadline after the threat's onset; reviews of the entity's other alerts do not count.

Command line:
  python alert_replay.py ALERTS.csv THREATS.csv --capacity 60 [--deadline 60] [--seeds 20]
ALERTS.csv columns: queue, time_min, entity, score, threat (1 for alerts raised on threat activity)
THREATS.csv columns: queue, entity, onset_min
Each value of `queue` (for example a day or a capture) is replayed from an empty queue.
"""

import argparse
import heapq

import numpy as np
import pandas as pd

POLICIES = ("fifo", "score", "fifo-host", "score-host")


def tie_ranks(n, seed):
    """Label-independent random ranks used to order alerts that are otherwise tied."""
    return np.random.default_rng(seed).permutation(n)


def replay(arrival_min, score, capacity_per_hour, policy, ranks, entity=None):
    """Completion minute of the review that covers each alert."""
    if policy not in POLICIES:
        raise ValueError(f"unknown policy {policy}")
    arr = np.asarray(arrival_min, dtype=float)
    score = np.asarray(score, dtype=float)
    ranks = np.asarray(ranks)
    service = 60.0 / capacity_per_hour
    if policy.endswith("-host"):
        if entity is None:
            raise ValueError("host policies need an entity for every alert")
        return _replay_cases(arr, score, np.asarray(entity), service, policy == "score-host", ranks)
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


def _replay_cases(arr, score, entity, service, by_score, ranks):
    """Host-grouped queue: one review covers every alert that joined the case before its review began."""
    order = np.lexsort((ranks, arr))
    done = np.full(len(arr), np.nan)
    members, first, top, version = [], [], [], []
    waiting = {}
    heap, t, i = [], 0.0, 0
    while i < len(order) or waiting:
        if not waiting:
            t = max(t, arr[order[i]])
        while i < len(order) and arr[order[i]] <= t:
            k = order[i]
            c = waiting.get(entity[k])
            if c is None:
                c = len(members)
                members.append([k])
                first.append(k)
                top.append(score[k])
                version.append(0)
                waiting[entity[k]] = c
                key = (-top[c], arr[k], ranks[k], 0, c) if by_score else (arr[k], ranks[k], 0, c)
                heapq.heappush(heap, key)
            else:
                members[c].append(k)
                if by_score and score[k] > top[c]:
                    top[c] = score[k]
                    version[c] += 1
                    j = first[c]
                    heapq.heappush(heap, (-top[c], arr[j], ranks[j], version[c], c))
            i += 1
        while True:
            key = heapq.heappop(heap)
            c = key[-1]
            if key[-2] == version[c] and entity[first[c]] in waiting and waiting[entity[first[c]]] == c:
                break
        del waiting[entity[first[c]]]
        t += service
        done[members[c]] = t
    return done


def threat_outcomes(alerts, threats, deadline_min):
    """Per threat: the first review that covers one of its threat alerts, measured from onset.

    `alerts` has columns entity, alert_min, completion_min, threat; `threats` has entity, onset_min.
    """
    rows = []
    by_entity = {e: g for e, g in alerts[alerts["threat"] == 1].groupby("entity", sort=False)}
    for th in threats.itertuples():
        q = by_entity.get(th.entity)
        if q is None:
            rows.append({"entity": th.entity, "detected": False, "on_time": False, "detection_delay_min": np.nan,
                         "queue_delay_min": np.nan, "time_to_review_min": np.nan})
            continue
        if not (q["alert_min"] >= th.onset_min - 1e-9).all():
            raise ValueError(f"threat alert before onset for entity {th.entity}")
        j = q["completion_min"].idxmin()
        review = q.at[j, "completion_min"]
        rows.append({"entity": th.entity, "detected": True,
                     "on_time": bool(review - th.onset_min <= deadline_min),
                     "detection_delay_min": float(q["alert_min"].min() - th.onset_min),
                     "queue_delay_min": float(review - q.at[j, "alert_min"]),
                     "time_to_review_min": float(review - th.onset_min)})
    return pd.DataFrame(rows, columns=["entity", "detected", "on_time", "detection_delay_min", "queue_delay_min",
                                       "time_to_review_min"])


def replay_log(alerts, threats, capacity_per_hour, policy, seed, deadline_min):
    """Replay every queue of an alert log; return totals and the per-threat outcomes."""
    totals = {"alerts": 0, "reviews": 0, "threat_alerts": 0, "threat_alerts_in_time": 0, "threats": 0,
              "threats_detected": 0, "threats_in_time": 0, "max_wait_min": 0.0}
    per_threat = []
    for n, (name, al) in enumerate(alerts.groupby("queue", sort=True)):
        al = al.reset_index(drop=True)
        done = replay(al["time_min"], al["score"], capacity_per_hour, policy, tie_ranks(len(al), seed * 1000 + n),
                      al["entity"].to_numpy())
        al = al.assign(alert_min=al["time_min"], completion_min=done)
        wait = al["completion_min"] - al["alert_min"]
        totals["alerts"] += len(al)
        totals["reviews"] += int(np.unique(done).size)
        totals["threat_alerts"] += int(al["threat"].sum())
        totals["threat_alerts_in_time"] += int(((wait <= deadline_min) & al["threat"].eq(1)).sum())
        totals["max_wait_min"] = max(totals["max_wait_min"], float(wait.max()))
        th = threats[threats["queue"] == name]
        res = threat_outcomes(al, th, deadline_min)
        res.insert(0, "queue", name)
        per_threat.append(res)
        totals["threats"] += len(res)
        totals["threats_detected"] += int(res["detected"].sum())
        totals["threats_in_time"] += int(res["on_time"].sum())
    return totals, pd.concat(per_threat, ignore_index=True) if per_threat else pd.DataFrame()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("alerts", help="CSV with queue, time_min, entity, score, threat")
    ap.add_argument("threats", help="CSV with queue, entity, onset_min")
    ap.add_argument("--capacity", type=float, nargs="+", required=True, help="reviews per hour")
    ap.add_argument("--deadline", type=float, default=60.0, help="minutes from onset")
    ap.add_argument("--seeds", type=int, default=20, help="number of random tie orders")
    args = ap.parse_args()
    alerts = pd.read_csv(args.alerts)
    threats = pd.read_csv(args.threats)
    rows = []
    for c in args.capacity:
        for policy in POLICIES:
            runs = [replay_log(alerts, threats, c, policy, s, args.deadline)[0] for s in range(args.seeds)]
            in_time = [r["threats_in_time"] for r in runs]
            rows.append({"capacity_per_hour": c, "policy": policy, "alerts": runs[0]["alerts"],
                         "reviews_median": float(np.median([r["reviews"] for r in runs])),
                         "threats": runs[0]["threats"], "threats_detected": runs[0]["threats_detected"],
                         "threats_in_time_median": float(np.median(in_time)),
                         "threats_in_time_min": min(in_time), "threats_in_time_max": max(in_time),
                         "max_wait_min_median": float(np.median([r["max_wait_min"] for r in runs]))})
    print(pd.DataFrame(rows).to_string(index=False))


if __name__ == "__main__":
    main()
