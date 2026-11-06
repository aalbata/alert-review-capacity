"""Regression tests on small synthetic inputs; no dataset download is needed."""

import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import alert_replay as ar  # noqa: E402
import ctu13_experiment as ce  # noqa: E402
import review_capacity as rc  # noqa: E402


def flows(rows):
    """Synthetic internal flow records: (src, start_s, dur_s, label)."""
    df = pd.DataFrame(rows, columns=["SrcAddr", "t_start", "Dur", "Label"])
    df["t_end"] = df["t_start"] + df["Dur"]
    df["DstAddr"] = "1.1.1.1"
    df["Dport"] = "80"
    df["Sport"] = "1234"
    df["Proto"] = "tcp"
    df["State"] = "SA_SA"
    df["SrcBytes"] = 100
    df["TotBytes"] = 200
    df["TotPkts"] = 4
    return df


def any_host_alert_ontime(alerts, first_pos_window_end_min, deadline=60.0):
    """Counts an infection as on time if any alert of the host, benign or not, is reviewed by the deadline."""
    if len(alerts) == 0:
        return False
    return bool(alerts["completion_min"].min() - first_pos_window_end_min <= deadline)


class WindowAssignment(unittest.TestCase):
    def test_record_joins_window_of_its_end_time(self):
        df = flows([("147.32.0.1", 10.0, 420.0, "flow=Background"),   # ends at 430 s, window 1
                    ("147.32.0.1", 20.0, 5.0, "flow=Background")])    # ends at 25 s, window 0
        w = ce.aggregate_windows(df, ce.flow_flags(df), delay_s=0)
        self.assertEqual(w.set_index("win")["n_flows"].to_dict(), {0: 1, 1: 1})
        self.assertAlmostEqual(float(w.set_index("win").loc[0, "dur_mean"]), 5.0)

    def test_export_delay_moves_records_later(self):
        df = flows([("147.32.0.1", 0.0, 250.0, "flow=From-Botnet-V1")])
        self.assertEqual(int(ce.aggregate_windows(df, ce.flow_flags(df), 0)["win"].iloc[0]), 0)
        self.assertEqual(int(ce.aggregate_windows(df, ce.flow_flags(df), 60)["win"].iloc[0]), 1)

    def test_no_statistics_before_record_end(self):
        df = flows([("147.32.0.1", 0.0, 3599.0, "flow=From-Botnet-V1")])
        w = ce.aggregate_windows(df, ce.flow_flags(df), 0)
        self.assertEqual(len(w), 1)
        self.assertEqual(int(w["win"].iloc[0]), 11)

    def test_alert_time_is_window_end(self):
        cap = pd.DataFrame({"host": ["h0", "h1"], "win": [0, 3], "pos": [1, 0]})
        al = ce.capture_alerts(cap, np.array([True, True]), np.array([0.9, 0.8]))
        self.assertEqual(list(al["alert_min"]), [5.0, 20.0])


class Onsets(unittest.TestCase):
    def test_records_before_onset_are_ordinary_traffic(self):
        df = flows([("147.32.0.1", 10.0, 1.0, "flow=From-Botnet-V1"),
                     ("147.32.0.1", 400.0, 1.0, "flow=From-Botnet-V1"),
                     ("147.32.0.2", 50.0, 1.0, "flow=Background")])
        flags = ce.flow_flags(df, onset_s={"147.32.0.1": 300.0})
        self.assertEqual(list(flags["pos"]), [False, True, False])

    def test_documented_onset_is_used_and_fallback_otherwise(self):
        df = flows([("147.32.84.165", 30.0, 1.0, "flow=From-Botnet-V1"),
                    ("147.32.84.191", 90.0, 1.0, "flow=From-Botnet-V1")])
        t0 = pd.Timestamp("2011-08-19 10:40:00")
        documented = ce.INFECTION_TIMES.get(53, {})
        onset, source = ce.infection_onsets(df, 53, t0)
        self.assertEqual(source["147.32.84.165"], "capture README")
        self.assertAlmostEqual(onset["147.32.84.165"],
                               (pd.Timestamp(documented["147.32.84.165"]) - t0).total_seconds())
        onset, source = ce.infection_onsets(df, 42, t0)
        self.assertEqual(source["147.32.84.191"], "first From-Botnet record")
        self.assertAlmostEqual(onset["147.32.84.191"], 90.0)


class InfectionMetric(unittest.TestCase):
    def setUp(self):
        # Host h0: a benign alert at minute 5 reviewed at minute 6, onset at minute 20,
        # first positive alert at minute 30 reviewed at minute 200 (late).
        self.alerts = pd.DataFrame({"host": ["h0", "h0"], "alert_min": [5.0, 30.0], "pos": [0, 1],
                                    "completion_min": [6.0, 200.0]})
        self.infections = pd.DataFrame({"host": ["h0"], "onset_min": [20.0]})

    def test_any_alert_rule_would_count_a_benign_review(self):
        self.assertTrue(any_host_alert_ontime(self.alerts, first_pos_window_end_min=25.0))

    def test_infection_metric_requires_a_botnet_alert(self):
        out = ce.infection_outcomes(self.alerts, self.infections)
        self.assertFalse(bool(out["on_time"].iloc[0]))
        self.assertAlmostEqual(float(out["detection_delay_min"].iloc[0]), 10.0)
        self.assertAlmostEqual(float(out["queue_delay_min"].iloc[0]), 170.0)

    def test_infection_metric_counts_timely_botnet_review(self):
        a = self.alerts.copy()
        a.loc[1, "completion_min"] = 70.0
        out = ce.infection_outcomes(a, self.infections)
        self.assertTrue(bool(out["on_time"].iloc[0]))

    def test_array_and_table_versions_agree(self):
        rng = np.random.default_rng(2)
        n = 400
        al = pd.DataFrame({"host": rng.choice(["h0", "h1", "h2", "h3"], n), "alert_min": np.sort(rng.random(n) * 900),
                           "pos": rng.integers(0, 2, n), "completion_min": 0.0})
        al["completion_min"] = al["alert_min"] + rng.random(n) * 120
        inf = pd.DataFrame({"host": ["h0", "h2", "h9"], "onset_min": [0.0, 0.0, 0.0]})
        table = ce.infection_outcomes(al, inf)
        rows = ce.infection_rows(al["host"].to_numpy(), al["pos"].to_numpy(), al["alert_min"].to_numpy(),
                                 al["completion_min"].to_numpy(), inf["host"].to_numpy(), inf["onset_min"].to_numpy())
        arr = pd.DataFrame(rows, columns=table.columns)
        pd.testing.assert_frame_equal(table, arr, check_dtype=False)


class QueueReplay(unittest.TestCase):
    def test_service_times(self):
        done = ce.replay(np.array([0.0, 0.0, 10.0]), np.array([0.1, 0.9, 0.5]), 60, "fifo", np.array([0, 1, 2]))
        self.assertEqual(list(done), [1.0, 2.0, 11.0])

    def test_score_policy_serves_highest_score_first(self):
        done = ce.replay(np.array([0.0, 0.0]), np.array([0.1, 0.9]), 60, "score", np.array([0, 1]))
        self.assertEqual(list(done), [2.0, 1.0])

    def test_tie_order_is_a_label_free_permutation(self):
        cap = pd.DataFrame({"host": [f"h{i}" for i in range(40)], "win": np.repeat([0, 1], 20)})
        score = np.full(40, 0.5)
        flag = np.ones(40, dtype=bool)
        done = []
        for labels in (np.zeros(40, dtype=int), np.random.default_rng(1).integers(0, 2, 40)):
            al = ce.capture_alerts(cap.assign(pos=labels), flag, score)
            done.append(ce.replay(al["alert_min"].to_numpy(), al["score"].to_numpy(), 30, "fifo",
                                  ce.tie_ranks(len(al), seed=3)))
        self.assertTrue(np.array_equal(done[0], done[1]))

    def test_tie_order_changes_with_seed(self):
        arrival = np.zeros(30)
        a = ce.replay(arrival, np.zeros(30), 30, "fifo", ce.tie_ranks(30, seed=1))
        b = ce.replay(arrival, np.zeros(30), 30, "fifo", ce.tie_ranks(30, seed=2))
        self.assertFalse(np.array_equal(a, b))
        self.assertEqual(sorted(a), sorted(b))

    def test_queue_keeps_working_after_last_arrival(self):
        done = ce.replay(np.zeros(3), np.zeros(3), 6, "fifo", np.arange(3))
        self.assertEqual(sorted(done), [10.0, 20.0, 30.0])

    def test_each_capture_starts_with_an_empty_queue(self):
        # Two test captures with the same ten alerts at minute 5; a shared queue would delay the second.
        s1, s2 = ce.TEST[0], ce.TEST[1]
        test = pd.DataFrame({"scenario": [s1] * 10 + [s2] * 10, "host": [f"h{i}" for i in range(20)],
                             "win": 0, "pos": 1})
        infections = pd.DataFrame({"scenario": [s1, s2], "host": ["h0", "h10"], "onset_s": [300.0, 300.0]})
        out = ce.evaluate_queue(test, infections, np.ones(20, dtype=bool), np.full(20, 0.5), 10, "fifo", 0)
        # At 10 reviews an hour the tenth alert of a capture completes 60 minutes after minute 5.
        self.assertEqual(out["pos_windows_ontime"], 20)
        self.assertEqual(out["infections_ontime"], 2)


class HostGrouping(unittest.TestCase):
    def test_waiting_alerts_of_a_host_share_one_review(self):
        arrival = np.array([0.0, 0.0, 0.5])
        hosts = np.array(["h1", "h0", "h0"])
        done = ar.replay(arrival, np.array([0.5, 0.4, 0.9]), 60, "fifo-host", np.arange(3), hosts)
        self.assertEqual(list(done), [1.0, 2.0, 2.0])

    def test_alert_after_review_start_opens_a_new_case(self):
        done = ar.replay(np.array([0.0, 0.5]), np.zeros(2), 60, "fifo-host", np.arange(2), np.array(["h0", "h0"]))
        self.assertEqual(list(done), [1.0, 2.0])

    def test_case_priority_rises_with_its_highest_score(self):
        arrival = np.array([0.0, 0.0, 0.0, 0.5])
        hosts = np.array(["h0", "h1", "h2", "h0"])
        done = ar.replay(arrival, np.array([0.2, 0.5, 0.3, 0.9]), 60, "score-host", np.arange(4), hosts)
        self.assertEqual(list(done), [2.0, 1.0, 3.0, 2.0])

    def test_distinct_hosts_match_the_per_alert_queue(self):
        rng = np.random.default_rng(4)
        arrival = np.sort(rng.integers(0, 30, 50)).astype(float)
        score = rng.random(50)
        hosts = np.array([f"h{i}" for i in range(50)])
        ranks = ar.tie_ranks(50, 7)
        for policy in ("fifo", "score"):
            self.assertTrue(np.array_equal(ar.replay(arrival, score, 20, policy, ranks),
                                           ar.replay(arrival, score, 20, f"{policy}-host", ranks, hosts)))

    def test_grouping_never_adds_reviews(self):
        rng = np.random.default_rng(5)
        arrival = np.sort(rng.integers(0, 120, 300)).astype(float)
        score = rng.random(300)
        hosts = rng.integers(0, 12, 300)
        done = ar.replay(arrival, score, 30, "score-host", ar.tie_ranks(300, 1), hosts)
        self.assertLessEqual(np.unique(done).size, 300)
        self.assertTrue((done >= arrival).all())

    def test_replay_log_counts_threats_in_time(self):
        alerts = pd.DataFrame({"queue": ["d1"] * 3, "time_min": [0.0, 0.0, 10.0], "entity": ["a", "b", "a"],
                               "score": [0.1, 0.2, 0.9], "threat": [0, 0, 1]})
        threats = pd.DataFrame({"queue": ["d1"], "entity": ["a"], "onset_min": [5.0]})
        totals, per = ar.replay_log(alerts, threats, 60, "fifo", 0, deadline_min=60)
        self.assertEqual(totals["reviews"], 3)
        self.assertEqual(totals["threats_in_time"], 1)
        self.assertAlmostEqual(float(per["time_to_review_min"].iloc[0]), 6.0)


class Thresholds(unittest.TestCase):
    def test_operating_points_keep_ties_together(self):
        p = ce.operating_points(np.array([0.9, 0.5, 0.5, 0.5, 0.1]), np.array([1, 0, 1, 0, 1]))
        self.assertEqual(list(p["alerts"]), [1, 4, 5])
        self.assertEqual(list(p["true_alerts"]), [1, 2, 3])
        self.assertTrue(p["threshold"].is_unique)

    def test_detection_threshold_meets_target(self):
        pos = np.array([0.9, 0.8, 0.7, 0.2, 0.2])
        t = ce.threshold_for_detection(pos, 0.9)
        self.assertGreaterEqual((pos >= t).mean(), 0.9)
        self.assertEqual(t, 0.2)
        self.assertEqual(ce.threshold_for_detection(pos, 0.6), 0.7)

    def test_detection_at_false_alert_rate_respects_ties(self):
        scores = np.array([0.9, 0.8, 0.5, 0.5, 0.5, 0.1])
        labels = np.array([1, 0, 1, 0, 0, 1])
        # Negatives: 0.8, 0.5, 0.5 -> including the 0.5 tie would put the false-alert rate at 3/3.
        self.assertAlmostEqual(ce.detection_at_false_alert_rate(scores, labels, 0.34), 1 / 3)
        self.assertAlmostEqual(ce.detection_at_false_alert_rate(scores, labels, 1.0), 1.0)
        self.assertAlmostEqual(ce.detection_at_false_alert_rate(scores, labels, 0.0), 1 / 3)

    def test_budget_threshold_never_exceeds_budget(self):
        scores = np.array([0.9, 0.5, 0.5, 0.5, 0.1])
        self.assertEqual(ce.threshold_for_budget(scores, hours=1.0, budget_per_hour=3), 0.9)
        self.assertEqual(ce.threshold_for_budget(scores, hours=1.0, budget_per_hour=4), 0.5)
        self.assertEqual(ce.threshold_for_budget(scores, hours=1.0, budget_per_hour=0.5), float("inf"))


class WorkedExample(unittest.TestCase):
    def test_alert_counts_and_capacity(self):
        tp_a, fp_a = rc.expected_alerts("A")
        tp_b, fp_b = rc.expected_alerts("B")
        self.assertAlmostEqual(tp_a + fp_a, 999.9)
        self.assertAlmostEqual(tp_b + fp_b, 1949.0)
        self.assertAlmostEqual(rc.capacity_alerts(3.0), 1200.0)
        self.assertAlmostEqual(rc.backlog("B")[-1], 5243.0)
        self.assertAlmostEqual(float(rc.threats_examined("B", 3.0)), 1200 * 950 / 1949)


if __name__ == "__main__":
    unittest.main()
