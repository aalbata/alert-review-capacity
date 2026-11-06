# Alert review capacity and the CTU-13 replay

This repository reproduces every number and figure in the article "When Detecting More Threats Means
Reviewing Fewer in Time" by Ali Al Bataineh. Repository: https://github.com/aalbata/alert-review-capacity

It contains three parts.

1. A worked example (`review_capacity.py`, Figure 1). Settings A and B are invented operating points of an
   email detector. They are not measurements of any product, trained model, or deployment.
2. An offline replay of the public CTU-13 botnet dataset (`ctu13_experiment.py`, Figures 2 to 4 and
   Table 1). Three detectors are trained on the six earliest captures and tested on the seven later ones,
   and the alerts are replayed through a review queue with fixed capacity under four review policies.
   This is a reproducible experiment on recorded traffic under stated timing assumptions, not a
   deployment in an operational security team.
3. A stand-alone replay tool (`alert_replay.py`) that reads any alert log with an alert time, an entity,
   a score, and a ground-truth flag, and reports how many threats are reviewed within a deadline.

## Environment

Developed and tested on Windows 11 (Intel Core Ultra 7 155U, CPU only) with Python 3.12.10.
`requirements.txt` pins the direct dependencies; `requirements-lock.txt` pins the full set installed in a
fresh virtual environment. Results for the gradient-boosted trees depend on the scikit-learn version:
scikit-learn 1.9.0 changed how histogram gradient boosting computes bin edges (pull request 29641), so
earlier versions give slightly different tree results.

## Reproduce

```
python -m venv .venv
.venv\Scripts\activate          (Linux or macOS: source .venv/bin/activate)
pip install -r requirements-lock.txt
python -m unittest discover -s tests
python reproduce.py --raw raw
```

`reproduce.py` runs the worked example, downloads the 13 raw CTU-13 flow files (about 2.7 GB) into `raw/`
and checks their SHA-256 sums, builds the derived host-window tables in `data/`, runs the experiment,
draws the figures, and compares every output with `SHA256SUMS`. `python checksums.py --check` repeats
the comparison. The queue replays run in parallel processes
(`ctu13_experiment.py --workers N`); the results do not depend on the number of processes.

A quick check without the dataset regenerates the worked example and the figures from the shipped result
files and compares them with `SHA256SUMS`:

```
python reproduce.py --fast
```

## Replaying your own alert log

```
python alert_replay.py alerts.csv threats.csv --capacity 30 60 120 --deadline 60 --seeds 20
```

`alerts.csv` has one row per alert with columns `queue` (an independent queue, for example a day or a
site; each starts empty), `time_min` (alert time in minutes), `entity` (the host, account, or mailbox the
alert concerns), `score` (higher is more suspicious), and `threat` (1 if the alert was raised on threat
activity, else 0). `threats.csv` has one row per threat with `queue`, `entity`, and `onset_min`. The tool
prints, for each capacity and review policy, the alerts, the reviews performed, the threats detected, and
the threats whose first review of a threat alert ended within the deadline after onset (median, minimum,
and maximum over random orders of simultaneous alerts).

## Data and terms

CTU-13 is published by the Stratosphere Laboratory at the Czech Technical University in Prague
(https://www.stratosphereips.org/datasets-ctu13). Its authors ask users to cite S. García, M. Grill,
J. Stiborek, and A. Zunino, "An empirical comparison of botnet detection methods," Computers & Security
45 (2014) 100-123, https://doi.org/10.1016/j.cose.2014.05.011. That paper analyzed unidirectional NetFlows;
this code uses the later bidirectional Argus NetFlow files with labels, from the
`detailed-bidirectional-flow-labels` folder of each capture, which the dataset page recommends instead.

The dataset page and capture notes state no license or redistribution terms, so this repository contains
neither the raw flow files nor the derived host-window tables. `download_ctu13.py` fetches the raw files
from the official server. The MIT License below covers the code only.

## Method

Timing. Each flow record is treated as available at its end time (start plus duration) plus an export delay
of 0 s in the main analysis and 60 s or 300 s in a sensitivity check.
A record's statistics cannot exist before its last packet, and the Argus configuration shipped with every
capture reports a long-lived flow at most once an hour (`ARGUS_FLOW_STATUS_INTERVAL=3600`); the actual
export time is not documented. Records are grouped by internal source host (147.32.0.0/16) and
5-minute window of availability, so a window's features use only records that became
available inside it. A window is botnet-positive if it holds a record labeled From-Botnet that starts at or
after the host's infection onset. The alert time is the end of the window.

Onset. CTU-13 labels all traffic from an infected lab machine as From-Botnet, including traffic before the
documented infection. Onset is therefore the infection time recorded in each capture's README (Central
European Summer Time, the clock of the flow records; in the test captures the first botnet record after a
documented onset follows it within 71 seconds). Scenario 48's README gives the bot start after
text repeated from scenario 42. The training scenarios 42 and 46 give no infection time; their onset is the
host's first From-Botnet record, which may include the lab machine's start-up traffic. Earlier From-Botnet
records of the host count as ordinary traffic (228 records in
all). `config.json` lists every documented onset used.

Detectors. Logistic regression and histogram gradient-boosted trees are trained on the labels; an isolation
forest with 200 trees is trained without labels and scores a window by how easily it is isolated.
Trees and isolation forests are run with model seeds 0, 1, 2, 3, 4.

Thresholds. Every threshold used for the test alerts and the queue replay is fixed on the training captures
only, with scores from leave-one-capture-out models. A detection target keeps at least
90% or 95% of held-out botnet windows (supervised detectors only); an alert
budget is the lowest score whose alert rate stays within 10, 30, 60, 120, 300
alerts per training hour. The final model is trained on all six training captures. The operating points and
the random-versus-time split comparison choose thresholds on the evaluated data itself and are
retrospective.

Queue. Each test capture is replayed separately from an empty queue, because the captures are separate
recordings. One queue performs one review at a time at a fixed capacity and keeps working after the
capture's last alert until it is empty. The four review policies are `fifo` (each alert on its own, earliest alert first), `score` (each alert on its own, highest score first), `fifo-host` (the waiting alerts of one host form one case, earliest case first), `score-host` (the waiting alerts of one host form one case, highest score in the case first).
A case takes new alerts of its host until its review starts. Alerts that remain tied are ordered by a
random permutation that does not depend on labels; results are reported over 20 permutation seeds at
60 reviews per hour and over 5 seeds at the other capacities
(10, 15, 20, 25, 30, 40, 50, 60, 80, 100, 120, 160, 200, 300, 400 per hour). The illustrative capacity of 60 reviews per hour
assumes three analysts who each review one alert every three minutes, the review time of the worked
example; it is not derived from test results.

Outcomes. An infection is reviewed in time if a review that covers one of its botnet-positive alerts ends
within 60 minutes of the documented onset; reviews of benign alerts from the same host do not count.
Detection delay runs from onset to the first botnet-positive alert, queue delay from that alert to its
review. A botnet window is reviewed in time if its review ends within 60 minutes of its alert time.

## Results

Test captures: 55,410 host windows from 2,512 hosts, 735 botnet-positive,
34.7 hours, 29 infections on 10 distinct lab machines. Training captures:
128,083 windows, 516 botnet-positive, 98.5 hours.

Thresholds fixed on the training captures (model seed 0):

| Detector | Threshold rule | Alerts per training hour | False-alert rate, training | Test detection | Test alerts per hour | Peak alerts in one hour | Precision |
|---|---|---|---|---|---|---|---|
| Logistic regression | 90% target | 6.2 | 0.11% | 47.6% | 12.9 | 123 | 78.0% |
| Logistic regression | 95% target | 827.7 | 63.51% | 62.4% | 751.7 | 1,063 | 1.8% |
| Logistic regression | 10 per hour | 10.0 | 0.40% | 48.0% | 25.1 | 145 | 40.5% |
| Logistic regression | 30 per hour | 30.0 | 1.94% | 48.3% | 57.8 | 199 | 17.7% |
| Logistic regression | 60 per hour | 60.0 | 4.26% | 48.4% | 88.1 | 244 | 11.6% |
| Logistic regression | 120 per hour | 120.0 | 8.89% | 49.3% | 138.3 | 305 | 7.5% |
| Logistic regression | 300 per hour | 300.0 | 22.78% | 52.0% | 376.8 | 604 | 2.9% |
| Gradient-boosted trees | 90% target | 1,187.6 | 91.30% | 59.3% | 56.8 | 167 | 22.1% |
| Gradient-boosted trees | 95% target | 1,207.3 | 92.82% | 59.5% | 58.5 | 167 | 21.5% |
| Gradient-boosted trees | 10 per hour | 9.9 | 0.61% | 55.0% | 14.5 | 121 | 80.3% |
| Gradient-boosted trees | 30 per hour | 16.5 | 1.12% | 55.4% | 14.7 | 121 | 80.0% |
| Gradient-boosted trees | 60 per hour | 59.7 | 4.45% | 55.4% | 14.7 | 121 | 79.8% |
| Gradient-boosted trees | 120 per hour | 117.1 | 8.88% | 55.4% | 14.7 | 121 | 79.8% |
| Gradient-boosted trees | 300 per hour | 262.4 | 19.93% | 58.2% | 30.6 | 140 | 40.3% |
| Isolation forest | 10 per hour | 10.0 | 0.66% | 35.0% | 32.0 | 162 | 23.1% |
| Isolation forest | 30 per hour | 30.0 | 1.94% | 51.3% | 74.6 | 230 | 14.5% |
| Isolation forest | 60 per hour | 60.0 | 4.26% | 54.1% | 139.4 | 327 | 8.2% |
| Isolation forest | 120 per hour | 120.0 | 8.88% | 56.9% | 255.6 | 463 | 4.7% |
| Isolation forest | 300 per hour | 300.0 | 22.78% | 70.3% | 557.0 | 901 | 2.7% |

Infections reviewed within 60 minutes of onset at 60 reviews per hour, median over 20 tie seeds
(range in parentheses), out of 29:

| Detector | Threshold rule | Infections alerted | `fifo` | `score` | `fifo-host` | `score-host` |
|---|---|---|---|---|---|---|
| Logistic regression | 90% target | 19 | 13 (13) | 11 (11) | 13 (13) | 12 (12) |
| Logistic regression | 95% target | 29 | 0 (0) | 11 (11) | 8 (6 to 11) | 12 (12) |
| Logistic regression | 10 per hour | 19 | 13 (13) | 11 (11) | 13 (13) | 12 (12) |
| Logistic regression | 30 per hour | 19 | 7 (6 to 9) | 11 (11) | 13 (13) | 12 (12) |
| Logistic regression | 60 per hour | 19 | 3 (3) | 11 (11) | 13 (13) | 12 (12) |
| Logistic regression | 120 per hour | 22 | 2 (2) | 11 (11) | 13 (13) | 12 (12) |
| Logistic regression | 300 per hour | 27 | 0 (0 to 1) | 11 (11) | 3.5 (2 to 5) | 12 (12) |
| Gradient-boosted trees | 90% target | 28 | 27 (26 to 28) | 28 (28) | 28 (28) | 28 (28) |
| Gradient-boosted trees | 95% target | 28 | 22 (20 to 25) | 28 (28) | 28 (28) | 28 (28) |
| Gradient-boosted trees | 10 per hour | 26 | 24 (24) | 24 (24) | 24 (24) | 24 (24) |
| Gradient-boosted trees | 30 per hour | 26 | 25 (25) | 25 (25) | 25 (25) | 25 (25) |
| Gradient-boosted trees | 60 per hour | 26 | 25 (25) | 25 (25) | 25 (25) | 25 (25) |
| Gradient-boosted trees | 120 per hour | 26 | 25 (25) | 25 (25) | 25 (25) | 25 (25) |
| Gradient-boosted trees | 300 per hour | 28 | 28 (28) | 28 (28) | 28 (28) | 28 (28) |
| Isolation forest | 10 per hour | 24 | 14 (14) | 12 (12) | 14 (14) | 12 (12) |
| Isolation forest | 30 per hour | 27 | 7 (7) | 15 (15) | 17 (17) | 15 (15) |
| Isolation forest | 60 per hour | 27 | 6 (6) | 15 (15) | 17 (17) | 15 (15) |
| Isolation forest | 120 per hour | 28 | 2.5 (2 to 4) | 15 (15) | 7 (7 to 8) | 16 (16) |
| Isolation forest | 300 per hour | 29 | 0 (0 to 1) | 15 (15) | 9 (9 to 11) | 16 (16) |

The same thresholds across model seeds:

| Detector | Threshold rule | Seeds | Alerts per training hour | Test detection | Test alerts per hour |
|---|---|---|---|---|---|
| Gradient-boosted trees | 90% target | 5 | 992.5 to 1,187.6 | 59.3% to 100.0% | 56.8 to 1,594.9 |
| Gradient-boosted trees | 95% target | 5 | 992.5 to 1,235.2 | 59.5% to 100.0% | 58.5 to 1,595.4 |
| Gradient-boosted trees | 10 per hour | 5 | 9.9 to 10.0 | 55.0% to 57.3% | 13.1 to 20.4 |
| Gradient-boosted trees | 30 per hour | 5 | 16.5 to 30.0 | 55.4% to 59.0% | 14.7 to 39.0 |
| Gradient-boosted trees | 60 per hour | 5 | 19.5 to 60.0 | 55.4% to 65.2% | 14.7 to 50.4 |
| Gradient-boosted trees | 120 per hour | 5 | 82.6 to 119.8 | 55.4% to 65.2% | 14.7 to 60.7 |
| Gradient-boosted trees | 300 per hour | 5 | 262.4 to 299.8 | 56.1% to 69.1% | 15.8 to 107.6 |
| Isolation forest | 10 per hour | 5 | 10.0 | 23.3% to 35.6% | 31.7 to 35.1 |
| Isolation forest | 30 per hour | 5 | 29.9 to 30.0 | 51.0% to 51.8% | 64.4 to 78.6 |
| Isolation forest | 60 per hour | 5 | 57.1 to 60.0 | 53.9% to 54.8% | 119.5 to 139.4 |
| Isolation forest | 120 per hour | 5 | 120.0 | 56.2% to 59.6% | 220.3 to 255.6 |
| Isolation forest | 300 per hour | 5 | 300.0 | 68.2% to 89.4% | 535.0 to 575.5 |

Random versus time-ordered split, detection at a 1% false-alert rate fixed on each evaluated set
(retrospective), and average precision:

| Detector | Seeds | Random split detection | Time-ordered detection | Random split AP | Time-ordered AP |
|---|---|---|---|---|---|
| Logistic regression | 1 | 65.9% | 48.0% | 0.62 | 0.47 |
| Gradient-boosted trees | 5 | 86.7% to 95.7% | 56.7% to 59.2% | 0.75 to 0.94 | 0.59 to 0.61 |
| Isolation forest | 5 | 23.7% to 35.9% | 3.3% to 23.4% | 0.13 to 0.19 | 0.10 to 0.13 |

Export-delay sensitivity at 60 reviews per hour, model seed 0: infections reviewed in time (median over tie
seeds) under `fifo` / `score` / `fifo-host` / `score-host`:

| Detector | Threshold rule | 0 s | 60 s | 300 s |
|---|---|---|---|---|
| Logistic regression | 90% target | 13 / 11 / 13 / 12 | 13 / 13 / 13 / 13 | 13 / 11 / 13 / 11 |
| Logistic regression | 95% target | 0 / 11 / 8 / 12 | 0 / 13 / 10 / 13 | 0 / 11 / 8 / 11 |
| Logistic regression | 10 per hour | 13 / 11 / 13 / 12 | 13 / 13 / 13 / 13 | 13 / 11 / 13 / 11 |
| Logistic regression | 30 per hour | 7 / 11 / 13 / 12 | 11 / 13 / 13 / 13 | 6 / 11 / 13 / 11 |
| Logistic regression | 60 per hour | 3 / 11 / 13 / 12 | 2 / 13 / 13 / 13 | 2 / 11 / 13 / 11 |
| Logistic regression | 120 per hour | 2 / 11 / 13 / 12 | 3 / 13 / 14 / 13 | 2 / 11 / 13 / 11 |
| Logistic regression | 300 per hour | 0 / 11 / 3.5 / 12 | 0 / 13 / 3 / 13 | 0 / 11 / 2 / 11 |
| Gradient-boosted trees | 90% target | 27 / 28 / 28 / 28 | 0 / 28 / 1 / 28 | 26 / 28 / 28 / 28 |
| Gradient-boosted trees | 95% target | 22 / 28 / 28 / 28 | 0 / 28 / 1 / 28 | 20 / 28 / 28 / 28 |
| Gradient-boosted trees | 10 per hour | 24 / 24 / 24 / 24 | 26 / 26 / 26 / 26 | 24 / 24 / 24 / 24 |
| Gradient-boosted trees | 30 per hour | 25 / 25 / 25 / 25 | 27 / 27 / 27 / 27 | 25 / 25 / 25 / 25 |
| Gradient-boosted trees | 60 per hour | 25 / 25 / 25 / 25 | 27 / 27 / 27 / 27 | 25 / 25 / 25 / 25 |
| Gradient-boosted trees | 120 per hour | 25 / 25 / 25 / 25 | 27 / 27 / 27 / 27 | 25 / 25 / 25 / 25 |
| Gradient-boosted trees | 300 per hour | 28 / 28 / 28 / 28 | 0 / 28 / 1 / 28 | 28 / 28 / 28 / 28 |
| Isolation forest | 10 per hour | 14 / 12 / 14 / 12 | 15 / 13 / 15 / 13 | 14 / 12 / 14 / 12 |
| Isolation forest | 30 per hour | 7 / 15 / 17 / 15 | 7 / 15 / 17 / 15 | 7 / 15 / 17 / 15 |
| Isolation forest | 60 per hour | 6 / 15 / 17 / 15 | 6 / 15 / 17 / 15 | 6 / 15 / 17 / 15 |
| Isolation forest | 120 per hour | 2.5 / 15 / 7 / 16 | 2 / 15 / 6 / 15 | 2 / 15 / 7 / 15 |
| Isolation forest | 300 per hour | 0 / 15 / 9 / 16 | 0 / 15 / 10 / 15 | 0 / 15 / 9 / 15 |

## Files

`config.json` holds every setting, seed, onset, and family name. `tests/test_pipeline.py` holds regression
tests on synthetic inputs, covering record timing and alert time, onsets and pre-onset records, the infection
metric, tie order, the per-capture queue reset, host grouping, and threshold ties.

Results (`results/`):
- `ctu13_settings.csv`: one row per detector (`model`), `seed`, and threshold (`setting`: `T90`, `T95` for
  detection targets, `B10` to `B300` for alert budgets; `rule`, `rule_value`): `threshold`;
  `train_alerts_per_hour`, `train_detection`, `train_false_alert_rate` (on held-out training captures);
  `test_detection` (share of botnet-positive test windows alerted); `test_alerts`, `test_alerts_per_hour`,
  `test_peak_alerts_in_hour` (most alerts in one hour of a capture, binned by alert time from the capture's
  start); `test_precision`; `test_false_alert_rate` (share of other test windows alerted).
- `ctu13_queue_by_seed.csv`: queue outcomes per detector, seed, setting, `policy`, `capacity_per_hour`, and
  `tie_seed`: `pos_windows`, `pos_windows_alerted`, `pos_windows_ontime`, `alerts`, `reviews` (cases
  reviewed), `alerts_ontime`, `max_wait_min` (longest wait of any alert), `infections`,
  `infections_detected`, `infections_ontime`.
- `ctu13_queue.csv`: medians, minima, and maxima of those counts over tie seeds.
- `ctu13_infection_timing.csv`: per infection at 60 reviews per hour, model seed 0: `detected`, `on_time`,
  `detection_delay_min`, `queue_delay_min`, `time_to_review_min`, per policy and tie seed.
- `ctu13_per_capture.csv`: per test capture and setting, model seed 0: `family` (probable name from the
  capture README), `infections`, `positive_windows`, `detected`, `alerts`, `peak_alerts_in_hour`, `hours`.
- `ctu13_hourly_alerts.csv`: alerts and botnet-positive alerts per test capture and hour, model seed 0.
- `ctu13_split_comparison.csv`: detection at the fixed false-alert rate and average precision, random split
  versus time-ordered split, per detector and seed.
- `ctu13_operating_points.csv`: every attainable threshold of the rule score >= threshold on the test
  captures (`alerts`, `true_alerts`, `alerts_per_hour`, `detection`), ties included, model seed 0.
- `ctu13_export_delay_sensitivity.csv`: queue outcomes at 60 reviews per hour for export delays of
  0, 60, 300 s, model seed 0.
- `ctu13_summary.csv`: dataset sizes and settings.

Worked example: `calculations.csv` (`quantity`, `value`, `unit`, `note`) and `backlog.csv` (`day`,
`backlog_A`, `backlog_B`).

Derived data (`data/`, generated, not distributed): `ctu13_windows_d0.csv.gz`, `_d60`, `_d300`, one row per
host and window (`scenario`, `host` as a per-capture identifier, `win`, the 18 features, `pos`);
`ctu13_infections.csv` (onset in seconds from capture start and its source); `ctu13_captures.csv`.

`SHA256SUMS` lists the expected checksum of every output.

## Caveats

- Most CTU-13 traffic carries a background label, which the dataset authors did not verify as benign, so
  some apparent false alarms may be unlabeled malicious activity.
- The training scenarios 42 and 46 document no infection time, so a few start-up records of those lab
  machines may carry botnet labels in training. Scenario 42's shipped argus.conf names a unidirectional
  flow type, although its flow file is bidirectional.
- Every review is assumed to take the same time, whether it covers one alert or a host's grouped alerts,
  and capacity is constant through the day. A review means that an analyst looked at an alert, not that
  the threat was confirmed or contained.

## License

MIT License. Copyright (c) 2026 Ali Al Bataineh. See `LICENSE`. Citation metadata: `CITATION.cff`.
