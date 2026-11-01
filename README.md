# Alert review capacity and the CTU-13 replay

This repository reproduces every number and figure in the article "When Detecting More Threats Means
Handling Fewer" by Ali Al Bataineh. Repository: https://github.com/aalbata/alert-review-capacity

It contains two analyses.

1. A worked example (`review_capacity.py`, Figure 1). Settings A and B are invented operating points of an
   email detector. They are not measurements of any product, trained model, or deployment.
2. An offline replay of the public CTU-13 botnet dataset (`ctu13_experiment.py`, Figures 2 and 3).
   Detectors are trained on the six earliest captures and tested on the seven later ones, and the alerts
   are replayed through a review queue with fixed capacity. This is a reproducible experiment on recorded
   traffic under stated timing assumptions, not a deployment in an operational security team.

## Environment

Developed and tested on Windows 11 (Intel Core Ultra 7 155U, CPU only) with Python 3.12.10.
`requirements.txt` pins the direct dependencies; `requirements-lock.txt` pins the full set installed in a
fresh virtual environment. Results for the gradient-boosted trees depend on the scikit-learn version:
scikit-learn 1.9.0 changed how histogram gradient boosting computes bin edges (pull request 29641), and
1.8.0 gives slightly different tree results. scikit-learn 1.9.0 and 1.9.1 give identical results.

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
the comparison. On the machine above, the steps after the download took about 5 minutes, and the download took about 6 minutes with 32 parallel connections.

A quick check without the dataset regenerates the worked example and the figures from the shipped result
files and compares them with `SHA256SUMS`:

```
python reproduce.py --fast
```

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

Thresholds. Every threshold used for the test alerts and the queue replay is fixed on the training captures
only, with scores from leave-one-capture-out models. A threshold is either the largest score that keeps at least 90% (setting A) or 95% (setting B) of held-out botnet
windows, or the lowest score whose alert rate stays within a budget of
10, 30, 100, 300 alerts per training hour.
The final model is trained on all six training captures. The operating points and the random-versus-time
split comparison choose thresholds on the evaluated data itself and are retrospective.

Queue. Each test capture is replayed separately from an empty queue, because the captures are separate
recordings. One queue serves alerts one at a time at a fixed capacity and keeps working after the capture's
last alert until it is empty. First in, first out serves the earliest alert time first; highest score
first serves the highest detector score first. Alerts that remain tied are ordered by a random
permutation that does not depend on labels; results are reported over 20 permutation seeds.
The illustrative capacity of 60 reviews per hour assumes three analysts who each review one alert every
three minutes, the review time of the worked example; it is not derived from test results. Figure 2b
shows the full capacity range.

Outcomes. A botnet window is reviewed on time if its review is completed within
60 minutes of its alert time; the denominator is every botnet-positive test window,
detected or not. An infection is reviewed on time if a review of one of its botnet-positive alerts is
completed within 60 minutes of the documented onset; reviews of benign alerts from the same host do
not count. Detection delay runs from onset to the first botnet-positive alert, queue delay from that
alert to its review.

## Results

Test captures: 55,410 host windows, 735 botnet-positive, 34.7 hours,
29 infections on 10 distinct lab machines. Training captures:
128,083 windows, 516 botnet-positive, 98.5 hours.

Detection-target thresholds (main seed):

| Detector | Training target | False-alert rate on held-out training captures | Test detection | Test alerts per hour | Peak alerts in one hour | Precision |
|---|---|---|---|---|---|---|
| Gradient-boosted trees | 90% | 91.3% | 59.3% | 56.8 | 167 | 22.1% |
| Gradient-boosted trees | 95% | 92.8% | 59.5% | 58.5 | 167 | 21.5% |
| Logistic regression | 90% | 0.1% | 47.6% | 12.9 | 123 | 78.0% |
| Logistic regression | 95% | 63.5% | 62.4% | 751.7 | 1,063 | 1.8% |

The same thresholds across gradient-boosting seeds 0, 1, 2, 3, 4:

| Detector | Target | Seeds | Test detection | Test alerts per hour |
|---|---|---|---|---|
| Gradient-boosted trees | 90% | 5 | 59.3% to 100.0% | 56.8 to 1,594.9 |
| Gradient-boosted trees | 95% | 5 | 59.5% to 100.0% | 58.5 to 1,595.4 |
| Logistic regression | 90% | 1 | 47.6% | 12.9 |
| Logistic regression | 95% | 1 | 62.4% | 751.7 |

On-time review at 60 reviews per hour, median over 20 tie seeds (range in parentheses):

| Detector | Target | Botnet windows on time, FIFO | Same, highest score first | Infections on time, FIFO | Same, highest score first |
|---|---|---|---|---|---|
| Gradient-boosted trees | 90% | 154 (153 to 156) | 315 (315) | 27 (26 to 28) | 28 (28) |
| Gradient-boosted trees | 95% | 140 (137 to 143) | 315 (315) | 22 (20 to 25) | 28 (28) |
| Logistic regression | 90% | 201 (201 to 203) | 225 (225) | 13 (13) | 11 (11) |
| Logistic regression | 95% | 0 (0) | 228 (228) | 0 (0) | 11 (11) |

Out of 735 botnet windows and 29 infections.

Alert-budget thresholds:

| Detector | Training budget (alerts per hour) | Seeds | Test detection | Test alerts per hour |
|---|---|---|---|---|
| Gradient-boosted trees | 10 | 5 | 55.0% to 57.3% | 13.1 to 20.4 |
| Gradient-boosted trees | 30 | 5 | 55.4% to 59.0% | 14.7 to 39.0 |
| Gradient-boosted trees | 100 | 5 | 55.4% to 65.2% | 14.7 to 51.3 |
| Gradient-boosted trees | 300 | 5 | 56.1% to 69.1% | 15.8 to 107.6 |
| Logistic regression | 10 | 1 | 48.0% | 25.1 |
| Logistic regression | 30 | 1 | 48.3% | 57.8 |
| Logistic regression | 100 | 1 | 49.1% | 120.1 |
| Logistic regression | 300 | 1 | 52.0% | 376.8 |

Random versus time-ordered split, detection at a 1% false-alert rate fixed on each evaluated set
(retrospective), and average precision:

| Detector | Seeds | Random split detection | Time-ordered detection | Random split AP | Time-ordered AP |
|---|---|---|---|---|---|
| Gradient-boosted trees | 5 | 86.7% to 95.7% | 56.7% to 59.2% | 0.75 to 0.94 | 0.59 to 0.61 |
| Logistic regression | 1 | 65.9% | 48.0% | 0.62 | 0.47 |

Export-delay sensitivity, logistic regression, 60 reviews per hour (medians over tie seeds):

| Export delay (s) | Target | Policy | Test detection | Alerts per hour | Botnet windows on time | Infections on time |
|---|---|---|---|---|---|---|
| 0 | 90% | fifo | 47.6% | 12.9 | 201 of 735 | 13 of 29 |
| 0 | 90% | score | 47.6% | 12.9 | 225 of 735 | 11 of 29 |
| 0 | 95% | fifo | 62.4% | 751.7 | 0 of 735 | 0 of 29 |
| 0 | 95% | score | 62.4% | 751.7 | 228 of 735 | 11 of 29 |
| 60 | 90% | fifo | 46.6% | 12.6 | 205 of 749 | 13 of 29 |
| 60 | 90% | score | 46.6% | 12.6 | 226 of 749 | 13 of 29 |
| 60 | 95% | fifo | 54.7% | 579.2 | 0 of 749 | 0 of 29 |
| 60 | 95% | score | 54.7% | 579.2 | 231 of 749 | 13 of 29 |
| 300 | 90% | fifo | 47.6% | 12.7 | 201 of 735 | 13 of 29 |
| 300 | 90% | score | 47.6% | 12.7 | 225 of 735 | 11 of 29 |
| 300 | 95% | fifo | 62.4% | 739.3 | 0 of 735 | 0 of 29 |
| 300 | 95% | score | 62.4% | 739.3 | 228 of 735 | 11 of 29 |

## Files

`config.json` holds every setting, seed, onset, and family name. `tests/test_pipeline.py` holds regression
tests on synthetic inputs, covering record timing and alert time, onsets and pre-onset records, the infection
metric, tie order, the per-capture queue reset, and threshold ties.

Results (`results/`):
- `ctu13_settings.csv`: one row per detector (`model`) and target (`setting`, A = 90%, B = 95%), main seed:
  `threshold`; `test_detection` (share of botnet-positive test windows alerted); `test_alerts`,
  `test_alerts_per_hour`, `test_peak_alerts_in_hour` (most alerts in one hour of a capture, binned by alert
  time from the capture's start);
  `test_precision`; `test_false_alert_rate` (share of other test windows alerted); `train_loco_detection`,
  `train_loco_false_alert_rate` (the same on held-out training captures).
- `ctu13_target_thresholds_by_seed.csv`: the same for every gradient-boosting seed.
- `ctu13_budget_thresholds.csv`: thresholds from training alert budgets (`budget_per_hour`) and their
  test metrics, per detector and seed; `train_loco_alerts_per_hour` is the attained training rate.
- `ctu13_split_comparison.csv`: detection at the fixed false-alert rate and average precision, random split
  versus time-ordered split, per detector and seed.
- `ctu13_operating_points.csv`: every attainable threshold of the rule score >= threshold on the test
  captures (`alerts`, `true_alerts`, `alerts_per_hour`, `detection`), ties included.
- `ctu13_queue_by_seed.csv`: queue outcomes per detector, setting, policy (`fifo` or `score`),
  `capacity_per_hour`, and `tie_seed`: `pos_windows`, `pos_windows_alerted`, `pos_windows_ontime`, `alerts`,
  `alerts_ontime`, `infections`, `infections_detected`, `infections_ontime`, and their shares.
- `ctu13_queue.csv`: medians, minima, and maxima of those counts over tie seeds.
- `ctu13_infection_timing.csv`: per infection at 60 reviews per hour: `detected`, `on_time`,
  `detection_delay_min`, `queue_delay_min`, `time_to_review_min`, per tie seed.
- `ctu13_per_capture.csv`: per test capture: `family` (probable name from the capture README), `infections`,
  `positive_windows`, `detected`, `alerts`, `peak_alerts_in_hour`, `hours`.
- `ctu13_export_delay_sensitivity.csv`: main outcomes for export delays of 0, 60, 300 s.
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
- For gradient-boosted trees, the 90% and 95% detection targets put the threshold near zero, because many
  botnet windows in held-out training captures receive scores below 0.001; the resulting test alert volume
  changes strongly with the random seed (table above).
- Every alert is assumed to take the same review time, and capacity is constant through the day.

## License

MIT License. Copyright (c) 2026 Ali Al Bataineh. See `LICENSE`. Citation metadata: `CITATION.cff`.
