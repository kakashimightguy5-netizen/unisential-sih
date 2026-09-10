# EXP-0018 — residual-smoothness test for missed CMRI — HYPOTHESIS NOT SUPPORTED

Diagnostic-then-build, measurement only. `ml/iforest_detector.run_detector` is NOT
modified; `app.py` and all protected experiment / Layer A files are unchanged.
New files only. Pre-registration and full method: `EXPERIMENT_LOG.md` (EXP-0018);
decision record: `DECISION_LOG.md` (EXP-0018).

## Hypothesis (external research — tested, not assumed)

A signal forged to mimic a real sensor is often *less* noisy than the genuine
process. If so, smooth CMRI response-value injection that stays inside the EXP-0016
pressure bounds should still show **suppressed one-step prediction residuals**
versus TRAIN-normal. Tested two-sided (low residual energy = over-smooth forgery;
high = noisy / unstable), each side calibrated against the TRAIN-normal residual
energy distribution.

## What was built

- AR(1) (lag-1 Yule–Walker) predictor over the **global chronological sequence of
  0x03 read-response pressure values**, fitted on TRAIN-normal only.
  `mu = 8.2792`, `phi = 0.99031`, residual `sigma = 0.8546`.
  (Cadence is 1–2 pressure samples per 5 s window, so a within-window series does
  not exist; the rolling window spans multiple windows. User-approved adaptation.)
- Per 5 s window: `E = mean(standardised residual²)` over the `K = 15` samples
  ending at the window's last 0x03 response (causal, ≈ 55 s of context).
- Two-sided rule: fire if `E < low_thr` (TRAIN-normal 0.5% quantile = `0.0002`) OR
  `E > high_thr` (99.5% quantile = `24.8143`). Calibration median `0.0077`,
  n = 9,995 — the distribution is extremely right-skewed, so the two thresholds
  are separate empirical quantiles, not a symmetric band.

## Evaluation cohort

CMRI-labelled TEST windows the **EXP-0017 combined detector does not already flag**
(`comb_pred == 0`). Already-caught CMRI windows earn no credit. 544 previously-missed
pure-CMRI windows (all with a defined rolling energy).

## Identity gates — passed

`exp0017_operational.load_result` re-verified every tracked source sha256, the
envelope checksum, the manifest identity and the VALIDATED status.
`comb_pred == protocol_pred | pressure_pred | if_pred` element-wise; whole-TEST
confusion `(4767, 40, 2166, 2374)`. `run_detector` not called. No drift.

## Result — the hypothesis fails, and the signal runs the other way

| Threshold-independent signal test | value |
|---|---|
| Mann–Whitney U (missed pure-CMRI vs pure-Normal energy) | 1,905,977 |
| p-value (two-sided) | 9.35 × 10⁻⁶⁹ |
| median energy — missed pure-CMRI | **9.749** |
| median energy — pure-Normal TEST | 0.0081 |
| median energy — TRAIN-normal calibration | 0.0077 |
| missed-CMRI energy *lower* than Normal (hypothesis direction) | **False** |

The difference is significant but **in the opposite direction**: the missed CMRI
windows that carry a pressure signal are *noisier* than normal, not smoother.

| New detections on 544 previously-missed pure-CMRI | count | new recall |
|---|---:|---:|
| two-sided rule | 257 | 47.24% |
| **low-energy / over-smooth variant only** | **14** | **2.57%** |
| high-energy variant only | 243 | 44.67% |

The hypothesised mechanism (over-smoothness) accounts for 14 windows — noise.

## Why it is unusable regardless of the cohort result

| Bar | Pre-registered | EXP-0018 two-sided rule |
|---|---|---|
| new pure-Normal FP rate | ≤ 0.30% | **11.86%** (570 / 4,807) |
| combined precision (comb OR residual) | ≥ 97.0% | **82.99%** |

Whole 9,347-window TEST block, delta (TN, FP, FN, TP) if OR-ed in:
`(-563, +563, -568, +568)`.

**Diagnostic (no method change):** not a sampling-gap artifact — high-energy Normal
windows have median max bucket-gap 1. Genuine normal egress pressure has legitimate
large step changes; with `sigma = 0.85` every real move is a large standardised
residual, so ~11% of Normal windows contain a high-energy rolling segment. The
AR(1)-residual-energy statistic does not separate normal from attack here and does
not transfer TRAIN → TEST at a usable quantile.

## Verdict

Pre-registered decision rule → **WEAK / HYPOTHESIS NOT SUPPORTED**.

EXP-0018 is closed as a recorded negative result. Nothing is wired into
`run_detector()`. The ~40% of CMRI that EXP-0017 misses is not recovered by a
residual-smoothness test on this dataset.

## Tests

Full suite **147 → 156 passed, 0 skipped, 0 failed** (+9 EXP-0018 tests: 8 fast
synthetic units, 1 slow saved-result replay). No raw data read in pytest.

## Limitations

- Pressure is the ARFF-aligned value, not a live 0x03 byte decode; register
  map/scale undocumented.
- AR(1) coefficient, σ and energy thresholds are empirical TRAIN-normal statistics,
  not a physical process model.
- 1–2 pressure samples per 5 s window: a window's verdict reflects ≈ 55 s of
  surrounding telemetry; a TEST window's causal context may include
  VALIDATION/guard samples.
- One testbed; egress-only. Judged only on CMRI windows EXP-0017 already misses.
