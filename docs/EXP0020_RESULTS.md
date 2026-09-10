# EXP-0020 — gated rate-of-change rule (in-bounds predecessor)

**Pre-registered primary verdict: `WEAK / HYPOTHESIS NOT SUPPORTED`.** The
in-bounds-predecessor gate confirmed EXP-0019's root-cause diagnosis (boundary-
artifact FP 35 → 8, precision floor now cleared) but also removed most of the
detections; a strict-cutoff variant of the same rule reaches **ACCEPTABLE**.
Measurement only; `run_detector`, `app.py` and all protected / EXP-0018 / EXP-0019
files unchanged. New files only. Pre-registration: `EXPERIMENT_LOG.md` (EXP-0020);
decision record: `DECISION_LOG.md` (EXP-0020).

## The one change from EXP-0019

A consecutive `0x03` sample pair `(i-1, i)` is scored only if `Δt > 0` **and the
earlier sample is a plausible baseline**:

> `0.482759 ≤ p_{i-1} ≤ 38.7471`  — the EXP-0016 frozen TRAIN-normal pressure
> bounds, read from the checksum-verified EXP-0017 artifact.

The later sample `p_i` is deliberately unconstrained (the hypothesis is that a
forgery lands inside the bounds but moves there too fast). This directly targets
EXP-0019's finding that 35 of its 45 pure-Normal false positives were the rule
crediting a Normal window for pressure *returning to normal* after an anomaly.

Everything else — feature, TRAIN-normal-percentile calibration, evaluation cohort,
decision rule, identity gates — is identical to EXP-0019 and reused from its
(frozen, unmodified) module.

## Identity gates — passed

EXP-0017 reproduced via `load_result` (all source sha256 + envelope checksum +
manifest + VALIDATED). `comb_pred == protocol_pred | pressure_pred | if_pred`
element-wise; whole-TEST `(4767, 40, 2166, 2374)`. `run_detector` not called.

## The gate is a no-op on TRAIN-normal

The EXP-0016 bounds *are* the TRAIN-normal pressure min/max, so every TRAIN-normal
step pair already has an in-bounds predecessor. 20,803 eligible TRAIN-normal pairs
(identical to EXP-0019); percentiles unchanged: p50 `0.0035`, p99 `1.1380`,
**p99.9 `2.1217` (primary cutoff)**, max `4.2197` (strict cutoff). The gate only
changes TEST scoring.

## EXP-0019 → EXP-0020

| | EXP-0019 (ungated) | EXP-0020 (gated) |
|---|---:|---:|
| new detections, missed pure-CMRI (p99.9) | 145 | **64** |
| missed pure-CMRI cohort (defined rate) | 544 | **460** (84 lose every eligible pair) |
| new pure-CMRI recall (p99.9) | 26.65 % | **13.91 %** |
| pure-Normal FP (p99.9) | 45 | **18** |
| — of which boundary artifact | 35 | **8** |
| combined precision (p99.9) | 96.945 % | **97.773 %** |
| Mann–Whitney p (signal) | 2.07e-19 | **1.84e-4** |

The gate did exactly what it was designed to do on the false-positive side. It also
removed 56 % of the detections and shrank the cohort — most of EXP-0019's headline
recall (and signal strength) was riding on the same boundary jumps.

## Decision-rule bars

| bar | pre-registered | primary (p99.9) | strict (TRAIN-normal max) |
|---|---|---:|---:|
| new pure-CMRI recall | ≥ 25 % strong / ≥ 10 % acceptable | 13.91 % | 12.17 % |
| new pure-Normal FP rate | ≤ 0.30 % | **0.3745 % ✗** | **0.0832 % ✓** (4 windows) |
| combined precision | ≥ 97.0 % | **97.773 % ✓** | **98.239 % ✓** |
| `classify_verdict` | | **WEAK / NOT SUPPORTED** | **ACCEPTABLE** |

**Pre-registered primary (p99.9) verdict: `WEAK / HYPOTHESIS NOT SUPPORTED`** — it
fails the FP bar by ~4 windows. Recall clears the 10 % ACCEPTABLE threshold and
precision clears the floor, but not both required bars.

Whole 9,347-window TEST block at the primary cutoff, delta (TN, FP, FN, TP) if
OR-ed in: `(-17, +17, -129, +129)`.

### The strict-cutoff variant

At the TRAIN-normal-max cutoff (`rate_w > 4.2197`) the same gated rule reaches
**ACCEPTABLE**: recall 12.17 % (56 / 460 missed pure-CMRI), pure-Normal FP 0.083 %
(4 / 4,807), combined precision 98.24 %. This is a defensible small detector — it
would lift pure-CMRI combined recall ~54.6 % → ~59 % for ~4 Normal false positives —
but it is the *secondary* variant, not the pre-registered primary. Claiming
EXP-0020 "passed" on its basis would be moving the goalposts.

## Signal test

Mann–Whitney U on gated `rate_w`, missed pure-CMRI vs pure-Normal:
`U = 1,215,680`, `p = 1.84e-4`, missed-CMRI median **0.0089** > Normal 0.0067 >
TRAIN-normal 0.0035. Still present and in the hypothesised direction, but far weaker
than EXP-0019's `p = 2.07e-19`.

## Context

Standalone, the gated rule (p99.9) catches NMRI pure 46 / 715 = 6.4 % and the whole
attack class 12.9 % at 97.0 % precision. MFCI / Recon untouched.

## Conclusion and recommendation

EXP-0020 as pre-registered is a **recorded negative result** — nothing is wired into
`run_detector()`. The physical rate-of-change hypothesis has a **real but small
effect**: after removing the boundary jumps that inflated both EXP-0019's false
positives and its detections, ~12–14 % of the CMRI EXP-0017 misses is recoverable,
and the pre-registered cutoff still slightly over-fires on Normal.

A strict-cutoff version does clear all bars at ACCEPTABLE. Whether to pursue it is a
**user judgement call**:
- **(a)** EXP-0021 pre-registers the gated rule with the TRAIN-normal-max cutoff as
  primary (justified — EXP-0020 showed p99.9 over-fires) and, if it holds, weighs
  wiring it in for a ~5 pp pure-CMRI recall gain at ~4 Normal FPs; or
- **(b)** close the pressure-rate line — the effect is real but marginal, and
  EXP-0018/0019/0020 have each now scored TEST once against a pressure hypothesis
  about the missed CMRI (garden-of-forking-paths risk, disclosed in the pre-reg).

## Tests

Full suite **164 → 170 passed, 0 skipped, 0 failed** (+6 EXP-0020 tests: 5 fast
synthetic units, 1 slow saved-result replay). No raw data read in pytest.

## Limitations

- Pressure is the ARFF-aligned value, not a live `0x03` byte decode; register
  map/scale undocumented.
- The cutoff is an empirical TRAIN-normal percentile; the in-bounds gate uses the
  empirical EXP-0016 TRAIN-normal range, not a physical spec.
- 1–2 pressure samples per 5 s window; `rate_w` is one step rate.
- EXP-0018/0019/0020 have each scored the frozen TEST set once against a pressure
  hypothesis about the missed CMRI — a truly held-out confirmation of any positive
  result needs data not used here.
- One testbed; egress-only. Judged only on CMRI windows EXP-0017 already misses.
