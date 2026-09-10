# EXP-0019 — physical rate-of-change plausibility test for missed CMRI

**Pre-registered verdict: WEAK / HYPOTHESIS NOT SUPPORTED** — but a near-miss: the
signal is real and points the hypothesised way, and the false-positive failure is
dominated by an identified, likely-fixable artifact. Measurement only;
`run_detector`, `app.py` and all protected / EXP-0018 files unchanged. New files
only. Pre-registration and full method: `EXPERIMENT_LOG.md` (EXP-0019); decision
record: `DECISION_LOG.md` (EXP-0019).

## Hypothesis (tested — not assumed)

A real physical process has a maximum plausible RATE of pressure change. A forged
CMRI injection can jump the reported value faster than the process could physically
move in the real elapsed time since the last `0x03` reading — even when the value is
inside the EXP-0016 bounds and the raw jump size resembles a legitimate swing.
Distinct from EXP-0018, which tested residual energy against a fixed AR(1) variance
and ignored elapsed time.

## What was built

- `align_egress_pressure_timeseries()` — the EXP-0016 verified TXT↔ARFF alignment
  loop, keeping `(timestamp, pressure)` for every canonical egress `0x03` response.
- Feature: `rate_i = |p_i − p_{i-1}| / (t_i − t_{i-1})` over consecutive samples,
  `Δt` from real TXT timestamps (strictly monotonic; consecutive `0x03` `Δt` median
  3.39 s; ~7 % of steps are 3–4× cadence gaps — EXP-0007/0008).
- Per window: `rate_w` = max step rate over pairs whose later sample lands in the
  window. Undefined (not flaggable) if the window has no such pair.
- Plausibility bound: **TRAIN-normal 99.9th percentile of `rate`** (the register
  map/scale is undocumented, so no engineering `dP/dt` limit exists; TRAIN-normal
  already contains the process's fastest legitimate valve/pump transitions). Fire if
  `rate_w > cutoff`. The TRAIN-normal max is also reported as a stricter variant.
  A `k·σ` bound is rejected on EXP-0018's evidence (statistic too heavy-tailed).

TRAIN-normal `|Δp|/Δt` percentiles: p50 `0.0035` · p99 `1.1380` · **p99.9 `2.1217`
(primary cutoff)** · p99.99 `3.5977` · max `4.2197` (strict cutoff).

## Evaluation cohort

CMRI-labelled TEST windows the **EXP-0017 combined detector does not already flag**
(`comb_pred == 0`). 544 previously-missed pure-CMRI windows (all with a defined
`rate_w`).

## Identity gates — passed

`load_result` re-verified every tracked source sha256, the envelope checksum, the
manifest identity and the VALIDATED status. `comb_pred == protocol_pred |
pressure_pred | if_pred` element-wise; whole-TEST `(4767, 40, 2166, 2374)`.
`run_detector` not called. No drift.

## Result

### Signal test (threshold-independent) — PRESENT, hypothesised direction

| | value |
|---|---|
| Mann–Whitney U (missed pure-CMRI vs pure-Normal `rate_w`) | 1,614,883 |
| p-value (two-sided) | 2.07 × 10⁻¹⁹ |
| median `rate_w` — missed pure-CMRI | **0.0139** |
| median `rate_w` — pure-Normal TEST | 0.0067 |
| median `rate_w` — TRAIN-normal steps | 0.0035 |
| missed-CMRI rate *higher* than Normal (hypothesis direction) | **True** |

Unlike EXP-0018, the effect is significant **and** in the direction the hypothesis
predicts.

### New detections on the 544 previously-missed pure-CMRI windows

| cutoff | new detections | new recall |
|---|---:|---:|
| TRAIN-normal p99.9 (`> 2.1217`) | 145 | **26.65 %** |
| TRAIN-normal max (`> 4.2197`) | 117 | 21.51 % |

dominant / containing cohorts: 25.86 % / 26.00 % (p99.9).

### Decision-rule bars

| bar | pre-registered | p99.9 cutoff | strict max cutoff |
|---|---|---:|---:|
| new pure-CMRI recall | ≥ 25 % (strong) | **26.65 % ✓** | 21.51 % |
| new pure-Normal FP rate | ≤ 0.30 % | **0.936 % ✗** | 0.437 % ✗ |
| combined precision | ≥ 97.0 % | **96.945 % ✗** | 97.71 % ✓ |

Whole 9,347-window TEST block, delta (TN, FP, FN, TP) if the p99.9 rule were OR-ed
in: `(-43, +43, -260, +260)` — +260 true positives for +43 false positives.

**Pre-registered verdict: `WEAK / HYPOTHESIS NOT SUPPORTED`** (fails the FP bar and
the precision floor; passes the recall bar and the signal-direction test).

### The false positives are mostly an artifact

| pure-Normal FPs (p99.9 rule) | count |
|---|---:|
| total | 45 |
| where the max-rate pair steps DOWN from a predecessor window EXP-0017 flags / that is attack-labelled | **35** |
| residual after excluding those | **10 → 0.208 % FPR** |

The rule is crediting a Normal window for pressure *returning to normal* after an
anomaly in the previous window, rather than for its own behaviour. Excluding that
mechanism, the residual false-positive rate (0.208 %) would clear the 0.30 % bar.
(Diagnostic only — the pre-registered rule is not changed or rescored.)

### Context

Standalone, the rate rule is a "large fast jump" detector: NMRI pure 144 / 715 =
20.1 % recall at 76.2 % precision; whole attack class 24.9 % recall / 96.2 %
precision. MFCI / Recon essentially untouched.

## Conclusion and recommendation

EXP-0019 as pre-registered is a **recorded negative result** — nothing is wired into
`run_detector()`. But this is materially more promising than EXP-0018: the
rate-of-change hypothesis is directionally confirmed, ~27 % of missed CMRI is
recoverable, and the dominant false-positive mechanism is specific and looks fixable.

**Recommended follow-up — EXP-0020**, with a FRESH pre-registration: a refined
per-window rate statistic that scores a jump only against an in-bounds / unflagged
predecessor (or only the entry transition into an episode), with the decision rule
fixed before rescoring. Do NOT tweak-and-rescore EXP-0019 against the same TEST.

## Tests

Full suite **156 → 164 passed, 0 skipped, 0 failed** (+8 EXP-0019 tests: 7 fast
synthetic units, 1 slow saved-result replay). No raw data read in pytest.

## Limitations

- Pressure is the ARFF-aligned value, not a live `0x03` byte decode; register
  map/scale undocumented.
- The cutoff is an empirical TRAIN-normal percentile, not a physical `dP/dt` limit —
  TRAIN-normal may not contain every legitimate fast transient the process can make.
- 1–2 pressure samples per 5 s window: `rate_w` is one step rate, and a window's
  later sample may pair with the previous window's last sample (the source of the
  boundary artifact above).
- One testbed; egress-only. Judged only on CMRI windows EXP-0017 already misses.
