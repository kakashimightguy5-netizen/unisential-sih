# EXP-0028 — CMRI trajectory-matching (DTW / discord) vs Normal reference library

**Pre-registered verdict: `NO-GO`.** The trajectory-shape hypothesis is
outperformed by the existing PressureBoundsRule baseline by a wide margin, and
fails the false-positive bar on top of that. Measurement only;
`run_detector`, `app.py`, and all protected EXP-0005..0027 files are
unchanged. New files only. This is the fourth and final CLOSED angle on the
missed-CMRI line (after EXP-0018 residual smoothness, EXP-0019 raw
rate-of-change, EXP-0020 gated rate-of-change).

## Implementation note — no dtaidistance / stumpy

`pip install dtaidistance stumpy` was attempted in this session. The download
did not finish inside the available time budget (slow network; `llvmlite`
alone is ~42 MB and stalled). Per the pre-registration's stated fallback, DTW
and the discord score are hand-written in `ml/exp0028_cmri_trajectory.py`:

- **DTW**: a standard O(n·m) dynamic-programming distance (full, unconstrained
  warping path, absolute-difference cost), batched with numpy across the whole
  reference library so a nearest-neighbor search against K library rows costs
  one set of vectorized DP sweeps instead of K separate Python-level DP runs.
- **Discord**: a z-normalized Euclidean nearest-neighbor distance to the same
  library. For two FIXED-length, non-warped sub-sequences this is exactly the
  matrix-profile distance against a reference set, so no separate stumpy
  dependency is needed for the fixed-length case used here.

Both were spot-checked against hand-computed small cases in
`tests/test_exp0028_cmri_trajectory.py` (e.g. DTW of `[0,2]` vs `[[0,0]]` = 2.0
by direct DP arithmetic; discord of `[0,0,0]` vs `[[1,0,0],[3,4,0]]` = 1.0).

## Identity gates — passed

`exp0017_operational.load_result` re-verified every tracked source sha256, the
envelope checksum, the manifest identity and the VALIDATED status.
`comb_pred == protocol_pred | pressure_pred | if_pred` element-wise; whole-TEST
`(4767, 40, 2166, 2374)`. `run_detector` never called. EXP-0016 pressure bounds
reproduced exactly `(0.482759, 38.7471)`.

## Method (as pre-registered)

- **Window definition**: EXP-0017's frozen 5 s buckets, from the checksummed
  manifest (`ml/exp0008_cadence_features.load_pretest_split`), reused via
  `exp0019_pressure_rate_plausibility.Blocks` — not rederived.
- **Sub-sequence length**: 15 samples. TRAIN-normal median egress `0x03` step
  is 3.521 s, so 15 samples ≈ 52.8 s — inside the spec's 30–70 s span and its
  10–20 sample range.
- **Gap tolerance ("no data-gap")**: 1.5× the TRAIN-normal median step =
  5.282 s. A run of samples breaks wherever a step exceeds this.
- **Normal reference library**: every length-15 sub-sequence (stride 1) from
  TRAIN-normal-labelled contiguous runs, deduplicated by exact match after
  rounding to 4 decimals. 14,148 raw sub-sequences before dedup. Because an
  O(K) batched DTW against ~10k+ VAL/TEST candidates at K≈14,148 was not
  computationally tractable in this session (an earlier, unbounded run was
  killed after >10 minutes with no output and >2 GB RSS), the library was
  **deterministically subsampled to 300 rows** (fixed seed 0, uniform
  reservoir sample) — a compute-tractability decision fixed in the code
  *before* any VAL or TEST score was computed, not a post-hoc rescue of a
  disappointing result.
- **Per-window score**: for every VAL/TEST window, the MAX (most anomalous)
  z-normalized DTW / discord nearest-neighbor distance over all sub-sequences
  ending on a sample inside that window (mirrors EXP-0019/0020's
  max-over-endings-in-window aggregation). Undefined (excluded, counted as a
  miss) if no full-length, no-gap sub-sequence ends there. The DTW/discord
  computation itself was restricted to windows in VAL ∪ TEST (a compute-only
  restriction — the library remains TRAIN-only regardless).
- **Threshold**: fit on VAL only, per metric, at the largest value clearing a
  ≤ 0.30 % empirical VAL-Normal FPR. TEST scored exactly once per metric.

## Score distributions

| metric | library size | VAL-Normal median | VAL threshold |
|---|---:|---:|---:|
| DTW (z-norm) | 300 | — (see artifact table) | 8.3283 |
| discord (z-norm Euclidean NN) | 300 | — (see artifact table) | 3.8895 |

## Step 3 — mandatory artifact diagnostic (pooled VAL+TEST, descriptive)

Group A = pure-Normal window whose immediate predecessor window is
attack-labelled ("just returned from an attack"). Group B = pure-Normal window
whose predecessor's last pressure sample is within the EXP-0016 TRAIN-normal
bounds (the EXP-0020-style "plausible baseline" gate).

| metric | n(A) | n(B) | median A | median B | Cohen's d | Mann-Whitney p | inflated? |
|---|---:|---:|---:|---:|---:|---:|---|
| DTW | 316 | 9,113 | 6.0476 | 5.9953 | +0.128 | 0.0157 | **False** |
| discord | 316 | 9,113 | 2.9984 | 2.9476 | +0.010 | 0.600 | **False** |

Neither metric shows the EXP-0019 "returning to normal" artifact: DTW has a
statistically detectable but negligible-magnitude difference (d = 0.128, below
the repo's own 0.2 "small effect" convention) and discord shows no difference
at all (p = 0.60). **The artifact check is clean — no gate was applied**, and
VAL/TEST were scored on the full (ungated) candidate set.

## VAL threshold selection (fit on VAL only)

| metric | threshold | VAL Normal FPR (empirical) | VAL pure-CMRI recall |
|---|---:|---:|---:|
| DTW | 8.3283 | 0.2577 % | 4.60 % |
| discord | 3.8895 | 0.2577 % | 0.00 % |

DTW has the higher VAL recall and is the pre-registered primary metric,
selected before TEST was touched.

## TEST scoring — scored exactly once

| metric | Normal FPR | pure-CMRI recall | dominant-CMRI recall | containing-CMRI recall |
|---|---:|---:|---:|---:|
| **DTW (primary)** | **0.4630 %** | **7.68 % (92/1198)** | 6.79 % | 6.90 % |
| discord | 0.1984 % | 0.08 % (1/1198) | 0.17 % | 0.16 % |

## Decision-rule verdict

| bar | pre-registered | primary metric (DTW) | pass? |
|---|---|---:|---|
| TEST pure-CMRI recall > 54.59 % (PressureBoundsRule baseline) | strictly beat | 7.68 % | **FAIL** |
| Normal FPR ≤ 0.30 % | hard bar | 0.4630 % | **FAIL** |
| artifact check clean or gated | required | clean (not needed) | pass |

**`NO-GO`** — the trajectory-matching rule fails both the recall bar (by a
wide margin: 7.68 % vs a 54.59 % baseline it would need to beat) and the FPR
bar. No amendment to the decision rule was made after seeing these numbers.

## Reading the result honestly

DTW recall (7.68%) is far below not just the 54.59% bar but also below what
the much simpler EXP-0019 raw rate-of-change rule achieved as a *standalone*
signal (24.9% whole-attack-class recall, 26.65% new-recall-among-misses). The
shape-matching hypothesis, at least in this length-15/library-300
implementation, adds nothing over the single-point bounds rule it was meant to
beat, and its FPR is more than 50% over budget even before accounting for
recall. The library subsampling (14,148 → 300, forced by compute constraints)
is a genuine limitation — a full un-subsampled library is a possible
follow-up, but per the pre-registered decision rule this line is **CLOSED**,
and per the pre-registration's own instruction ("Do NOT iterate on window
length/distance metric/library size as post-hoc rescue"), that follow-up is
explicitly not pursued here.

## Tests

`tests/test_exp0028_cmri_trajectory.py`: 19 tests (18 fast synthetic units + 1
slow saved-result replay). Full repo suite: **322 passed, 0 skipped, 0
failed** (was 198 after EXP-0022; the difference includes EXP-0023/0025/0026/
0027/ACK-001/ACK-002 tests added since, plus these 19). No raw data read in
fast tests.

## Limitations

- Pressure is the ARFF-aligned value, not a live `0x03` byte decode; register
  map/scale undocumented.
- `dtaidistance`/`stumpy` were unavailable within the session's time budget;
  DTW and discord are hand-written and were only spot-checked against small
  hand-computed cases, not cross-validated against a reference library
  implementation.
- The Normal reference library was deterministically subsampled from 14,148 to
  300 rows for compute tractability, fixed before any VAL/TEST score was
  computed. A full library was not evaluated; whether it would change the
  result is untested.
- Per-window score is a MAX over sub-sequence endings inside the window
  (matching EXP-0019/0020's aggregation), not an average or a percentile.
- DTW/discord computation was restricted to VAL ∪ TEST candidate windows for
  compute reasons; the library itself remains TRAIN-only regardless (no
  leakage).
- EXP-0018/0019/0020/0028 have each scored the frozen TEST set once against a
  pressure hypothesis about the missed CMRI — a garden-of-forking-paths risk
  disclosed across the whole line; this is now the fourth and, per the CMRI
  saga's own closing convention, presumably final angle.
- One testbed; egress-only; measurement only, nothing wired in.

## Note on the deliverables list

The spec's NO-GO deliverable asked to append a summary to a "Major saga #3:
CMRI" section of `docs/overview.md`. Neither `docs/overview.md` nor any file
containing "Major saga" text exists anywhere in this repository (searched
recursively). Rather than invent that file/section, this NO-GO is recorded
here and as a new entry in `docs/EXPERIMENT_LOG.md` instead, consistent with
how EXP-0018/0019/0020/0021/0022 record their outcomes. Flagged for the user
rather than guessed.
