# EXP-0026 — Native window-size exploration for MSCI/MPCI pressure separation

**Status: TESTED. Descriptive/diagnostic only — the decision gate did NOT
pass, so no detector was built.** This is a NEW, SEPARATE pipeline variant;
`ml/features_windowed.py` and `ml/iforest_detector.run_detector` are untouched.

## Bottom line

**No window size (15s/30s/60s) clears the pre-registered bar (`|d| >= 0.5` on
the primary, EXP-0021-methodology-matched cohort) for MSCI or MPCI.** The
effect does grow monotonically with window size — MPCI's `p_std` Cohen's d
rises 0.242 (5s) → 0.317 (15s) → 0.384 (30s) → 0.421 (60s) — but plateaus
below the bar even at 60s (12x the baseline duration), consistent with, not an
improvement on, EXP-0021's episode-level finding (0.446, also sub-bar). This is
the honest, negative, near-miss result the pre-registration anticipated as a
real possibility. **This does not close the window-size question as
definitively as ACK-001/002 closed ack-anchored attribution** — see the
secondary "pure cohort" finding below, which is a genuinely different,
unexpectedly stronger signal that was NOT the pre-registered decision metric
and needs its own pre-registration if pursued.

## A bug the pre-registration's own consistency check caught

The pre-registration's step 3 required reproducing EXP-0021's saved
window-level Cohen's d at the 5s baseline before trusting any new window size.
**The first run failed this check** (MSCI p_std came back 0.643 vs the
expected 0.144): the initial implementation used EXP-0014's "pure" cohort
(no other attack category co-occurring) instead of EXP-0021's actual
window-level cohort ("containing" — any window with ≥1 frame of the category,
regardless of co-occurrence). This was a genuine implementation bug, not a
methodology dispute — EXP-0021's episode/window-level comparison is built from
`_containing`-equivalent membership, not `_pure`. Corrected to use `_containing`
as the primary cohort (matching EXP-0021 exactly) and keep `_pure` as
secondary, disclosed context. **After the fix, the 5s baseline reproduces
EXP-0021's saved numbers exactly** (0.144 for all four MSCI features except
`p_mean_shift` at 0.245; 0.242/0.263 for MPCI) — see the consistency-check
table below. This is exactly why the pre-registration required the check
before trusting anything: it caught a real bug before any conclusion was drawn.

## 5s-baseline consistency check

| category | feature | EXP-0021 saved d | EXP-0026 5s d | within 0.01 |
|---|---|---:|---:|---|
| MSCI | p_std | 0.144 | 0.144 | yes |
| MSCI | p_range | 0.144 | 0.144 | yes |
| MSCI | p_max_abs_step | 0.144 | 0.144 | yes |
| MSCI | p_trend_abs | 0.144 | 0.144 | yes |
| MSCI | p_mean_shift | 0.245 | 0.245 | yes |
| MPCI | p_std | 0.242 | 0.242 | yes |
| MPCI | p_range | 0.242 | 0.242 | yes |
| MPCI | p_max_abs_step | 0.242 | 0.242 | yes |
| MPCI | p_trend_abs | 0.242 | 0.242 | yes |
| MPCI | p_mean_shift | 0.263 | 0.263 | yes |

**All within tolerance.** The new native-window pipeline reproduces EXP-0021's
independently-computed numbers exactly at the baseline size, which is strong
evidence the split-boundary handling and feature computation are correct
before trusting the new window sizes.

## Native window population by size (TRAIN+VALIDATION)

| window (s) | TRAIN windows | VALIDATION windows | discarded (boundary/gap) |
|---:|---:|---:|---:|
| 5 | 28,040 | 9,345 | 3,379 |
| 15 | 8,778 | 2,928 | 3,819 |
| 30 | 4,325 | 1,446 | 2,022 |
| 60 | 2,091 | 700 | 1,137 |

The tradeoff is real and visible: 60s windows have ~10x fewer total examples
than 5s windows. Discarded counts are non-trivial at every size (boundary
crossings plus the manifest's existing internal TRAIN/VALIDATION gaps,
multiplied by the coarser grid) — disclosed, not hidden.

## Primary comparison — "containing" cohort (matches EXP-0021's methodology)

| window (s) | MSCI best \|d\| (feature) | n MSCI containing | MPCI best \|d\| (feature) | n MPCI containing |
|---:|---:|---:|---:|---:|
| 5 (baseline) | 0.245 (p_mean_shift) | 1,012 | 0.263 (p_mean_shift) | 2,593 |
| 15 | 0.327 (p_mean_shift) | 858 | 0.391 (p_mean_shift) | 2,152 |
| 30 | 0.397 (p_mean_shift) | 499 | 0.397 (p_mean_shift) | 1,235 |
| 60 | 0.450 (p_range) | 310 | 0.423 (p_range) | 770 |

Full per-feature tables are in `data/experiments/exp0026_window_size.json`.
Every value is graded "small" (0.2–0.5) at every window size tested; none
reaches "medium" (≥0.5), the pre-registered bar. The trend is monotonically
increasing with window size but decelerating — consistent with a real, weak,
slowly-accumulating pressure-consequence signal that the current 5s window
partially (not severely) dilutes, not a sudden reveal at some larger size.

## Secondary finding — the "pure" cohort (EXP-0014's methodology, NOT the pre-registered gate)

Reported honestly because it is large and directionally interesting, but it is
**not** part of the pre-registered decision rule and must not be treated as if
it were:

| window (s) | MSCI pure \|d\| (p_std) | n MSCI pure | MPCI pure \|d\| (p_std) | n MPCI pure |
|---:|---:|---:|---:|---:|
| 5 | 0.643 | 606 | 0.035 | 1,435 |
| 15 | 0.991 | 460 | 0.035 | 1,132 |
| 30 | 1.242 | 234 | 0.051 | 586 |
| 60 | 1.426 | 117 | -0.001 | 299 |

**MSCI's pure-cohort effect is large and grows sharply with window size** (0.643
→ 1.426), while MPCI's pure-cohort effect stays negligible throughout (~0.0-0.05)
— the opposite pattern from the containing cohort, where MPCI showed the
larger effect. This asymmetry is itself informative: MSCI windows that do NOT
co-occur with any other attack category appear to have a materially different
(stronger) pressure signature than MSCI windows generally, at every window
size — but this population shrinks fast (606 → 117) and was never the
pre-registered comparison, so it is reported as a genuinely surprising,
exploratory finding, not a result the gate authorizes acting on. Pursuing it
would require a fresh pre-registration (why "pure" is the right cohort for a
detector target, what selection effect co-occurrence exclusion introduces,
whether 117 examples at 60s is enough to trust).

## Decision gate — NOT PASSED

Pre-registered rule: `|Cohen's d| >= 0.5` AND `n_containing_attack_windows >=
30`, on the primary cohort, at some window size > 5s. **Not satisfied at any
tested size for either category.** Per the pre-registration's step 5/8: STOP —
no detector built at any native window size. This is a valid, useful negative
result, not a failure of the experiment.

## Honest interpretation

Redefining the observation unit natively longer does move the pressure-
consequence signal in the same direction EXP-0021's episode aggregation
found — growing, not vanishing — but it does not clear the bar EXP-0021's own
episode-level number also failed to clear (0.446 there, 0.421-0.450 here at
60s). **Native window-size alone is not the missing ingredient**; EXP-0021's
aggregation (which follows the actual variable-length attack episode, not a
fixed grid) got closer to the bar with less data reduction than a fixed 60s
grid does here. This is consistent with the underlying signal being real but
weak and only partially explained by "the window is too short" — some of what
EXP-0021 gained from true episode-alignment is lost when windows are instead
snapped to a fixed grid that frequently starts/ends mid-episode.

## Tests

`tests/test_exp0026_window_size.py`: 17 fast synthetic units (split-boundary
discard logic including internal-gap crossing, no-leakage-across-blocks
guarantee across all three tested multiples, native window rejection of non-5s
multiples, the five pressure features including the redefined `p_mean_shift`,
`_pure`/`_containing`/`_pure_normal` cohort selection, the decision gate
including its baseline-exclusion rule, and static-analysis scope checks) + 1
`@pytest.mark.slow` saved-result replay (no raw-data read; skips if the JSON is
absent). Full suite: **275 → 293 passed** (18 new; 0 skipped, 0 failed with the
JSON present).

## Files

New only: `ml/exp0026_window_size.py`, `tests/test_exp0026_window_size.py`,
`data/experiments/exp0026_window_size.json`, this file. `ml/features_windowed.py`,
`ml/iforest_detector.py`, `run_detector`, DoS Type 1's invalidated files, CMRI's
closed files, Layer A, and `app.py` are unchanged. `exp0021_msci_mpci.Blocks`/
`cohens_d`/`grade_effect` are imported read-only, as the pre-registration's
step 3 specified.

## Limitations / honest disclosure

- Feature scope is deliberately narrowed to EXP-0021's five pressure features,
  not EXP-0014's 16 protocol/rate/entropy features — disclosed and justified
  in the pre-registration (those features are structurally invariant to
  window size, since MSCI/MPCI write frames are byte-identical to Normal
  writes).
- Native windows are fixed-grid, not episode-aligned; a native window can
  start or end mid-episode, and this experiment does not correct for that —
  it is offered as one candidate explanation for why native windows did not
  outperform EXP-0021's episode-aligned aggregation despite testing sizes
  (60s) larger than the median episode duration (~75-80s at 5s/window median
  length 15-16).
- The "pure" cohort's strong MSCI effect is reported but not validated against
  any held-out data or gate — it is exploratory, disclosed as such, and
  requires its own pre-registration before any further action.
- `p_mean_shift` is redefined at native-window granularity as "vs the mean
  pressure of the immediately preceding native window of the same size,"
  generalizing EXP-0021's "vs the episode's own preceding span" from
  episode-relative to grid-relative. At the 5s baseline a native window of
  size 5s IS an ordinary 5s window, so this reduces to the same comparison
  EXP-0021 made — checked explicitly (not assumed), and it reproduced exactly
  (0.245 MSCI / 0.263 MPCI, both within tolerance).
- One testbed; egress-only; TRAIN+VALIDATION only. TEST was not read or
  scored (no gate passed to authorize it).
