# ACK-001 — Feasibility/coverage check for an ack-anchored consequence detector

**Status: TESTED.** Feasibility/coverage check only — no classifier, detector, rule
or threshold was built or scored. `run_detector`, `iforest_detector.py`, `rules.py`,
Layer A, `app.py`, DoS files and CMRI's closed files are unchanged.
`features_windowed.build_windows`/`Window` were imported read-only (via
`exp0021_msci_mpci.Blocks`) for the pure/mixed check only.

## Bottom line

**The proposed design is not feasible as specified, for every category checked —
including Normal.** The pre-registered stopping rule, applied literally to the raw
(uncensored) scorability numbers, does not trigger — but that is because the raw
metric silently ignores the design's own truncation/censoring rule. Once that rule
is actually applied (as it must be for the design to make sense — pressure samples
after the *next* command reflect that command's effect, not the anchoring ack's),
**scorability collapses to 0.00% at every horizon (10/30/60/120s) for Normal, MSCI,
and MPCI alike.** This is a structural property of the write-command and
pressure-read cadence in this dataset, not a per-category or per-attack-type
problem, and not a bug (verified directly against raw per-ack counts below).

## Identity gate

EXP-0017 reproduced from its checksummed artifact (`comb == protocol | pressure |
IF`, whole-TEST confusion `(4767, 40, 2166, 2374)`). TEST was not read or scored by
this experiment.

## Population (TRAIN+VALIDATION only, corrected manifest)

- 51,229 observable egress `0x10` write-acknowledgements (8-byte echo responses).
- 53,261 observable egress `0x03` canonical pressure-response frames.
- By ground-truth label (reporting only): **Normal 38,807**, **MPCI 8,341**,
  **MSCI 3,274**, and 807 acks under **DoS** (out of scope for this design,
  reported separately, not silently dropped). No NMRI/CMRI/MFCI/Recon acks were
  observed.

## Why raw and censoring-aware scorability diverge: the cadence

| signal | median inter-arrival | mean | p90 | max |
|---|---|---|---|---|
| `0x03` pressure response | 3.41s | 4.11s | 3.69s | 348.6s |
| `0x10` write ack | 3.38s | 4.27s | 3.67s | 640.1s |

Both signal types arrive on **essentially the same ~3.4-second cadence** — the
master's polling/control cycle interleaves pressure reads and register writes at a
similar rate. This single fact explains everything below: a "10-second post-ack
window" nominally spans about 3 poll cycles, but because *another* write ack lands
roughly every 3.4 seconds too, the design's own truncation rule almost always cuts
that window down to ~3.4 seconds before a second pressure sample can arrive.

## Coverage results, by category

### Pre-ack baseline (≥5 samples in 30s before the ack)

| category | n acks | % valid baseline |
|---|---|---|
| Normal | 38,807 | 98.77% |
| MSCI | 3,274 | 99.30% |
| MPCI | 8,341 | 98.60% |

Pre-ack baselines are fine — this is not where the design breaks.

### Clustering and pure/mixed

| category | % clustered (another ack ≤10s away) | % pure | % mixed |
|---|---|---|---|
| Normal | 100.00% | 73.83% | 26.17% |
| MSCI | 100.00% | 0.00% | 100.00% |
| MPCI | 100.00% | 0.00% | 100.00% |

**Every single ack in the population is clustered** under the design's own 10s
definition — consistent with the ~3.4s inter-ack cadence above. MSCI and MPCI acks
are **never** pure (0.00%): every 5-second bucket containing an MSCI or MPCI ack
also contains at least one other category (almost always Normal, since command
injection attacks are interleaved with ongoing legitimate polling, not batched into
isolated windows).

### Horizon scorability — raw (nominal window, ignoring censoring) vs
censoring-aware (design's own truncation rule applied)

| category | horizon | min required | raw % scorable | **censoring-aware % scorable** | % censored |
|---|---|---|---|---|---|
| Normal | 10s | 2 | 99.64% | **0.00%** | 99.66% |
| Normal | 30s | 5 | 98.84% | **0.00%** | 99.67% |
| Normal | 60s | 10 | 97.42% | **0.00%** | 99.67% |
| Normal | 120s | 20 | 94.72% | **0.00%** | 99.67% |
| MSCI | 10s | 2 | 99.79% | **0.00%** | 99.79% |
| MSCI | 30s | 5 | 99.27% | **0.00%** | 99.79% |
| MSCI | 60s | 10 | 98.41% | **0.00%** | 99.79% |
| MSCI | 120s | 20 | 96.27% | **0.00%** | 99.79% |
| MPCI | 10s | 2 | 99.68% | **0.00%** | 99.71% |
| MPCI | 30s | 5 | 98.93% | **0.00%** | 99.71% |
| MPCI | 60s | 10 | 97.76% | **0.00%** | 99.71% |
| MPCI | 120s | 20 | 95.36% | **0.00%** | 99.71% |

The raw column is the number the pre-registered stopping rule (read literally) would
check — and by that reading, none of MSCI/MPCI is flagged (`pct_unscorable_at_120s
≈ 3.7–4.6%`, nowhere near the 50% majority threshold). **This is a misleading
picture on its own.** The censoring-aware column applies the design's own
truncation rule (a horizon is cut to the gap-to-next-ack whenever that gap is
shorter than the nominal horizon) — and once truncated, **literally zero acks in
any category, at any horizon, retain enough pressure samples to be scorable.**

This is not an artifact of the 0.00% being a rounded small number. Direct
per-ack verification (not just the aggregate percentage) on every ack that is *not*
even censored at the easiest 10-second horizon (131 Normal, 7 MSCI, 24 MPCI acks —
i.e. the most favourable cases in the entire population) found a **maximum of 1**
pressure sample reachable in that window, against a minimum requirement of 2, with
**zero exceptions** across all 162 such acks checked directly. The 0.00% is real,
not a display artifact.

## Pre-registered stopping-rule verdict

| category | literal rule (raw horizon) | censoring-aware verdict |
|---|---|---|
| MSCI | not flagged (3.73% unscorable at 120s, raw) | **LIKELY INFEASIBLE** (100% unscorable at 120s, after censoring) |
| MPCI | not flagged (4.64% unscorable at 120s, raw) | **LIKELY INFEASIBLE** (100% unscorable at 120s, after censoring) |

**The literal pre-registered rule, taken at face value, would give a false GO
signal.** It was written assuming "scorable" naturally accounts for censoring; it
does not unless the truncation is explicitly applied. Reporting only the raw number
here would have been dishonest given step 6's mandate and the fact that this
divergence was directly measured and verified. The correct reading of the
pre-registered stopping rule — applying its own truncation logic, as the surrounding
text in step 3 clearly intends — is **LIKELY INFEASIBLE for both MSCI and MPCI**.
And, as the table above shows, **Normal fares no better** (0.00% censoring-aware
scorable too) — this is not a category-specific detection problem, it is a
population-wide data-density problem.

## Honest interpretation (step 6)

This hits the same wall EXP-0023 found for the undecoded payload bytes: **the data
does not support the question**, not because of a subtle effect that's too small to
detect, but because the observation the design requires (several pressure samples
cleanly attributable to a single ack's aftermath) essentially never exists in this
capture. The root cause is structural and dataset-wide: `0x03` polls and `0x10`
writes interleave on a shared ~3.4-second master cycle, so any accounting that
respects "don't attribute post-command pressure behaviour past the next command"
leaves almost no window to observe.

**Recommendation: do not invest further build effort in the fuller design (matched-
reference detector, trajectory templates, supervised heads) as specified.** Two
paths that were *not* evaluated here and would need their own pre-registration if
pursued:
- Relaxing the censoring rule to tolerate overlap with the next ack's effects (this
  changes what is being measured — no longer "this command's consequence" — and
  would need to be justified on its own terms, not smuggled in as a coverage fix).
- Redefining the observation unit at a coarser grain (e.g. the existing 5-second
  window or per-episode aggregation, as EXP-0021/0022 already did for pressure) —
  this abandons the ack-anchoring premise entirely and is really a different design,
  already explored by EXP-0021/0022 with its own (also negative) result for MPCI.

## Tests

`tests/test_ack001_ack_anchored_coverage.py`: 21 fast synthetic units (ack/pressure
shape identification including a reproduction of the frozen EXP-0016/0023 sample
frame, range-counting inclusivity, pre/post-ack counting, nearest- and next-ack gap
arithmetic, end-to-end category summarisation including a case that specifically
exercises raw-vs-censoring-aware divergence, pure/mixed, the stopping rule
[including its raw-vs-censoring-aware divergence], cadence-summary arithmetic, and
static-analysis checks that `source` and the protected files are never touched) + 1
`@pytest.mark.slow` saved-result replay (no raw-data read; skips if the JSON is
absent). Full suite: **215 → 237 passed** (22 new; 0 skipped, 0 failed with the JSON
present).

## Files

New only: `ml/ack001_ack_anchored_coverage.py`,
`tests/test_ack001_ack_anchored_coverage.py`,
`data/experiments/ack001_coverage.json`, this file. `run_detector`, `app.py`, DoS
files, Layer A, the closed EXP-0018/0019/0020 CMRI files, and all prior EXP files
are unchanged.

## Limitations / honest disclosure

- The censoring rule as implemented truncates a horizon to the gap-to-next-ack
  whenever that gap is shorter than the horizon; it does not attempt to attribute
  partial credit or model overlap more finely. A more permissive rule (e.g.
  tolerating brief overlap) was not tried and would need to be independently
  justified, not adopted post hoc to rescue the design.
- This check only establishes *data availability* for the anchoring/horizon/
  censoring scheme as literally specified. It says nothing about whether pressure
  actually *changes* differently after MSCI/MPCI acks versus Normal acks in
  whatever observation window does exist — that question is moot here because the
  window essentially never exists in the first place.
- `pct_censored` and `pct_scorable_after_censoring` are computed per ack
  independently at each horizon; the reported "typical censoring point" evidence is
  the cadence table above (median inter-ack gap ≈3.4s) rather than a full
  distribution across all four horizons, since the conclusion (0.00% scorable
  post-censoring, at every horizon) made a finer breakdown unnecessary.
