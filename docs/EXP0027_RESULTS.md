# EXP-0027 — MSCI 60s `p_std`: does the pure-cohort effect survive the realistic population?

**Status: TESTED. Decision gate NOT PASSED — no detector built.** EXP-0026's
MSCI 60s `p_std` pure-cohort effect (d=1.426, already verified not small-n
noise) does **not** survive against the realistic evaluation population.
Reported honestly as a selection-effect artifact, not a deployable signal —
still a valuable, well-verified negative result.

## Identity check

Reproduced EXP-0026's pure-cohort d exactly: **1.4263** (reference 1.426,
within 0.01 tolerance). Everything below builds on a pipeline confirmed
correct before trusting the new comparison.

## The three populations

| population | n MSCI | n Normal | d | effect |
|---|---:|---:|---:|---|
| pure MSCI vs pure Normal (EXP-0026's cohort) | 117 | 1,028 | +1.426 | large |
| **ALL MSCI-containing vs pure Normal (realistic)** | **310** | 1,028 | **+0.448** | small |
| mixed-only MSCI vs pure Normal | 193 | 1,028 | +0.697 | medium |

**The pre-registered gate (`|d| >= 0.5`, n >= 30) is NOT cleared: 0.448 < 0.5.**
This is close — closer than EXP-0021's episode-level number (0.446) was to
*its* gate — but per the pre-registration, "close" does not pass, and the bar
was fixed before this number was seen.

## Why does the combined population score LOWER than either sub-population?

This is the counterintuitive part worth explaining rather than leaving as a
black box: pure (d=1.426, n=117) and mixed (d=0.697, n=193) each show a real
effect on their own — yet pooling them into "all containing" (n=310) drops d
to 0.448, **below both**. This is not an arithmetic mistake; it is what Cohen's
d does to a genuinely heterogeneous mixture. Pure and mixed MSCI windows have
different mean pressure-variability shifts relative to Normal, so pooling them
inflates the "attack" group's own internal variance far more than it moves the
group mean — and Cohen's d divides by that pooled variance. **"MSCI-containing"
is not one homogeneous population; a plain window-level rule sees several
different distributions depending on what else is happening in the window,**
and averaging across them costs more than either sub-population would predict.

## Mixed-cohort breakdown by co-occurring category (step 2c)

| co-occurring | n windows | p_std mean | p_std median | n huge (>1e6) |
|---|---:|---:|---:|---:|
| CMRI | 83 | 5.4e+36 | 7.84 | 15 |
| CMRI+MPCI | 16 | 2.09e+37 | 20.6 | 6 |
| DoS | 3 | 0.538 | 0.505 | 0 |
| MPCI | 26 | 1.69 | 0.318 | 0 |
| NMRI | 42 | 6.8e+32 | 3.66 | 6 |
| NMRI+CMRI | 6 | 1.18e+37 | 5.14e+24 | 3 |
| NMRI+CMRI+DoS | 1 | 3,676 | 3,676 | 0 |
| NMRI+CMRI+MPCI | 6 | 1.21e+37 | 9.6e+35 | 5 |
| NMRI+MPCI | 10 | 2.39e+16 | 6.23 | 1 |

**The means in this table are not usable numbers** — 36 of the 310 containing
windows (12%) have a `p_std` above 1e6, all of them in groups that co-occur
with CMRI. CMRI is *defined* as naive out-of-bounds response injection
(the same phenomenon `PressureBoundsRule`/EXP-0016 was built to catch): when
an MSCI window also contains a genuine CMRI-forged pressure reading, that
reading is legitimately part of the window's own `p_std` — this is not a bug,
it is exactly what a live deployment would see, but it means `p_std` in those
windows is measuring CMRI's own signature, not MSCI's.

## CMRI-mechanism cross-check (informational only — does not change the gate)

To separate "is CMRI's forged pressure the reason the gate fails" from "is
population-heterogeneity the reason," both were checked directly:

| split | n | d |
|---|---:|---:|
| mixed WITH CMRI co-occurrence | 112 | +1.193 |
| mixed WITHOUT CMRI co-occurrence | 81 | +0.416 |
| ALL containing, EXCLUDING any CMRI co-occurrence | 198 | **+0.178** |

**CMRI co-occurrence is not the reason the gate fails — if anything it was
propping the number up.** Removing every CMRI-co-occurring window entirely
(leaving pure MSCI + non-CMRI-mixed MSCI, n=198) drops d to 0.178, *lower*
than the 0.448 with CMRI included. The heterogeneous-population-pooling
mechanism explained above is the dominant effect, not CMRI contamination —
CMRI's huge forged values happen to inflate the "mixed" sub-group's own d
(1.193 with CMRI vs 0.416 without), partially offsetting the pooling penalty,
not causing it.

## Decision gate — NOT PASSED

Pre-registered rule (same bar as EXP-0021/0026, not weakened for this harder
test): `|Cohen's d| >= 0.5` AND `n >= 30` on the realistic (all-containing)
population. **0.448 < 0.5 — gate does not pass.** Per the pre-registration:
STOP. No detector is built.

## Honest interpretation

**This is a selection-effect artifact of the pure-cohort filtering, not a
deployable signal.** The pure-cohort effect (d=1.426) is real and was
correctly verified as not small-n noise — but it describes a population a
real detector cannot select for in advance (it cannot know a window is "pure"
before scoring it). Once evaluated against the population an actual detector
would see — every MSCI-containing window, mixed with other attacks and all —
the effect collapses below the bar, for a real and explainable reason
(heterogeneous-population pooling), not a data artifact or a coding bug.
**This closes the specific "MSCI 60s `p_std`" lead as a standalone detector
candidate.** It does not reopen or invalidate ACK-001/002 (per-write/burst
attribution, already closed) or EXP-0026's other findings (window-size effect
on the primary "containing" cohort, unrelated to this pure-cohort excursion).

A narrower, honestly-scoped possibility this experiment surfaces but does NOT
pursue: `p_std` still shows a real (d=0.416-0.697), sub-gate but non-trivial
effect specifically for MSCI-mixed-with-non-CMRI-categories. Whether that
narrower population is itself identifiable in advance (e.g., co-occurring
MPCI is already independently somewhat detectable) is a different, not
pre-registered question and is not addressed here.

## Tests

`tests/test_exp0027_msci_realistic_population.py`: 9 fast synthetic units
(`other_category_of` co-occurrence detection, pure/mixed split correctness,
feature-value extraction with the two-sample minimum, CMRI-co-occurrence
identification, and static-analysis scope checks) + 1 `@pytest.mark.slow`
saved-result replay (no raw-data read; skips if the JSON is absent). Full
suite: **293 → 303 passed** (10 new; 0 skipped, 0 failed with the JSON
present).

## Files

New only: `ml/exp0027_msci_realistic_population.py`,
`tests/test_exp0027_msci_realistic_population.py`,
`data/experiments/exp0027_msci_realistic_population.json`, this file, plus
two documentation-only erratum entries in `docs/EXPERIMENT_LOG.md`/
`docs/DECISION_LOG.md` flagging EXP-0026's `p_mean_shift` contamination (see
below). `ml/features_windowed.py`, `run_detector`, the 5s production
pipeline, `ml/exp0026_window_size.py`, DoS Type 1's invalidated files, CMRI's
closed files, Layer A, and `app.py` are all unchanged.

## p_mean_shift erratum (task item 5)

Flagged in `docs/EXPERIMENT_LOG.md`/`docs/DECISION_LOG.md` (2026-09-12, prior
to this experiment's pre-registration): EXP-0026's `p_mean_shift` feature
reads the PRECEDING native window's pressure regardless of that window's
category, and a small number of neighbours are CMRI-labelled with a genuinely
huge forged pressure value — the same underlying phenomenon this experiment's
breakdown surfaces directly (CMRI co-occurrence inflating `p_std` within a
window that itself contains a CMRI frame, rather than via a neighbour).
`p_mean_shift` is not used anywhere in EXP-0027 (scope is `p_std` only), so it
is not at risk here, but the erratum stands as a documented limitation for any
future reuse of that specific feature.

## Limitations / honest disclosure

- Only `p_std` was re-examined at the realistic population; `p_range`/
  `p_max_abs_step`/`p_trend_abs` showed the same pattern in EXP-0026 (all four
  identical `d` at the pure-cohort level, since they are highly correlated for
  this data) and were not independently re-derived here — a reasonable
  economy given `p_std` is the headline feature and the mechanism (population
  pooling) is feature-agnostic, but disclosed as a scope limitation rather
  than assumed identical without stating it.
- The "co-occurring category" breakdown groups by the exact SET of other
  categories present; several groups have single-digit counts (DoS n=3,
  NMRI+CMRI+DoS n=1) and are reported as-is, not hidden, but should not be
  over-interpreted individually.
- 60s window size only; other sizes from EXP-0026 were not re-examined at the
  realistic population (out of scope for this follow-up, which targeted the
  specific 60s pure-cohort finding that motivated it).
- One testbed; egress-only; TRAIN+VALIDATION only. TEST was not read or
  scored — the gate did not pass, so no approval to score TEST was sought or
  needed.
