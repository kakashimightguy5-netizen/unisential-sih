# EXP-0029 — regime-aware rolling baseline (causal relative deviation) — TESTED, NO-GO

**Verdict: NO-GO for NMRI. NO-GO for the CMRI secondary check (not evaluated further — the diagnostic failed for the shared feature before any detector was built).**

Pressure is egress traffic extracted from Mississippi State ICS testbed dataset, used as a simulated diode-observer view — never real diode capture data. `ml/iforest_detector.run_detector` was NOT modified and NOT called.

## Motivation

EXP-0017's combined rule (pressure-bounds + IF) misses 150/715 (23.4%) pure-NMRI TEST windows even though all existing rules only compare pressure against a GLOBAL notion of normal (fixed TRAIN-normal extrema). This experiment tested whether those 150 misses are anomalous relative to the *immediately preceding run* — a regime-local baseline — via a causal rolling median/MAD z-score:

```
z_t = (P_t - median(P[t-k:t-1])) / (MAD(P[t-k:t-1]) + epsilon)
```

for pre-registered candidate window sizes k = 5, 10, 20 samples (fixed before any VAL/TEST score was read). This is explicitly **not** a rate-of-change feature (no division by elapsed time) — it is a different baseline model from the closed EXP-0019/0020 rate-of-change line.

## Identity gates (all passed)

- EXP-0017 artifact loaded and checksum-verified.
- `comb == protocol | pressure | IF` element-wise: **True**.
- Whole-TEST confusion matches EXP-0017 exactly: **4767 / 40 / 2166 / 2374** (TN/FP/FN/TP).
- EXP-0016 pressure bounds unchanged: `[0.482759, 38.7471]`.
- Split manifest identity (`verified-egress-5s-exp0008-pretest-v1`) matches the EXP-0017 artifact.
- Known false-negative cohort re-derived directly (pure-NMRI TEST windows with `comb_pred == 0`): **150/150**, exactly matching the pre-registered figure. No re-derivation ambiguity.

## Step 2 — mandatory diagnostic (BEFORE building any detector)

Cohen's d and Mann-Whitney U comparing `|z_t|` for the 150 known pure-NMRI false negatives vs pure-Normal TEST windows, per candidate k:

| k | median missed-NMRI \|z\| | median Normal \|z\| | Cohen's d | Mann-Whitney p |
|---:|---:|---:|---:|---:|
| 5 | 2.6496 | 2.1000 | **+0.075** | 0.803 |
| 10 | 2.1986 | 1.9997 | +0.052 | 0.046 |
| 20 | 2.8869 | 1.7996 | +0.040 | 5.07e-08 |

Best candidate: **k=5, d=+0.075**, far below the pre-registered `d >= 0.5` bar. All three candidates are effectively negligible effect sizes (Cohen's convention: `d < 0.2` is "negligible"). Two of three candidates show statistically significant p-values (large TEST sample sizes make even a tiny median shift of ~0.2-1.1 units in `|z|` statistically detectable), but the effect size is what the pre-registration gates on, and it is a diagnostic failure by that bar.

**This is a diagnostic failure, reported honestly per the EXP-0014 standard**: statistical significance without a materially meaningful effect size does not clear the pre-registered bar. The missed NMRI windows are *not* markedly more regime-anomalous (via this median/MAD causal feature) than ordinary Normal traffic in the same TEST period.

## Steps 3–5 (threshold building, artifact check, CMRI generalization) — NOT performed

Per the pre-registered decision rule: diagnostic effect size `d < 0.5` → NO-GO, close, document, **do not iterate on window size k as a post-hoc rescue**. No threshold was fit on VAL, no TEST rule-scoring was performed, and the CMRI generalization check was not run because it depends on the same z_t feature that already failed the mandatory diagnostic gate for NMRI.

## Decision-rule verdict (fixed, not amended after seeing results)

- **NMRI: NO-GO** — diagnostic effect size (best d=0.075) is below the 0.5 bar.
- **CMRI (secondary): NO-GO** — not independently evaluated; the shared z_t feature already failed the mandatory diagnostic for its primary target, and the spec's decision rule closes the line on diagnostic failure before any detector is built for either target.

## Interpretation

The missed NMRI false negatives are, by this measure, not detectable via a regime-local (recent-run-relative) baseline on pressure alone. A plausible explanation: NMRI (naive-response injection) forgeries that pass the global bounds check may already resemble locally-typical values for the current operating regime rather than deviating from the recent trailing window — i.e., a forged value chosen to look globally plausible can also look locally plausible if the process is not moving quickly between regimes at that moment. This does not rule out a *different* regime-local formulation (e.g. one anchored to explicit setpoint-change detection, or with a much longer trailing horizon spanning multiple operating cycles), but per the pre-registration, k is not iterated further inside this experiment.

## Deliverables

- `ml/exp0029_regime_baseline.py` — diagnostic + (unreached) detector-build code.
- `tests/test_exp0029_regime_baseline.py` — 19 fast synthetic unit tests + 1 slow saved-result replay; all pass.
- `data/experiments/exp0029_regime_baseline.json` — saved run output (status: `TESTED — DIAGNOSTIC FAILURE; NO DETECTOR BUILT`).
- This file.
- No wiring diff produced (NO-GO on both targets).

## Deliverables note (docs/overview.md)

The spec's fallback deliverable location `docs/overview.md` does not exist anywhere in this repository (confirmed, same as EXP-0028) — flagged rather than invented. This results file plus the `docs/EXPERIMENT_LOG.md` entry serve as the record instead.
