# EXP-0032 — admissible-information ceiling audit for NMRI/CMRI residual false negatives — TESTED, PROCEED-BOTH (both attack types)

**Verdict: PROCEED-BOTH for NMRI and PROCEED-BOTH for CMRI** (EXP-0030 float-provenance AND EXP-0031 event-level distribution fingerprint are both supported as candidate detectors; final go/no-go on each remains a *separate*, later decision — this experiment is a diagnostic probe, not a detector build).

Pressure is egress traffic extracted from Mississippi State ICS testbed dataset, used as a simulated diode-observer view — never real diode capture data. `ml/iforest_detector.run_detector` was NOT modified and NOT called beyond frozen-artifact identity-gate reproduction.

## Motivation

Four structurally different framings — EXP-0018 (AR(1) residual energy), EXP-0019 (rate-of-change plausibility), EXP-0020 (rate-bound gated on in-bounds predecessor), EXP-0028 (DTW/discord trajectory matching), EXP-0029 (regime-local median/MAD baseline) — were all NO-GO on the NMRI/CMRI windows EXP-0017's combined rule (pressure-bounds + protocol + Isolation Forest) already misses. Before spending a full pre-registration cycle each on EXP-0030 (IEEE-754 float-provenance) and EXP-0031 (event-level distribution fingerprint), this experiment used a flexible supervised classifier (XGBoost) purely as an information-ceiling probe: does *any* admissible signal exist in the residual cohort, and if so, in which feature family?

## Identity gates (all passed)

- EXP-0017 artifact loaded and checksum-verified.
- `comb == protocol | pressure | IF` element-wise: **True**.
- Whole-TEST confusion matches EXP-0017 exactly: **4767 / 40 / 2166 / 2374** (TN/FP/FN/TP).
- EXP-0016 pressure bounds unchanged: `[0.482759, 38.7471]`.
- Split manifest identity (`verified-egress-5s-exp0008-pretest-v1`) matches the EXP-0017 artifact.
- Known TEST false negatives (exact frozen `comb_pred == 0`): pure-NMRI **150**, pure-CMRI **544** (matches the population EXP-0018..0029 have targeted).

## Adaptation disclosed up front (documented, same convention as EXP-0028's dtaidistance/stumpy substitution)

The frozen EXP-0017 artifact only carries `comb_pred` for the **TEST** block. There is no saved combined-rule prediction for TRAIN/VALIDATION windows, and reproducing the full combined rule (protocol + pressure + Isolation Forest) for TRAIN/VAL would require calling `ml/iforest_detector.run_detector`, which this diagnostic is forbidden from doing beyond the frozen-artifact identity gate. The "windows the current rule already misses" residual cohort is therefore defined **per split**:

- **TEST**: exact frozen `comb_pred == 0` (no approximation).
- **TRAIN / VALIDATION**: the EXP-0016 pressure-bounds component **alone**, reproduced from the frozen, checksummed `pressure_bounds` tuple — the only cheaply and exactly reproducible piece of the combined rule outside the frozen TEST artifact.

This makes the TRAIN/VAL residual-positive class a mild **over-approximation** of the true (protocol+pressure+IF) residual: a handful of TRAIN/VAL windows the protocol rule or the Isolation Forest would independently have caught may be retained as "residual" there. It does not touch TEST (exact `comb_pred`) or the honest final TEST number (scored once, below). Also, per-window features use the **last** pressure sample ending in the window plus a trailing causal buffer, not a max-over-endings aggregate (EXP-0019/28/29's convention) — a completeness/compute tradeoff for a diagnostic probe, disclosed as a limitation.

## Method

Three feature families, kept separable in code (`ml/exp0032_admissible_ceiling_audit.py`):

- **F1** — numeric pressure + EXP-0019/20-style derivative (`last_pressure`, `abs_delta_predecessor`, `step_rate`): reused as a baseline sanity check, not expected to add anything new (and, per the closed EXP-0018/19/20 line, a single global-threshold rule on these features specifically failed).
- **F2** — IEEE-754 representation features: exponent, low-8-bit mantissa pattern, trailing zero-bit count, ULP distance to the nearest previously-observed TRAIN-normal value, distance to two independent candidate quantization/ADC-lattice grids, and local (trailing-buffer) low-mantissa-bit entropy.
- **F3** — event-level (per-window, trailing-30-sample-buffer) distribution features: quantiles q01..q99, two interquantile widths, skewness, kurtosis, unique-value count, exact-repetition rate, histogram entropy/occupancy, max gap between sorted unique values, and Wasserstein-1 distance to a capped (500-sample) TRAIN-normal reference distribution.

For each attack type (NMRI, CMRI) and each family (F1-only, F2-only, F3-only, combined), an `XGBClassifier` (150 estimators, depth 4, fixed seed) was trained on TRAIN (residual-positive vs pure-Normal), thresholded on VAL to keep Normal FPR ≤ 0.30%, then evaluated via:

- **Event-grouped VAL bootstrap** (60 resamples, fixed seed 0; whole contiguous-window episodes resampled together, never individual rows) → 95% CI on VAL recall at the fixed threshold.
- **Label-permutation null** (20 event-grouped TRAIN-label permutations, fixed seed 1, reduced from the spec's illustrative 50-200 for session compute-time tractability — 2 attack types × 4 families × 20 extra XGBoost fits — same disclosure convention as EXP-0028's `LIBRARY_MAX_SIZE` compute cap): retrain on scrambled TRAIN labels, refit the VAL threshold, recompute VAL recall, giving a null distribution of "how much recall a model gets by chance at this FPR budget."
- **TEST scored exactly once**, at the very end, for the combined model — an honest final number, **not** part of the decision rule (which is judged on VAL bootstrap vs the permutation null, per the fixed pre-registration).
- **Feature-causality audit** for the combined model's top-10-importance features.

## Results

### NMRI

| family | VAL recall (point) | VAL recall 95% CI | permutation null p95 | clears null |
|---|---:|---:|---:|---|
| F1 | 49.13% | [38.67%, 60.23%] | 1.24% | **True** |
| F2 | 12.72% | [8.57%, 18.61%] | 1.79% | **True** |
| F3 | 4.62% | [1.09%, 8.07%] | 0.58% | **True** |
| combined | 71.68% | [54.87%, 80.65%] | 0.00% | **True** |

Dominant feature in the combined model: **`ulp_distance_to_train_normal`** (importance 0.825, F2), by a wide margin over the next feature (`step_rate`, F1, importance 0.034). Causality audit clean (all top-10 features causal, egress-derived, no future data, no label leakage — see table below).

TEST scored once (combined model, VAL-fit threshold): recall **58.0%** (87/150 known false negatives recovered), Normal FPR **0.42%** (20/4,957) — informational only, not part of the decision rule.

### CMRI

| family | VAL recall (point) | VAL recall 95% CI | permutation null p95 | clears null |
|---|---:|---:|---:|---|
| F1 | 76.91% | [69.64%, 82.87%] | 2.72% | **True** |
| F2 | 14.80% | [9.27%, 20.75%] | 1.80% | **True** |
| F3 | 9.87% | [3.96%, 16.97%] | 0.71% | **True** |
| combined | 73.77% | [65.84%, 80.37%] | 0.72% | **True** |

Dominant feature in the combined model: **`ulp_distance_to_train_normal`** (importance 0.828, F2), same as NMRI. Causality audit clean.

TEST scored once (combined model, VAL-fit threshold): recall **80.5%** (438/544 known false negatives recovered), Normal FPR **0.60%** (29/5,351) — informational only, not part of the decision rule.

## Feature-causality audit (combined model, top 10 by importance, both attack types)

Every one of the top-10 contributing features for both NMRI and CMRI is: derived directly from the egress response frame's decoded pressure value (raw or IEEE-754 bit-level derived), uses no future data (all trailing-buffer/predecessor computations are strictly causal), and uses no label information indirectly. No `source`, `crc_rate`, filename, collection, or run-ID field is referenced anywhere in the feature code (enforced by `test_no_forbidden_fields_referenced`). **Causality audit: clean for both attack types.**

| feature | family | NMRI importance | CMRI importance | keep |
|---|---|---:|---:|---|
| `ulp_distance_to_train_normal` | F2 | 0.825 | 0.828 | yes |
| `step_rate` | F1 | 0.034 | 0.019 | yes |
| `abs_delta_predecessor` | F1 | 0.017 | 0.010 | yes |
| `last_pressure` | F1 | 0.008 | 0.009 | yes |
| `q99` / `q01` | F3 | 0.007 | 0.007-0.010 | yes |
| `unique_count` | F3 | 0.007 | - | yes |
| `histogram_occupancy` | F3 | 0.007 | 0.007 | yes |
| `mantissa_entropy_local` | F2 | 0.007 | - | yes |
| `q90` / `q05` | F3 | 0.006 | 0.008 | yes |
| `entropy` | F3 | 0.006 | 0.006 | yes |
| `max_gap` | F3 | - | 0.019 | yes |

## Decision-rule verdict (fixed before running; not amended after seeing results)

Bar: VAL event-grouped-bootstrap recall-at-≤0.30%-FPR 95% CI lower bound must exceed the label-permutation null's 95th percentile.

- **NMRI**: F2-only clears (8.57% > 1.79%); combined is dominated by F2 (`ulp_distance_to_train_normal`) and clears (54.87% > 0.00%); causality audit clean → **PROCEED-0030 condition satisfied**. F3-only also independently clears (1.09% > 0.58%), narrowly, with distinct winning features (quantile/entropy/max-gap statistics rather than the ULP-distance feature) → **PROCEED-0031 condition also satisfied**. Combined verdict: **PROCEED-BOTH**.
- **CMRI**: identical structure — F2-only clears (9.27% > 1.80%), combined dominated by F2 and clears (65.84% > 0.72%) → **PROCEED-0030**. F3-only clears (3.96% > 0.71%) → **PROCEED-0031**. Combined verdict: **PROCEED-BOTH**.

## Interpretation and honesty notes

- The dominant signal by a wide margin, for **both** attack types independently, is `ulp_distance_to_train_normal`: how far a decoded pressure value sits from the nearest *exact* value already observed in TRAIN-normal traffic. This is a coherent, physically plausible hypothesis: real sensor readings recur (quantization, repeated setpoints, ADC resolution), so genuine Normal traffic clusters on a a finite, TRAIN-observable set of float values, while forged/injected NMRI/CMRI values — even when chosen to fall inside the EXP-0016 global bounds and to look plausible on a raw-value or rate-of-change basis — are less likely to land exactly on a previously-seen value. This is exactly the EXP-0030 pre-registration's central hypothesis, and this probe gives it a first, non-fabricated, honestly-measured signal.
- F1 alone (raw pressure and its first-order derivative — the exact feature family EXP-0018/19/20 already tested with single-threshold rules) also clears the bar on its own, with a *materially higher* point estimate than F2 or F3 for CMRI (76.9%) and a high one for NMRI (49.1%). This is not a contradiction of the four prior NO-GOs: those experiments each tested one fixed, monotone, global threshold on one derived scalar (a percentile cutoff on `|Δp|/Δt`, or a fixed-variance AR(1) residual, etc.). A gradient-boosted classifier can carve **multiple, non-monotone regions** out of the same raw features (e.g., several disjoint pressure sub-ranges, each individually inside the EXP-0016 bounds, that are collectively over-represented in the forged-value population) — a genuinely different, more expressive hypothesis class than any of EXP-0018/19/20/28/29 tested, not the same rule re-run.
- **Caveat, disclosed rather than hidden**: this signal was measured against the *specific* attack-generation tooling used to build this one testbed's NMRI/CMRI captures. If that tooling has a systematic float-generation quirk (e.g., forged values computed in a different numeric pathway than the plant simulator, landing off the plant's natural float-value lattice more often than genuine sensor noise would), the classifier may be picking up a signature of *this generator*, not a property that is guaranteed to transfer to a different attacker's forging method. This is a legitimate, admissible, egress-observable signal (not testbed metadata, not a forbidden field) — but the causality audit's "keep: yes" answers whether the feature is *causally admissible*, not whether it is *guaranteed to generalize to a different attack tool*. This distinction is flagged explicitly for whoever picks up EXP-0030/0031: the pre-registration for either should include an explicit test of whether the ULP-distance signal survives if attacks are held out by *specific_attack* sub-type rather than only by contiguous time block.
- The TRAIN/VAL residual-cohort proxy (pressure-bounds-alone, see Adaptation above) is a real limitation: it does not filter out windows the protocol rule or the Isolation Forest would already catch, so the TRAIN/VAL "residual" population is not identical in composition to the exact TEST residual population. The TEST number (scored once, honest, not part of the decision rule) is reported specifically so this gap is visible: TEST recall (58.0% NMRI, 80.5% CMRI) is in the same ballpark as VAL recall (71.7% NMRI, 73.8% CMRI) but not identical, consistent with — not proof against — some TRAIN/VAL-vs-TEST cohort-composition drift from this proxy.
- The F3 (event-level distribution) clearance is comparatively weak for both attack types (4.6% / 9.9% point recall, narrow CIs sitting only just above a small null percentile) — a genuine but much fainter signal than F2's. `PROCEED-0031` is triggered by the letter of the fixed decision rule, but whoever pre-registers EXP-0031 should treat this as a weak positive, not a strong one, and budget accordingly.

## Deliverables

- `ml/exp0032_admissible_ceiling_audit.py` — diagnostic probe code (feature builders, event-grouped bootstrap/permutation, XGBoost probe, causality audit).
- `tests/test_exp0032_admissible_ceiling_audit.py` — 34 fast synthetic unit tests + 1 slow saved-result replay; all pass.
- `data/experiments/exp0032_admissible_ceiling_audit.json` — saved run output (status: `TESTED — DIAGNOSTIC PROBE; NO DETECTOR BUILT`).
- This file.
- No detector wiring diff produced (diagnostic only, per spec, regardless of verdict).

## Deliverables note (docs/overview.md)

The spec's fallback deliverable location `docs/overview.md` does not exist anywhere in this repository (confirmed, same finding as EXP-0028 and EXP-0029) — flagged rather than invented. This results file plus the `docs/EXPERIMENT_LOG.md` entry serve as the record instead.
