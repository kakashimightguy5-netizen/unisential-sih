# EXP-0030 — IEEE-754 float/representation-provenance detector — TESTED, NO-GO (FPR bar)

**Verdict: NO-GO for both NMRI and CMRI.** The underlying signal (`ulp_distance_to_train_normal`, an IEEE-754 float-representation feature) is confirmed to generalize on the FITTED model exactly as EXP-0032b found on the raw feature, and TEST recall improves for both attack types. But the pre-registered system-wide Normal-FPR bar (≤0.30%) is exceeded — **not primarily because of this rule**, but because the currently-wired combined detector's baseline FPR (0.832%, from EXP-0025) was already above 0.30% before this rule was ever added. Per the pre-registered decision rule ("no amendments after seeing TEST results"), this is scored as NO-GO as literally specified. **Nothing was wired into production code.**

Framing (used everywhere in this document, per pre-registration): this is **float/representation-provenance detection**, NOT physical-anomaly detection. The signal most likely reflects that forged pressure values were produced by a different quantization/generation pipeline than the real sensor, not a property of the physical process being measured.

Pressure is egress traffic extracted from Mississippi State ICS testbed dataset, used as a simulated diode-observer view — never real diode capture data. `ml/iforest_detector.run_detector` was NOT called or modified.

## ULP-distance metric — exact definition

`ulp_distance_to_train_normal(v)` is, despite its inherited name, the plain absolute-value distance

```
min(|v - r| for r in R)
```

where `R` is the sorted, deduplicated array of every raw float64 pressure value observed on TRAIN-normal egress `0x03` response frames (built once, TRAIN-only). It is **not** a ULP-count (units-in-the-last-place ordinal) metric — the name is inherited unchanged from `ml/exp0032_admissible_ceiling_audit.py`'s `ulp_distance_to_train_normal` column name and is called out explicitly here so it is never misread as a bit-level ULP count.

- **Nearest-neighbour lookup**: `np.searchsorted(R, v)` gives an insertion index; the predecessor (`idx-1`, clipped to `[0, len(R)-1]`) and successor (`idx`, clipped the same way) candidates are both compared, and the smaller absolute distance is returned (`nearest_reference_distance`, reused unchanged from EXP-0032).
- **Tie-breaking**: irrelevant in practice — only the minimum *distance* is ever returned, never an index or which neighbour "won"; if both candidates are equidistant the returned value is simply that common distance.
- **Unseen-exponent-range handling (extrapolation)**: values outside `R`'s observed range are **not** extrapolated. Because `searchsorted`'s index is clipped into `[0, len(R)-1]`, an out-of-range candidate's distance is computed purely against `R`'s minimum or maximum element — i.e., a value with an exponent (or magnitude) range TRAIN-normal never saw is scored by its distance to the nearest *edge* of the observed population, not given an artificially small "matches something" score. Verified in `tests/test_exp0030_float_provenance_detector.py::test_nearest_reference_distance_out_of_range_scores_against_nearest_edge`.

## Method (reused directly from EXP-0032/EXP-0032b, not re-approximated)

- **Residual cohort**: `FrozenCombinedWithRateDetector` (new, in `ml/exp0030_float_provenance_detector.py`) extends EXP-0032b's `FrozenExp0017Detector` with EXP-0025's `RateFloodRule` term, reproducing the **currently wired** combined detector — protocol OR pressure-bounds OR rate OR Isolation Forest — for TRAIN, VALIDATION, and TEST. Verified element-wise against the frozen `data/experiments/exp0025_detector.json` result before anything else is trusted:

  | check | result |
  |---|---|
  | `protocol_pred` matches | True |
  | `pressure_pred` matches | True |
  | `rate_pred` matches | True |
  | `if_pred` matches | True |
  | `comb_pred` matches | True |

  This is the "current wired baseline," not a stale EXP-0017-only baseline, per pre-registration.

- **Feature set**: F2 only (`exponent`, `mantissa_low_bits`, `trailing_zero_bits`, `ulp_distance_to_train_normal`, `quantization_distance`, `adc_lattice_distance`, `mantissa_entropy_local`), imported unchanged from `ml/exp0032_admissible_ceiling_audit.py`. F1 (plain numeric baseline) and F3 (event-level distribution features, ruled out in EXP-0032b as run-dependent) are excluded per pre-registration.
- **Model**: one `XGBClassifier` per attack type (NMRI, CMRI), `n_estimators=150, max_depth=4, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8, reg_lambda=1.0, random_state=0`, trained on TRAIN's residual cohort (windows the current wired rule misses) vs Normal.
- **Threshold**: fit on VALIDATION Normal scores to keep VAL Normal FPR ≤ 0.30% (`MAX_NORMAL_FPR`), same convention as EXP-0032/0032b.
- **VAL event-grouped bootstrap** (60 resamples, reduced from the spec's illustrative 200 for session compute-time tractability — same disclosed convention as EXP-0032) vs a label-permutation null (20 draws, reduced from 50-200 for the same reason):

  | attack | VAL recall (point) | VAL recall 95% CI | clears permutation null |
  |---|---:|---:|---|
  | NMRI | 11.70% | [5.40%, 17.50%] | True |
  | CMRI | 24.26% | [16.78%, 30.51%] | True |

  (These low VAL point-recall numbers are expected and match EXP-0032b exactly: F2 alone recovers only a minority of the residual cohort — the combined detector's F1+F2+F3 model recovered far more in EXP-0032b's diagnostic. This experiment builds F2 alone, per pre-registration item 1, since F2 is the only family that survived EXP-0032b's leave-one-run-out check.)

- **Leave-one-attack-run-out on the FINAL FITTED model** (not just the raw feature): the deterministic refit (same `XGB_PARAMS`, seed 0, deterministic data ordering) was independently reproduced and its VAL recall matched the reported point estimate exactly (`refit_reproduces_reported_val_recall: True` for both attacks — confirms the model handed to the wiring step is the same model whose VAL statistics were reported).

  | attack | runs evaluated | mean recall | std | min | max | run-dependent? |
  |---|---:|---:|---:|---:|---:|---|
  | NMRI | 66 | 94.06% | 9.59% | 50.0% | 100% | **False** |
  | CMRI | 107 | 95.29% | 8.13% | 50.0% | 100% | **False** |

  **This matches EXP-0032b's raw-feature finding almost exactly (94.06%/95.29% mean vs EXP-0032b's 94.06%/95.29%)** — no measurable degradation from raw feature to fitted detector. The fitted model generalizes to held-out attack episodes never seen during that fold's training, exactly as strongly as the raw feature did.

## TEST — scored once

**Baseline (currently wired: protocol OR pressure OR rate OR IF, from `exp0025_detector.json`):**

| tn | fp | fn | tp | FPR | recall |
|---:|---:|---:|---:|---:|---:|
| 4767 | 40 | 2166 | 2374 | 0.832% | 52.29% |

**With the float-provenance rule OR-ed in (both NMRI-model and CMRI-model fire → rule fires):**

| tn | fp | fn | tp | FPR | recall |
|---:|---:|---:|---:|---:|---:|
| 4740 | 67 | 1923 | 2617 | 1.394% | 57.64% |

**Marginal contribution of adding this rule alone:** +243 TP, +27 FP (a ~9:1 TP:FP ratio — a reasonable trade by the EXP-0017 attribution standard on its own terms). **But the system-wide FPR bar is judged on the resulting ABSOLUTE FPR (1.394%), not the marginal delta**, and the baseline itself (0.832%) already exceeded the 0.30% bar before this rule was added.

**Pure-cohort recall, NMRI and CMRI separately:**

| attack | n (TEST, pure cohort) | baseline recall | new recall | recall gain | historical pressure-rule-only ceiling (legibility anchor) |
|---|---:|---:|---:|---:|---:|
| NMRI | 715 | 79.02% | 83.50% | +4.48pp | 79.02% |
| CMRI | 1198 | 54.59% | 66.61% | +12.02pp | 54.59% |

Both categories show a real recall improvement over the CURRENT wired baseline (which is already higher than the historical pressure-rule-only ceiling for NMRI, since the wired baseline includes rate+IF too).

## Decision-rule application (fixed before running; not amended after seeing results)

| attack | recall improves? | clears VAL permutation-null bar? | LORO generalizes (fitted model)? | system-wide FPR bar holds? | qualifies for wiring? |
|---|---|---|---|---|---|
| NMRI | True | True | True | **False** | **False** |
| CMRI | True | True | True | **False** | **False** |

**Overall verdict: NO-GO (system-wide FPR bar exceeded).**

Per the pre-registered decision rule's literal wording ("combined-detector Normal FPR must stay ≤ 0.30% after adding this rule"), this is scored as NO-GO for both categories, because the resulting ABSOLUTE combined-detector FPR (1.394%) exceeds 0.30%. Every other gate (recall improvement, VAL permutation-null bar, leave-one-run-out generalization on the fitted model) passes cleanly for both NMRI and CMRI — the rule itself is not the failure mode.

## Honesty notes (why this is NO-GO despite every other signal being positive)

- **The FPR bar was already broken before this rule existed.** The currently-wired baseline (EXP-0025: protocol OR pressure OR rate OR IF) has a TEST Normal FPR of 0.832%, already 2.8× the 0.30% bar this pre-registration inherited from EXP-0032/0032b's diagnostic threshold-fitting convention. That 0.30% figure was never re-validated as an appropriate SYSTEM-WIDE bar for the current combined detector at the time this experiment was pre-registered — it is the per-classifier VAL-threshold-fitting convention EXP-0032/0032b used for a diagnostic probe, not a system-level SLA that was checked against the current wired baseline before this experiment began. This is disclosed honestly as a **specification gap discovered during execution**, not something quietly patched: per "no amendments after seeing TEST results," it is not corrected here.
- **The rule's own marginal contribution is reasonable on its own terms**: +243 TP for +27 FP (TEST), and the leave-one-run-out generalization on the actual fitted model reproduces EXP-0032b's raw-feature finding to within noise (94.06%/95.29% vs 94.06%/95.29%) — this is strong, disclosed evidence the underlying signal and the fitted detector built on it are sound. The NO-GO verdict here is a statement about the pre-registered bar's applicability to the CURRENT wired baseline, not about the float-provenance signal's validity.
- If this line of work is revisited, the correct next step is a **fresh pre-registration** that either (a) re-derives an appropriate system-wide FPR bar from the current wired baseline's own FPR (e.g., "no more than +0.30pp above the current wired baseline's FPR" instead of an absolute 0.30% cap), or (b) tightens the per-attack classifier threshold further (at a cost to the already-modest VAL recall shown above) — this experiment does not attempt either, per the "no amendments" discipline.
- Two separate per-attack-type XGBoost classifiers are OR-ed at inference (the rule cannot know the true attack category ahead of time); this mirrors how EXP-0032b evaluated NMRI/CMRI separately and is disclosed as the inference-time design.
- Bootstrap (60) and permutation (20) counts are reduced from the spec's illustrative 200/50, same disclosed convention as EXP-0032, for session compute-time tractability.
- Leave-one-run-out pools TRAIN+VAL for training (inherited from `exp0032b_ceiling_audit_corrected.leave_one_run_out`; disclosed there, not re-approximated here).
- Pressure is the ARFF-aligned value, not a live `0x03` byte decode; register map/scale undocumented. One testbed; egress-only; measurement only.
- `docs/overview.md` does not exist in this repo (same finding as EXP-0028/0029); no such file was created or updated as a side effect.

## Deliverables

- `ml/exp0030_float_provenance_detector.py` — the detector build (new file). Reuses `F2_NAMES`, `SeriesIndex`, `build_cohort_frame`, `window_row`, `nearest_reference_distance` from `ml/exp0032_admissible_ceiling_audit.py`, and `FrozenExp0017Detector`, `_dataset_for`, `_run_family`, `leave_one_run_out` from `ml/exp0032b_ceiling_audit_corrected.py`, unchanged.
- `tests/test_exp0030_float_provenance_detector.py` — fast synthetic unit tests (ULP-distance metric edge cases, decision-rule aggregation, a source-level guard that this module never calls/imports `run_detector`) plus a slow saved-result replay.
- `data/experiments/exp0030_float_provenance_detector.json` — saved run output (actual run).
- This file.
- `docs/EXPERIMENT_LOG.md` — EXP-0030 entry appended (append-only).
- **No production code was modified.** `ml/rules.py` and `ml/iforest_detector.py` are untouched — per the pre-registered decision rule, wiring only happens on GO/PARTIAL-GO, and this is NO-GO.
- Full existing test suite: 399/400 passing before and after this change (the one failure, `test_exp0017_operational.py::test_dashboard_uses_saved_result_with_pressure_limitation`, is a pre-existing environment issue — a `pyarrow` DLL blocked by a local Windows Application Control policy — unrelated to this experiment; confirmed by the fact that no file it depends on was modified in this session).
