# EXP-0032b — CORRECTED admissible-information ceiling audit — TESTED, PROCEED-0030 (NMRI and CMRI); PROCEED-0031 RETRACTED for both

**Final verdict: PROCEED-0030 for NMRI and PROCEED-0030 for CMRI.** EXP-0032's original `PROCEED-BOTH` (for both attack types) does **NOT** fully survive this corrected re-run. The EXP-0030 (IEEE-754/float-provenance, `ulp_distance_to_train_normal`) signal is confirmed robust after all three corrections. The EXP-0031 (event-level distribution fingerprint) signal is **not confirmed**: it clears the (weak) permutation-null bar for CMRI exactly as EXP-0032 found, but fails Fix 3's leave-one-attack-run-out generalization check for **both** attack types — it is a real but run-dependent effect, not a stable admissible signal. Per the pre-registered amendment, this verdict is final; no further amendments to this line.

Pressure is egress traffic extracted from Mississippi State ICS testbed dataset, used as a simulated diode-observer view — never real diode capture data. `ml/iforest_detector.run_detector` was NOT modified and NOT called anywhere in this module.

## Why this amendment existed

EXP-0032 (`docs/experiments/EXP-0032_RESULTS.md`) found `PROCEED-BOTH` for NMRI and CMRI, but disclosed three specific weaknesses in its own write-up:

1. **Cohort mismatch**: TEST used the exact frozen `comb_pred` (protocol OR pressure-bounds OR Isolation Forest), but TRAIN/VALIDATION used a pressure-bounds-only proxy, because reproducing the full combined rule for TRAIN/VAL would have required calling `run_detector`, which was off-limits. The pre-registered decision rule is judged on VAL, so it ran on the *wrong* (looser) cohort.
2. **Weak controls**: 60 bootstrap resamples (spec asked for 200) and 20 permutation draws (spec asked for 50-200).
3. **No generalization check** for the dominant feature `ulp_distance_to_train_normal` (~0.83 importance) — a feature this strong could be genuine float-provenance, or an artifact of one specific attack-generation tool's runs (the same structural risk class as this project's known `source==3` DoS leak).

## Fix 1 — corrected residual cohort

`FrozenExp0017Detector` (new, in `ml/exp0032b_ceiling_audit_corrected.py`) reproduces EXP-0017's real combined rule — protocol OR pressure-bounds OR Isolation Forest — for **TRAIN, VALIDATION, and TEST**, not just TEST. It reuses every frozen, checksummed scalar from the EXP-0017 artifact unchanged (`mu`, `sd`, `threshold`, `valid_func_codes`, `valid_addresses`, `pressure_bounds`) and refits only the Isolation Forest itself in-process, with identical hyperparameters (`n_estimators=300, max_samples="auto", contamination="auto"`) and the identical fixed seed (0) `iforest_detector.run_detector` uses. This is the same pattern EXP-0016's `FrozenExp0004Detector` already established for EXP-0004.

**Identity gate (all passed, verified before anything else ran):**

| check | result |
|---|---|
| `if_pred` matches frozen TEST array element-wise | True |
| `protocol_pred` matches frozen TEST array element-wise | True |
| `pressure_pred` matches frozen TEST array element-wise | True |
| `comb_pred` matches frozen TEST array element-wise | True |
| whole-TEST confusion == EXP-0017 frozen (4767, 40, 2166, 2374) | True |

Because the refit Isolation Forest reproduces the frozen artifact's TEST predictions *exactly*, element-wise, this is strong evidence the same deterministic refit is faithful on TRAIN/VAL too (there is no independent frozen array to check TRAIN/VAL against directly — this is disclosed as a residual limitation, not hidden).

**Cohort-size effect, corrected vs EXP-0032's proxy:**

| cohort | EXP-0032 proxy (pressure-bounds-only) | EXP-0032b corrected (true comb_pred) | delta |
|---|---:|---:|---:|
| NMRI TRAIN | 558 | 556 | -2 |
| NMRI VAL | 173 | 171 | -2 |
| CMRI TRAIN | 1316 | 1302 | -14 |
| CMRI VAL | 446 | 441 | -5 |

**Honest finding on Fix 1's effect size: small.** The pressure-bounds-only proxy over-approximated the true residual cohort by only 2-14 rows (≤1.1% of cohort size) — the protocol rule and Isolation Forest independently catch very few of the windows the pressure-bounds rule alone missed, in this specific residual population. EXP-0032's disclosed cohort-mismatch limitation was real but numerically minor; it is not what changes the final verdict below (Fix 3 is what changes it).

## Fix 2 — restored control strength

Bootstrap resamples restored to the full spec value (200; cheap, since bootstrap only resamples already-computed scores, no refit). Permutation draws restored to 50 — the spec's disclosed low end of its 50-200 range, for session compute-time tractability (every permutation draw refits an XGBoost model, ×2 attack types ×4 families; the full run took ~751s). Both the original weak counts (60/20) and the restored counts (200/50) were run on the *same corrected cohort* and compared.

| attack | reduced (60/20) verdict | full (200/50) verdict | stable? |
|---|---|---|---|
| NMRI | PROCEED-0030 | PROCEED-0030 | **True** |
| CMRI | PROCEED-BOTH | PROCEED-BOTH | **True** |

**Honest finding: control-strength did not flip either verdict** (verdicts shown here are *before* Fix 3's LORO gate — see below). Both weak and restored controls agree that F2 clears the permutation-null bar for both attacks, and F3 clears for CMRI only (not NMRI, in either configuration).

### Full-strength (200 bootstrap / 50 permutation) per-family results

**NMRI** (n_train_positive=556, n_val_positive=171, n_test_positive=150):

| family | VAL recall (point) | VAL recall 95% CI | permutation null p95 | clears null | TEST recall (once) | TEST normal FPR |
|---|---:|---:|---:|---|---:|---:|
| F1 | 49.71% | [39.45%, 61.17%] | 1.17% | True | 28.00% | 0.437% |
| F2 | 11.70% | [5.71%, 17.75%] | 3.30% | True | 6.67% | 0.208% |
| F3 | 3.51% | [0.00%, 8.16%] | 1.55% | **False** | 6.67% | 0.416% |
| combined | 78.36% | [65.97%, 89.14%] | 1.17% | True | 60.00% | 0.478% |

**CMRI** (n_train_positive=1302, n_val_positive=441, n_test_positive=544):

| family | VAL recall (point) | VAL recall 95% CI | permutation null p95 | clears null | TEST recall (once) | TEST normal FPR |
|---|---:|---:|---:|---|---:|---:|
| F1 | 77.32% | [70.10%, 84.97%] | 4.65% | True | 79.23% | 0.437% |
| F2 | 24.26% | [17.14%, 30.70%] | 2.85% | True | 19.67% | 0.395% |
| F3 | 11.11% | [3.25%, 19.42%] | 2.39% | True | 5.88% | 0.250% |
| combined | 69.16% | [60.17%, 78.24%] | 2.17% | True | 76.47% | 0.707% |

Dominant feature in both combined models: `ulp_distance_to_train_normal` (F2), importance 0.818 (NMRI) / 0.822 (CMRI) — consistent with EXP-0032. Causality audit: clean for both (every top-10-importance feature is derived from the egress pressure value, strictly causal, no label leakage, no forbidden field).

## Fix 3 — leave-one-attack-run-out generalization check (the check that actually changes the verdict)

For F2 (`ulp_distance_to_train_normal`) and F3 (distribution features), residual-positive rows were pooled across TRAIN+VAL (disclosed simplification for this sub-check only — the VAL-bootstrap numbers above never train on VAL) and grouped into contiguous-window-index "runs" (same grouping unit the bootstrap uses). For every run with ≥3 examples, the family model was retrained with that run's examples excluded, and the run's OWN held-out recall was measured (threshold fit to keep Normal FPR ≤ 0.30% on the remaining pool).

| attack | family | runs evaluated | mean recall | std | min | max | run-dependent? |
|---|---|---:|---:|---:|---:|---:|---|
| NMRI | F2 | 66 | 94.06% | 9.59% | 50.0% | 100% | **False** |
| NMRI | F3 | 66 | 17.65% | 26.61% | 0.0% | 100% | **True** |
| CMRI | F2 | 107 | 95.29% | 8.13% | 50.0% | 100% | **False** |
| CMRI | F3 | 107 | 22.53% | 34.40% | 0.0% | 100% | **True** |

(`run-dependent` flags per-run recall standard deviation > 0.25, a disclosed heuristic.)

**F2 (`ulp_distance_to_train_normal`) generalizes strongly and consistently.** Across 66 (NMRI) and 107 (CMRI) *distinct held-out attack episodes* — never seen during that fold's training — recall never drops below 50% and averages ~94-95%. This is real evidence the ULP-distance signal is not a signature of one specific attack-generation run: it survives removal of any single run from training and still detects that same run when held out.

**F3 (distribution/quantile features) is confirmed run-dependent.** Per-run recall ranges from 0% to 100% with a standard deviation of 27-34 percentage points — exactly the profile of a feature that works great on some attack episodes and not at all on others, i.e. it is picking up something specific to individual runs rather than a stable population-level property. This matches EXP-0032's own honesty note ("F3's clearance is comparatively weak... should be treated as a weak positive, not a strong one") — Fix 3 turns that qualitative caution into a quantitative disqualification.

## Corrected decision-rule application

Each verdict component (PROCEED-0030 via F2, PROCEED-0031 via F3) is now gated by **its own** family's LORO result, not just whichever family happens to dominate the combined model's feature importances (a gap in an earlier draft of this correction — the combined model is F2-dominated for both attacks, but CMRI's F3-only result independently clears the permutation-null bar and must be checked against F3's *own* LORO result, not waved through on F2's).

| attack | PROCEED-0030 (F2) before LORO | F2 generalizes | PROCEED-0030 final | PROCEED-0031 (F3) before LORO | F3 generalizes | PROCEED-0031 final | **Final verdict** |
|---|---|---|---|---|---|---|---|
| NMRI | True | True | **True** | False | False (N/A, never cleared) | False | **PROCEED-0030** |
| CMRI | True | True | **True** | True | **False** | **False** | **PROCEED-0030** |

## Verdict

**PROCEED-0030 for NMRI. PROCEED-0030 for CMRI.** `PROCEED-0031` is **not** supported for either attack type after Fix 3.

This is a **partial reversal** of EXP-0032's `PROCEED-BOTH` finding, honestly reported: the EXP-0030 (float-provenance, `ulp_distance_to_train_normal`) candidate is *more* solidly supported than EXP-0032 knew (cohort-corrected, control-restored, and now generalization-tested across dozens of held-out attack episodes with no run-dependence). The EXP-0031 (event-level distribution fingerprint) candidate does **not** survive the generalization check and should not be pre-registered as a detector build on the strength of EXP-0032's finding alone.

Per the pre-registered amendment this verdict is final for this line: no further amendments. EXP-0030 (float-provenance detector) is a legitimate candidate for a future, separate pre-registration and detector build — this experiment remains a diagnostic probe; nothing was wired. EXP-0031 should not be separately pre-registered on this evidence; if anyone wants to revisit event-level distribution features later, they would need a fundamentally different, non-run-dependent formulation, not this one.

## Honesty notes

- Fix 1's cohort-mismatch effect size was small (≤14 rows, ≤1.1% of cohort) — it was a real, disclosed methodological flaw, but not the reason the verdict changed.
- Fix 2's control-strength restoration did not flip either attack's pre-LORO verdict — the original weak counts (60/20) happened not to produce a fragile answer here.
- Fix 3 is what changed the outcome: it is exactly the check EXP-0032's own honesty notes flagged as missing ("whether it generalizes to a different forging method is flagged explicitly as unresolved"), and it found a real, quantifiable difference between F2 (generalizes) and F3 (does not).
- The Isolation Forest in `FrozenExp0017Detector` is refit, not loaded from a serialized object (none exists in the frozen artifact). Its exact TEST element-wise match against the frozen `if_pred` is the strongest available evidence the refit is faithful on TRAIN/VAL too, but it is evidence, not a stored object — disclosed as a residual limitation.
- The leave-one-attack-run-out check pools TRAIN+VAL for training (disclosed, specific to this sub-check); the primary VAL-bootstrap decision numbers above never train on VAL.
- `run_detector()` was NOT called and NOT modified anywhere in this module or this session.
- One testbed; egress-only; measurement only; no detector was built or wired.

## Deliverables

- `ml/exp0032b_ceiling_audit_corrected.py` — corrected diagnostic probe (new file; `ml/exp0032_admissible_ceiling_audit.py` is untouched, historical record).
- `tests/test_exp0032b_ceiling_audit_corrected.py` — 13 fast synthetic unit tests + 1 slow saved-result replay.
- `data/experiments/exp0032b_ceiling_audit_corrected.json` — saved run output (actual run, ~751s).
- This file.
- `docs/EXPERIMENT_LOG.md` — EXP-0032b entry appended (append-only; EXP-0032's original entry is untouched).
- No detector wiring diff produced (diagnostic only, per spec, regardless of verdict).
