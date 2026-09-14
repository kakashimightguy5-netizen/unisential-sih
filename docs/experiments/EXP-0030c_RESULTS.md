# EXP-0030c — CMRI-only float-provenance rule: production wiring — GO, wired

Turns EXP-0030b's CMRI-only paper verdict (isolated marginal trade ratio worst-case 5.33:1, GO) into a real production artifact: a materialized F2 (IEEE-754 bit-structure) feature pipeline, a retrained + serialized CMRI-only XGBoost classifier, a versioned TRAIN-normal reference set, and a new OR-term wired into `ml/rules.py` / `ml/iforest_detector.py`.

**CMRI ONLY.** NMRI is explicitly out of scope per EXP-0030b's decision (isolated ratio worst-case 1.19:1, NO-GO) and is not built, fit, or wired anywhere in this experiment.

Pressure is egress traffic extracted from Mississippi State ICS testbed dataset, used as a simulated diode-observer view — never real diode capture data.

## Ordering irregularity, flagged explicitly

This experiment was **not pre-registered in `docs/EXPERIMENT_LOG.md` before it was run** — the orchestrator's task brief arrived with the method already specified and user-approved decisions already made, and I (the implementation agent) began Method step 1 (precondition checks) before any PLANNED entry existed. Per this project's standing workflow ("pre-registration first"), this is out of the normal order. Both a PLANNED entry (dated as of this run, 2026-09-14) and the TESTED entry are appended together to `docs/EXPERIMENT_LOG.md` in this session, and this irregularity is disclosed here and in that log rather than smoothed over.

## Precondition 1 — isolated CMRI-only FP cost (this experiment's own single TEST touch)

Per the user-approved decision, precondition 1 is answered by this experiment's own retrain -> serialize -> score pipeline, not by a separate pre-check. Because only the CMRI classifier is built here (no NMRI model exists in this experiment to share/conflate false positives with), the isolated marginal ratio is **exact, not a worst-case bound**:

| | tn | fp | fn | tp | fpr | recall |
|---|---:|---:|---:|---:|---:|---:|
| baseline (protocol\|pressure\|rate\|IF, EXP-0025 wired) | 4767 | 40 | 2166 | 2374 | 0.832% | 52.29% |
| baseline OR CMRI-only float-provenance rule | 4749 | 58 | 2002 | 2538 | 1.207% | 55.90% |
| **isolated marginal** | — | **+18** | — | **+164** | | |

**Isolated ratio: 164 / 18 = 9.11:1** — clears the 3:1 bar and is **stronger than EXP-0030b's worst-case 5.33:1 bound**, as expected: EXP-0030b's 5.33:1 pessimistically charged CMRI with the FULL combined +27 FP that was actually shared with an NMRI classifier; that NMRI classifier does not exist in this experiment, so there is nothing left to conflate CMRI's FP with. This is the exact number, not a bound.

CMRI pure-cohort recall: 54.59% -> 63.52% (+8.93pp; n=1198). This is a smaller gain than EXP-0030/0030b's combined NMRI+CMRI figure (54.59%->66.61%) because this experiment's rule is CMRI-only — some of EXP-0030's combined gain on CMRI-labelled-but-mixed windows came from the NMRI classifier also firing on them. That is expected and not a discrepancy.

Total resulting FPR: baseline 0.832% -> 1.207% with the CMRI-only rule added (vs EXP-0030b's 1.394% for the combined NMRI+CMRI rule — lower here because only one classifier's FP is contributing). **Flagged for the human's demo-readiness/precision trade-off decision, not auto-decided.**

## Precondition 2 — independent confirmation of the "known failing test" (result: does NOT reproduce)

Ran `git stash -u` to revert to the pre-EXP-0030c state (the only uncommitted changes present were the pre-existing untracked EXP-0021..0032b files and one `docs/EXPERIMENT_LOG.md` modification, all already disclosed as pre-existing in the orchestrator's task context — no unrelated changes were present, so the stash proceeded as a single unit per the approved instruction).

```
tests/test_exp0017_operational.py::test_dashboard_uses_saved_result_with_pressure_limitation PASSED [100%]
1 passed in 11.35s
```

Re-ran on the restored (post-`git stash pop`) state:

```
tests/test_exp0017_operational.py::test_dashboard_uses_saved_result_with_pressure_limitation PASSED [100%]
1 passed in 9.77s
```

Full suite on the restored state: **400 passed in 51.86s — zero failures.**

**This contradicts the task's premise** that this test was a known-failing pyarrow/Windows-DLL issue. The coordinator confirmed with the user mid-session that this finding is correct and accepted, that the memory note was stale, and corrected it. **New baseline for this experiment: 400/400 passing is the "no regressions" bar**, not "400 passing + 1 known failure." This is used below.

## Identity ledger refresh (`exp0017_detector.json` and `exp0025_detector.json`)

Both files' `identity.source_sha256` ledgers track `ml/rules.py` and `ml/iforest_detector.py` (both edited to add the CMRI OR-term). Following EXP-0025's exact pattern (envelope = `{"sha256": <hash of payload>, "payload": {...}}`), for each file:

1. Loaded the envelope, verified the existing `sha256` matched the existing `payload` (sanity pre-check) — **passed** for both files before any edit.
2. Updated ONLY `payload.identity.source_sha256["ml/rules.py"]` and `payload.identity.source_sha256["ml/iforest_detector.py"]` to the new file hashes. Every other key in `payload` — most importantly `payload.result` (every prediction array, mu/sd/threshold, rule_hits, etc.) — was left byte-for-byte untouched.
3. Recomputed the envelope `sha256` over the modified `payload` and rewrote the file.
4. Verified via a structural diff against the pre-refresh `git show HEAD:...` version that **only** `/sha256`, `/payload/identity/source_sha256/ml/iforest_detector.py`, and `/payload/identity/source_sha256/ml/rules.py` changed — confirmed for both files.
5. Confirmed `exp0017_operational.load_result()` and `exp0025_dos_rate_rule.load_detector_result()` both succeed after the refresh (both are called, successfully, inside `ml/exp0030c_cmri_production_wiring.py::run_experiment()` — see below).
6. Ran the full test suite (see counts below), including `tests/test_ack001*.py`, `tests/test_ack002*.py`, `tests/test_exp0021*.py`, `tests/test_exp0022*.py` and everything else that depends on either identity gate — all still pass.

`data/experiments/exp0025_detector.json` was not named in the task brief's checksum list but has the identical structural dependency (it also SHA-256-tracks `ml/rules.py` / `ml/iforest_detector.py` in its own envelope) and would otherwise break `exp0025_dos_rate_rule.load_detector_result()`; it was refreshed with the exact same procedure and disclosed here rather than silently worked around.

## Method executed (steps 2-7, in one pass, single final TEST touch)

Implemented in `ml/exp0030c_cmri_production_wiring.py`, run via `py -3 ml/exp0030c_cmri_production_wiring.py`.

1. **True combined-detector reproduction** — `FrozenCombinedWithRateDetector` (imported unchanged from `exp0030_float_provenance_detector.py`) reproduces protocol OR pressure OR rate OR IF for TRAIN/VAL/TEST, gated element-wise against the frozen EXP-0025 artifact. **All 5 gate checks passed** (`protocol_pred_matches`, `pressure_pred_matches`, `rate_pred_matches`, `if_pred_matches`, `comb_pred_matches` — all `true`).
2. **TRAIN-normal reference artifact** — `ml/float_provenance_features.py::build_train_normal_reference` built `R` (2387 sorted, deduplicated raw float64 TRAIN-normal `0x03` pressure values) from the frozen manifest split (`verified-egress-5s-exp0008-pretest-v1`), and `save_reference` persisted it to `data/experiments/exp0030c_train_normal_reference.json`. Independently re-derived from scratch inside the same run and compared element-wise to the version used for feature computation: **identical (`reference_reproducible_from_scratch: true`)**.
3. **CMRI residual cohort, F2 only** — via `build_cohort_frame` (unchanged import, `exp0032_admissible_ceiling_audit`) and `_dataset_for` (unchanged import, `exp0032b_ceiling_audit_corrected`), restricted to `cmri_pure` windows the TRUE combined rule already misses. TRAIN: 16253 rows (1302 positive). VAL: 5293 rows (441 positive).
4. **Retrain** — `XGBClassifier(**XGB_PARAMS)` (unchanged hyperparameters from EXP-0032/0032b/0030) fit on TRAIN; threshold fit on VAL to keep Normal FPR <= `MAX_NORMAL_FPR` (0.30%). Achieved VAL FPR: 0.268%. VAL recall at that threshold: 24.26% (a much stricter operating point than the combined-cohort numbers reported later, because this is VAL-Normal-only threshold-fitting on the residual cohort — the same convention EXP-0030/0032b used, not a new methodology).
5. **Serialize** — `clf.save_model()` (XGBoost's native JSON format) to `data/artifacts/exp0030c_cmri_float_provenance_model.json`, plus a sidecar metadata file (`..._model_meta.json`) with threshold, feature order, xgboost/python versions, and a SHA-256 of the model file. **Fixed a real bug found during this step**: the temp-file rename pattern (`model_path.with_suffix(".json.tmp")`) broke XGBoost's filename-extension-based format inference (it silently saved UBJSON instead of JSON, which then failed to reload) — fixed to `model_path.with_name(stem + ".tmp" + suffix)`, verified by successful reload.
6. **Leave-one-attack-run-out**, on this freshly retrained model's data (`leave_one_run_out`, unchanged import from `exp0032b_ceiling_audit_corrected`, F2/cmri_pure): **107 runs evaluated, mean recall 95.29%, std 8.13%, `run_dependent: False`** — numerically identical to EXP-0030b's cited CMRI LORO figures, as expected (same underlying TRAIN+VAL data and method; this is a fresh execution on the newly retrained data, not a copy of the old number).
7. **Round-trip + score TEST once** — loaded the model back from the serialized artifact (`load_model`), confirmed `threshold_matches: true`, `feature_names_match: true`, `reference_matches: true`. Built `rules.CmriFloatProvenanceRule` from the loaded model. Batch-scored all TEST F2 rows; independently cross-checked the production `evaluate()`-per-window path against the batch path on a 50-window sample — **`evaluate_path_matches_batch_scoring_sample: true`**. Combined with the frozen EXP-0025 `comb_pred` via a plain OR (see Precondition 1 table above for the resulting confusion matrices).

## GO / NO-GO

**Decision rule (fixed before running):** GO iff isolated ratio >= 3:1 AND leave-one-run-out generalizes (`n_runs_evaluated >= 2 and run_dependent is False`).

| check | result |
|---|---|
| Isolated marginal ratio | **9.11:1** (>= 3:1 bar) |
| Leave-one-run-out generalizes | **True** (107 runs, mean 95.29%, std 8.13%, not run-dependent) |
| **Verdict** | **GO — CMRI-only float-provenance rule wired into production** |

`ml/rules.py` and `ml/iforest_detector.py` remain wired (not reverted) — no unwind step needed.

## Production wiring summary

- New rule class: `rules.CmriFloatProvenanceRule` (loads a fitted model + threshold + feature order; `evaluate(feature_row)` -> `RuleHit`, matching the existing `RateFloodRule`/`PressureBoundsRule` interface pattern).
- New production feature module: `ml/float_provenance_features.py` (`f2_row`, `build_train_normal_reference`, `save_reference`/`load_reference`, `save_model`/`load_model`). Imports the pure, stable, side-effect-free IEEE-754 helpers (`ieee754_bits`, `nearest_reference_distance`, `quantization_grid_distance`, `mantissa_low_bits_entropy`, `F2_NAMES`, `SeriesIndex`) unchanged from `ml/exp0032_admissible_ceiling_audit.py` (not duplicated — rationale documented in the module docstring: duplicating would create a second copy that could silently drift); re-derives only the F2-row assembly itself, since EXP-0032's `window_row` computes F1+F2+F3 together and this production path doesn't need the F1/F3 machinery. `ml/exp0032_admissible_ceiling_audit.py` itself was NOT edited.
- New `DetectorResult.cmri_float_pred` field (default empty array — non-breaking for every existing frozen `DetectorResult(**data)` load site, since the field has a default and the key is simply absent from old saved JSON).
- `ml/iforest_detector.run_detector()` now permanently includes the CMRI-only rule as a fourth deterministic OR-term (protocol OR pressure OR rate OR CMRI-float, then OR IF) for any FUTURE fresh run. It was **not called this session** (`run_detector_called_this_session: false`) — this experiment's reported numbers are a closed-form combination of the frozen EXP-0025 arrays plus the freshly-scored CMRI-float term, exactly mirroring EXP-0025's own pattern relative to EXP-0017.
- Versioned artifacts: `data/experiments/exp0030c_train_normal_reference.json` (TRAIN-normal reference set; refreshable — safe to regenerate whenever TRAIN data or the manifest split changes, documented in the module docstring, unlike the TEST-scored-once ledgers elsewhere in this project which must never be regenerated), `data/artifacts/exp0030c_cmri_float_provenance_model.json` + `..._model_meta.json` (serialized classifier).
- Full run output: `data/experiments/exp0030c_cmri_production_wiring.json`.

## Test suite: before/after

- **Before this session's code changes: 400/400 passing** (confirmed as part of Precondition 2, on the reverted/pre-EXP-0030c state — this is the corrected baseline, per the coordinator's mid-session correction).
- **A real regression was found and fixed during this work**: `tests/test_exp0017_operational.py::test_synthetic_pipeline_fits_train_normal_only_and_test_changes_do_not_tune` failed after wiring the CMRI rule into `run_detector()`, because it exercises `run_detector()` on a fully synthetic fixture and the new CMRI code path tried to read real raw data (`align_egress_pressure_timeseries()`'s SHA-256 check against the real TXT file) that this synthetic test correctly forbids. Fixed by extending the test's existing monkeypatch pattern (which already patches `align_egress_pressure`/`begin_evaluation`/etc. at the source-module level, relying on `run_detector`'s lazy `from X import Y` imports to pick up patched attributes at call time) to also patch `exp0019_pressure_rate_plausibility.align_egress_pressure_timeseries`, `float_provenance_features.load_reference`, and `float_provenance_features.load_model`. With an empty synthetic series, every synthetic window has no "own pressure sample", so `f2_row` returns `None` for all of them and the CMRI rule fires `False` everywhere — it does not otherwise perturb this test's assertions (pressure bounds, mu/sd/threshold reproducibility).
- **After all changes: 420/420 passing** (400 pre-existing + 20 new tests in `tests/test_float_provenance_features.py` and `tests/test_exp0030c_cmri_production_wiring.py`), **zero regressions** against the corrected 400/400 baseline.

```
py -3 -m pytest -q -m ""
420 passed in 19.09s
```

## Deliverables

- `docs/experiments/EXP-0030c_RESULTS.md` — this file.
- `ml/float_provenance_features.py` — new production F2 feature pipeline.
- `ml/exp0030c_cmri_production_wiring.py` — new experiment/retrain/serialize/score module.
- `ml/rules.py` — added `CmriFloatProvenanceRule` (additive; existing rules unchanged).
- `ml/iforest_detector.py` — added `cmri_float_pred` field to `DetectorResult`; wired the CMRI-only rule into `run_detector()`'s permanent definition (not called this session).
- `tests/test_float_provenance_features.py`, `tests/test_exp0030c_cmri_production_wiring.py` — new tests.
- `tests/test_exp0017_operational.py` — one existing test's fixture extended (see regression note above); no assertions weakened.
- `data/experiments/exp0017_detector.json`, `data/experiments/exp0025_detector.json` — identity-ledger `source_sha256` refresh only (byte-for-byte `result`/`payload` otherwise untouched, verified by structural diff).
- `data/experiments/exp0030c_train_normal_reference.json`, `data/experiments/exp0030c_cmri_production_wiring.json`, `data/artifacts/exp0030c_cmri_float_provenance_model.json`, `data/artifacts/exp0030c_cmri_float_provenance_model_meta.json` — new artifacts.
- `docs/EXPERIMENT_LOG.md` — PLANNED + TESTED entries appended (see ordering-irregularity note above).
- **No git commit or push performed**, per instruction.

## Limitations (disclosed)

- **TEST-touch accounting**: this experiment retrained a NEW model instance and scored TEST with it exactly once, as a single deliberate exception to "TEST touched once ever" — explicitly authorized by the user for this specific step, because the earlier EXP-0030 research model's fitted classifier object was never serialized to disk (only aggregate statistics were saved), so this is a reproducibility/serialization step for the SAME already-evaluated hypothesis and methodology, not a new hypothesis test or new degrees of freedom. See module docstring for the full disclosure.
- The rest of the wired chain (protocol/pressure/rate/IF) is reproduced in-process via `FrozenCombinedWithRateDetector` (imported unchanged from EXP-0030), not loaded from a serialized object; its exact TEST element-wise match against the frozen EXP-0025 arrays is the evidence this reproduction is faithful.
- The `evaluate()`-per-window production code path was cross-checked against the batch-matrix scoring path on only a 50-window sample of TEST, not the full set, for session compute-time tractability.
- `data/` is globally gitignored in this repository (`.gitignore`: `data/`); the existing tracked JSON results (`exp0017_detector.json`, `exp0025_detector.json`, etc.) were previously force-added, presumably by an earlier session. The new artifacts this experiment wrote (`exp0030c_*` json/model files) are therefore currently **untracked** and will need an explicit `git add -f` if the user wants them committed — flagged here, not acted on, since no commit was requested.
- `overview.md` was searched for (repo root and `docs/`) and **does not exist** in this repository — the requested "proposed update to overview.md's CMRI section" could not be produced because there is no such file to update. Flagged rather than guessed at; if a different filename/location was intended, please point me at it.
- CMRI-only recall gain (54.59%->63.52%, +8.93pp) is noticeably smaller than EXP-0030/0030b's combined NMRI+CMRI figure (54.59%->66.61%) on the same pure cohort — expected (no NMRI classifier contributing here), documented above, not a discrepancy to be alarmed about.
- Pressure is the ARFF-aligned value, not a live `0x03` byte decode; register map/scale undocumented. One testbed; egress-only; measurement only (unchanged limitation, inherited from the whole EXP-0016/0017/0025/0030 line).
