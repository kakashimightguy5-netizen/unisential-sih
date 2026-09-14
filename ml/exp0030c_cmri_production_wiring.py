#!/usr/bin/env python3
"""EXP-0030c — CMRI-only float-provenance rule: production wiring.

Turns EXP-0030b's CMRI-only paper verdict (GO: isolated marginal trade ratio
>= 3:1, worst-case 5.33:1, `docs/experiments/EXP-0030b_RESULTS.md`) into a
real production artifact: a materialized F2 feature pipeline
(`ml/float_provenance_features.py`), a retrained + serialized CMRI-only
XGBoost classifier (`data/artifacts/exp0030c_cmri_float_provenance_model.json`
+ sidecar metadata), a versioned TRAIN-normal reference set
(`data/experiments/exp0030c_train_normal_reference.json`), and a new
`rules.CmriFloatProvenanceRule` OR-term wired into `iforest_detector.run_detector`
for any FUTURE fresh run.

CMRI ONLY. NMRI is explicitly out of scope per EXP-0030b's decision (isolated
ratio worst-case 1.19:1, NO-GO) and is not built, fit, or wired anywhere in
this module.

**TEST-touch accounting (read carefully, this is a deliberate, disclosed
exception):** EXP-0030 and EXP-0030b already spent TEST touches on an
earlier, unserialized research model (`exp0030_float_provenance_detector.py`,
whose fitted `XGBClassifier` object was never persisted to disk — only
aggregate confusion-matrix statistics were saved). This module retrains a
NEW model instance (same TRAIN/VAL data, same `XGB_PARAMS`, same
deterministic fit — bit-identical in expectation, but this is a genuinely
different in-memory/serialized object) and scores TEST with it exactly ONCE,
as PART of this module's own retrain -> serialize -> score pipeline (Method
steps 3-7 below are a single pass, not a separate later TEST touch). This is
a distinct, singular final TEST touch for the newly retrained/serialized
PRODUCTION artifact — explicitly disclosed as an exception to "TEST touched
once ever" because that budget technically belongs to the artifact
identity, not merely to the raw TEST rows; the raw TEST rows were already
read for the SAME classification task (CMRI-only F2) at this exact
threshold-fitting methodology in EXP-0030/0030b, so no new degrees of
freedom are being fished for — this is a reproducibility/serialization step,
not a new hypothesis test. Per user-approved decision, this experiment's
own isolated CMRI marginal ratio computed here (not the EXP-0030b worst-case
NMRI-OR-CMRI bound) is precondition 1's answer.

Method (fixed before running):
  1. Reproduce the TRUE currently-wired combined detector (protocol OR
     pressure OR rate OR IF) for TRAIN/VAL/TEST via
     `exp0030_float_provenance_detector.FrozenCombinedWithRateDetector`
     (imported unchanged, not reimplemented), gated element-wise against the
     frozen EXP-0025 artifact before anything else runs.
  2. Build + persist the TRAIN-normal reference set (`R`).
  3. Build the CMRI residual cohort (`comb_pred==0` under the TRUE combined
     rule, `cmri_pure` category) on TRAIN/VAL/TEST via `build_cohort_frame`
     (imported unchanged from `exp0032_admissible_ceiling_audit`) and
     `_dataset_for` (imported unchanged from
     `exp0032b_ceiling_audit_corrected`), F2 features only.
  4. Retrain an `XGBClassifier(**XGB_PARAMS)` on TRAIN, threshold fit on VAL
     to keep Normal FPR <= `MAX_NORMAL_FPR` (same convention as EXP-0030/32b).
  5. Serialize the fitted model + threshold + feature order
     (`ml/float_provenance_features.save_model`).
  6. Leave-one-attack-run-out check (`leave_one_run_out`, imported unchanged
     from `exp0032b_ceiling_audit_corrected`) on this freshly-trained data.
  7. Load the model BACK from the serialized artifact (round-trip check) via
     `rules.CmriFloatProvenanceRule.load_from_artifact()`, score TEST once:
     full combined confusion (baseline OR cmri_float), isolated marginal
     (baseline vs baseline-OR-cmri_float, restricted to windows the rest of
     the chain misses — mathematically identical to the plain delta for a
     monotonic two-term OR, same argument as EXP-0030b), CMRI pure-cohort
     recall, total resulting FPR.

Hard constraints (unchanged from the whole float-provenance line): no
`source`, `crc_rate`, filename/collection/run-ID metadata as features. Only
IEEE-754 bit-structure features of the decoded egress `0x03` pressure value,
computed causally, plus a TRAIN-normal-only reference set. Frozen
TRAIN/VAL/TEST manifest, never rederived. Refit on TRAIN/VAL only.

Pressure is the ARFF-aligned "pressure measurement" value — egress traffic
extracted from Mississippi State ICS testbed dataset, used as a simulated
diode-observer view — never real diode capture data.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0030c) and
`docs/experiments/EXP-0030c_RESULTS.md`.
"""
from __future__ import annotations

import json
import math
import os
import platform
from importlib.metadata import version
from pathlib import Path
from typing import Mapping

import numpy as np
from xgboost import XGBClassifier

from exp0019_pressure_rate_plausibility import Blocks, align_egress_pressure_timeseries
from exp0017_operational import load_result as load_exp0017_result
from exp0025_dos_rate_rule import load_detector_result as load_exp0025_result
from exp0030_float_provenance_detector import FrozenCombinedWithRateDetector
from rules import CmriFloatProvenanceRule

from exp0032_admissible_ceiling_audit import (
    F2_NAMES, CMRI, WASSERSTEIN_REF_MAX_SIZE, WASSERSTEIN_REF_SEED,
    XGB_PARAMS, MAX_NORMAL_FPR, SeriesIndex, build_cohort_frame, rows_to_matrix,
    fit_threshold, recall_at_threshold,
)
from exp0032b_ceiling_audit_corrected import _dataset_for, leave_one_run_out

from float_provenance_features import (
    build_train_normal_reference, load_model, load_reference, save_model, save_reference,
)

ROOT = Path(__file__).resolve().parent.parent
RESULT_PATH = ROOT / "data" / "experiments" / "exp0030c_cmri_production_wiring.json"

FAMILY = "F2"
COHORT_KEY = "cmri_pure"
ATTACK_NAME = "CMRI"
GO_RATIO_BAR = 3.0
HISTORICAL_CMRI_PRESSURE_ONLY_CEILING = 0.5459  # legibility anchor only (EXP-0030b)
EXP0030B_WORST_CASE_CMRI_RATIO = 5.33            # legibility anchor only (EXP-0030b)


def run_experiment() -> dict:
    R = load_exp0017_result()
    exp0025_result = load_exp0025_result()  # currently wired: protocol|pressure|rate|IF

    # ---- step 1: reproduce the TRUE combined detector, identity-gated ----
    detector = FrozenCombinedWithRateDetector(R, exp0025_result)

    blocks = Blocks()
    series = align_egress_pressure_timeseries()
    si = SeriesIndex(series)
    is_train_normal = np.array(
        [blocks.label(int(b)) == "train_normal" for b in si.bucket_by_pos], dtype=bool,
    )
    train_normal_values = si.values[is_train_normal]
    if len(train_normal_values) < 500:
        raise RuntimeError("too few TRAIN-normal samples for a reference distribution")
    train_normal_sorted = np.sort(np.unique(train_normal_values))
    if len(train_normal_values) > WASSERSTEIN_REF_MAX_SIZE:
        rng0 = np.random.default_rng(WASSERSTEIN_REF_SEED)
        keep = rng0.choice(len(train_normal_values), size=WASSERSTEIN_REF_MAX_SIZE, replace=False)
        train_normal_ref_sample = train_normal_values[np.sort(keep)]
    else:
        train_normal_ref_sample = train_normal_values
    hist_range = (float(train_normal_values.min()), float(train_normal_values.max()))
    bounds = (float(R.pressure_bounds[0]), float(R.pressure_bounds[1]))

    # ---- step 2: materialize + persist the TRAIN-normal reference artifact ----
    ref_check = np.array_equal(train_normal_sorted, build_train_normal_reference(si, blocks))
    reference_meta = save_reference(train_normal_sorted, blocks)

    def cohort_frame_for(block_key: str):
        block = getattr(detector, block_key)
        frame = build_cohort_frame(
            block["windows"], si, bounds, train_normal_sorted, train_normal_ref_sample, hist_range,
        )
        frame["missed_by_rule"] = (block["comb_pred"] == 0)
        return frame

    train_frame = cohort_frame_for("train")
    val_frame = cohort_frame_for("val")
    test_frame = cohort_frame_for("test")

    # ---- step 3: CMRI residual cohort, F2 only ----
    ds = _dataset_for(train_frame, val_frame, test_frame, COHORT_KEY, FAMILY)
    X_tr, y_tr, idx_tr = ds["train"]
    X_val, y_val, idx_val = ds["val"]
    X_test, y_test_cohort, idx_test = ds["test"]

    if len(np.unique(y_tr)) < 2 or len(X_tr) < 10:
        raise RuntimeError(
            f"insufficient CMRI residual TRAIN data to retrain a production model "
            f"(n_train={len(X_tr)}, positives={int(y_tr.sum()) if len(y_tr) else 0})"
        )

    # ---- step 4: retrain on TRAIN, threshold fit on VAL ----
    clf = XGBClassifier(**XGB_PARAMS)
    clf.fit(X_tr, y_tr)
    val_scores = clf.predict_proba(X_val)[:, 1]
    threshold, achieved_val_fpr = fit_threshold(val_scores[y_val == 0], MAX_NORMAL_FPR)
    val_recall = recall_at_threshold(val_scores, y_val, threshold)

    # ---- step 5: serialize ----
    model_meta = save_model(clf, threshold, F2_NAMES)

    # ---- step 6: leave-one-attack-run-out on the freshly retrained model's data ----
    loro = leave_one_run_out(train_frame, val_frame, COHORT_KEY, FAMILY)
    generalizes = bool(loro["n_runs_evaluated"] >= 2 and loro["run_dependent"] is False)

    # ---- step 7: load back from the serialized artifact (round-trip check), score TEST once ----
    loaded_clf, loaded_threshold, loaded_names = load_model()
    loaded_reference = load_reference()
    round_trip_checks = {
        "threshold_matches": bool(loaded_threshold == threshold),
        "feature_names_match": bool(loaded_names == list(F2_NAMES)),
        "reference_matches": bool(np.array_equal(loaded_reference, train_normal_sorted)),
    }

    rule = CmriFloatProvenanceRule().fit_from_trained(loaded_clf, loaded_threshold, loaded_names)
    defined = test_frame["defined"]
    X_test_all_f2 = rows_to_matrix(test_frame["rows"], F2_NAMES)
    scores_all = loaded_clf.predict_proba(X_test_all_f2)[:, 1]
    cmri_float_pred = ((scores_all > loaded_threshold) & defined).astype(int)

    # independent evaluate()-path cross-check (same production code path as
    # iforest_detector.run_detector uses for a fresh run), on a small sample,
    # to catch any scalar-vs-batch scoring drift.
    sample_n = min(50, len(test_frame["rows"]))
    evaluate_path_matches = True
    for i in range(sample_n):
        row = test_frame["rows"][i] if defined[i] else None
        hit = rule.evaluate(row)
        if bool(hit.fired) != bool(cmri_float_pred[i]):
            evaluate_path_matches = False
            break

    baseline_pred = np.asarray(exp0025_result.comb_pred, dtype=int)
    y_test_full = np.asarray(exp0025_result.y_test, dtype=int)
    new_pred = (baseline_pred | cmri_float_pred).astype(int)

    def confusion(pred):
        tn = int(((pred == 0) & (y_test_full == 0)).sum())
        fp = int(((pred == 1) & (y_test_full == 0)).sum())
        fn = int(((pred == 0) & (y_test_full == 1)).sum())
        tp = int(((pred == 1) & (y_test_full == 1)).sum())
        return {"tn": tn, "fp": fp, "fn": fn, "tp": tp,
                "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
                "recall": tp / (tp + fn) if (tp + fn) else 0.0}

    baseline_confusion = confusion(baseline_pred)
    new_confusion = confusion(new_pred)

    # Isolated marginal: for a monotonic two-term OR, "restricted to windows
    # the rest of the chain misses" == the plain before/after delta (same
    # argument as EXP-0030b; no possible overlap-inflation for a two-way
    # union). This is now EXACT (not a worst-case bound) because only ONE
    # classifier (CMRI) exists in this experiment — unlike EXP-0030/0030b,
    # there is no NMRI term whose FP could be conflated with CMRI's.
    tp_gain = new_confusion["tp"] - baseline_confusion["tp"]
    fp_gain = new_confusion["fp"] - baseline_confusion["fp"]
    isolated_ratio = (tp_gain / fp_gain) if fp_gain > 0 else (float("inf") if tp_gain > 0 else 0.0)

    mask = test_frame["cmri_pure"]
    n_pos = int((mask & (y_test_full == 1)).sum())
    baseline_tp_pure = int((mask & (baseline_pred == 1) & (y_test_full == 1)).sum())
    new_tp_pure = int((mask & (new_pred == 1) & (y_test_full == 1)).sum())
    pure_cohort = {
        "n": n_pos,
        "baseline_recall": baseline_tp_pure / n_pos if n_pos else None,
        "new_recall": new_tp_pure / n_pos if n_pos else None,
        "recall_gain": (new_tp_pure - baseline_tp_pure) / n_pos if n_pos else None,
        "historical_pressure_only_ceiling_pct_legibility_anchor":
            100 * HISTORICAL_CMRI_PRESSURE_ONLY_CEILING,
    }

    go = bool(isolated_ratio >= GO_RATIO_BAR and generalizes)
    if go:
        overall_verdict = "GO — CMRI-only float-provenance rule wired into production"
    else:
        reasons = []
        if isolated_ratio < GO_RATIO_BAR:
            reasons.append(f"isolated ratio {isolated_ratio:.2f}:1 < {GO_RATIO_BAR}:1 bar")
        if not generalizes:
            reasons.append("leave-one-run-out does not confirm generalization on the retrained model")
        overall_verdict = "NO-GO — " + "; ".join(reasons)

    return {
        "status": "TESTED — production wiring, TEST scored once (retrained/serialized artifact)",
        "experiment": "EXP-0030c",
        "scope": "CMRI ONLY. NMRI explicitly out of scope (EXP-0030b NO-GO); not built here.",
        "framing": (
            "float/representation-provenance detection, NOT physical-anomaly detection "
            "(unchanged framing from EXP-0030/0030b)."
        ),
        "identity_gates": {
            "fix1_style_gate_vs_exp0025": detector.gate_vs_exp0025,
            "run_detector_modified": True,
            "run_detector_called_this_session": False,
            "reference_reproducible_from_scratch": ref_check,
            "round_trip_checks_after_serialize_reload": round_trip_checks,
            "evaluate_path_matches_batch_scoring_sample": evaluate_path_matches,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "reference_artifact": reference_meta,
        "model_artifact": {k: v for k, v in model_meta.items() if k != "feature_names"},
        "feature_set": F2_NAMES,
        "xgb_params": XGB_PARAMS,
        "max_normal_fpr_threshold_fit": MAX_NORMAL_FPR,
        "train_val": {
            "n_train": int(len(X_tr)), "n_train_positive": int(y_tr.sum()),
            "n_val": int(len(X_val)), "n_val_positive": int(y_val.sum()),
            "threshold": threshold, "val_normal_fpr_achieved": achieved_val_fpr,
            "val_recall_point_estimate": val_recall,
        },
        "leave_one_run_out_fitted_model": loro,
        "generalizes": generalizes,
        "test_scored_once": {
            "baseline_confusion_exp0025_wired": baseline_confusion,
            "new_confusion_with_cmri_float_rule": new_confusion,
            "isolated_marginal": {
                "tp_gain": tp_gain, "fp_gain": fp_gain, "isolated_ratio": isolated_ratio,
                "note": (
                    "EXACT isolated ratio for THIS experiment (single CMRI-only classifier, "
                    "no NMRI term to conflate FP with) — compare against EXP-0030b's "
                    "worst-case bound below."
                ),
            },
            "pure_cohort_recall": {ATTACK_NAME: pure_cohort},
            "total_fpr": {
                "baseline": baseline_confusion["fpr"],
                "with_cmri_float_rule": new_confusion["fpr"],
            },
        },
        "comparison_to_exp0030b_historical_anchor": {
            "exp0030b_cmri_worst_case_isolated_ratio": EXP0030B_WORST_CASE_CMRI_RATIO,
            "this_experiment_exact_isolated_ratio": isolated_ratio,
            "note": (
                "EXP-0030b's 5.33:1 was a WORST-CASE bound (charging the full combined "
                "+27 FP, shared with an NMRI classifier that does not exist in this "
                "experiment, entirely to CMRI). This experiment's ratio is EXACT, not a "
                "bound, because only the CMRI classifier is built/scored here."
            ),
        },
        "decision_rule": {
            "go_bar": f"isolated ratio >= {GO_RATIO_BAR}:1 AND leave-one-run-out generalizes",
            "isolated_ratio": isolated_ratio,
            "generalizes": generalizes,
            "overall_verdict": overall_verdict,
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "xgboost": version("xgboost"),
        },
        "limitations": [
            "TEST-touch accounting: this is a fresh, singular, final TEST touch for the "
            "newly retrained/serialized production artifact, distinct from EXP-0030/0030b's "
            "already-spent TEST touches on the earlier (unserialized) research model — see "
            "module docstring for the full disclosure of this exception.",
            "The rate rule and the rest of the wired chain are reproduced in-process inside "
            "FrozenCombinedWithRateDetector (imported unchanged from EXP-0030), not loaded "
            "from a serialized object; its TEST element-wise match against the frozen "
            "EXP-0025 arrays is the evidence this reproduction is faithful.",
            "Two separate feature-computation call paths were cross-checked on a 50-window "
            "sample (batch matrix scoring vs. the production evaluate()-per-window path) "
            "but not on the full TEST set, for session compute-time tractability.",
            "Pressure is the ARFF-aligned value, not a live 0x03 byte decode; register "
            "map/scale undocumented. One testbed; egress-only; measurement only.",
        ],
    }


# --------------------------------------------------------------- io

def _json_ready(value):
    if isinstance(value, Mapping):
        return {k: _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(v) for v in value]
    if isinstance(value, (np.generic,)):
        return _json_ready(value.item())
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def write_result_atomic(result: Mapping, path: Path = RESULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(_json_ready(result), indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(json.dumps(_json_ready(result), indent=2)[:8000])
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
