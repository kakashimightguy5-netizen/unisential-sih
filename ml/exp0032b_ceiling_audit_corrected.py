#!/usr/bin/env python3
"""EXP-0032b — CORRECTED re-run of EXP-0032's admissible-information ceiling
audit for the residual NMRI/CMRI false negatives.

This is a pre-registered METHODOLOGICAL AMENDMENT, not a new hypothesis.
EXP-0032 found PROCEED-BOTH (NMRI + CMRI), but had three disclosed flaws
that must be fixed before that verdict can be trusted:

  Fix 1 — cohort mismatch: EXP-0032's TRAIN/VALIDATION "residual" cohort was
  the EXP-0016 pressure-bounds-alone proxy (an over-approximation), because
  the frozen EXP-0017 artifact only carries `comb_pred` for TEST. This
  module reproduces the TRUE combined rule (protocol OR pressure-bounds OR
  Isolation Forest — EXP-0017's exact `comb_pred` logic) for TRAIN and
  VALIDATION too, using `FrozenExp0017Detector` below: it reuses every
  frozen, checksummed constant from the EXP-0017 artifact (mu, sd,
  threshold, valid_func_codes, valid_addresses, pressure_bounds) and refits
  ONLY the Isolation Forest itself in-process (not serialized in the frozen
  artifact), with the identical hyperparameters and fixed seed
  `iforest_detector.run_detector` uses — verified, not assumed, by requiring
  EXACT element-wise agreement with the frozen `R.if_pred` / `R.protocol_pred`
  / `R.pressure_pred` / `R.comb_pred` and the frozen TEST confusion matrix
  before anything else runs. Same pattern EXP-0016's `FrozenExp0004Detector`
  already established for EXP-0004. `iforest_detector.run_detector` itself
  is NEVER called (it now refuses a second TEST scoring attempt via its
  attempt ledger, by design, and this module must not call it).

  Fix 2 — control strength: EXP-0032 used 60 bootstrap resamples (spec:
  200) and 20 permutation draws (spec: 50-200). This module restores
  bootstrap to the full 200 (cheap: it only resamples already-computed
  scores, no refit) and reruns the permutation null at 50 draws (the low
  end of the spec's 50-200 range, disclosed for session compute-time
  tractability — each permutation draw refits an XGBoost model). BOTH the
  original reduced counts (60/20) and the restored counts (200/50) are run
  on the corrected cohort and compared; the verdict must not flip between
  them for a PROCEED conclusion to stand.

  Fix 3 — leave-one-attack-run-out generalization check: the dominant
  feature `ulp_distance_to_train_normal` (~0.83 importance in EXP-0032) is
  checked for run-dependence. Distinct attack episodes are identified as
  contiguous-window-index runs of residual-positive examples (same grouping
  unit the event-grouped bootstrap uses). For every run with at least
  `MIN_RUN_SIZE_FOR_LORO` examples, an F2-only (and F3-only) model is
  retrained with that run's examples excluded, and its OWN held-out recall
  is reported — not just an average — so a feature that is secretly a
  signature of one specific attack-generation run cannot hide behind a
  healthy pooled average.

Hard constraints (unchanged from EXP-0032 and the whole missed-NMRI/CMRI
line): no `source` field, no `crc_rate`, no filename/collection/run-ID
metadata, no other testbed artifact, ever. Only features causally available
behind the diode at (or before) the response frame. TRAIN/VAL/TEST
membership from the frozen checksummed manifest
(`exp0008_cadence_features.load_pretest_split` via `Blocks()`), never
rederived. Feature selection and hyperparameter selection happen on
TRAIN/VAL only; TEST is touched exactly once, at the very end, using the
real frozen `comb_pred` (already exact in both EXP-0032 and here) — it
plays NO role in the decision rule.

Pressure is the ARFF-aligned "pressure measurement" value — egress traffic
extracted from Mississippi State ICS testbed dataset, used as a simulated
diode-observer view — never real diode capture data.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0032b).
"""
from __future__ import annotations

import json
import math
import os
import platform
import time
from importlib.metadata import version
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

from exp0016_pressure_bounds_rule import align_egress_pressure, window_pressure_min_max
from exp0017_operational import load_result, manifest_indices
from exp0019_pressure_rate_plausibility import (
    Blocks, EXP0017_TEST_CONFUSION, align_egress_pressure_timeseries, bucket_of,
)
from features_windowed import IF_FEATURES, WINDOW_FEATURES, build_windows
from rules import DeterministicRuleLayer, PressureBounds, PressureBoundsRule

# ---- reused, unchanged, from EXP-0032 (Fix 1-3 do not touch these) ----
from exp0032_admissible_ceiling_audit import (
    CAUSALITY_TABLE, F1_NAMES, F2_NAMES, F3_NAMES, FAMILIES, FEATURE_FAMILIES,
    NMRI, CMRI, WASSERSTEIN_REF_MAX_SIZE, WASSERSTEIN_REF_SEED, XGB_PARAMS,
    MAX_NORMAL_FPR, BASELINE_NMRI_CEILING, BASELINE_CMRI_CEILING,
    SeriesIndex, build_causality_audit, build_cohort_frame,
    contiguous_events, event_grouped_bootstrap_resample,
    event_grouped_permute_labels, fit_threshold, percentile_ci,
    recall_at_threshold, rows_to_matrix, window_row,
)

ROOT = Path(__file__).resolve().parent.parent
RESULT_PATH = ROOT / "data" / "experiments" / "exp0032b_ceiling_audit_corrected.json"

IF_SEED = 0                              # matches iforest_detector.SEED / run_detector's fixed seed
BOOTSTRAP_SEED = 0
PERMUTATION_SEED = 1
N_BOOTSTRAP_REDUCED, N_PERMUTATIONS_REDUCED = 60, 20     # EXP-0032's original (weak) counts, rerun here
N_BOOTSTRAP_FULL, N_PERMUTATIONS_FULL = 200, 50          # Fix 2: restored (bootstrap full-spec;
                                                          # permutation at the spec's 50-200 low end,
                                                          # disclosed for session compute-time tractability)
MIN_RUN_SIZE_FOR_LORO = 3                # windows (>= 15s of contiguous attack episode)
MIN_TRAIN_POSITIVES_FOR_LORO = 5         # minimum remaining positive examples after
                                          # holding one run out, to still fit a model
RUN_DEPENDENT_STD_THRESHOLD = 0.25       # disclosed heuristic: per-run recall std above this
                                          # fraction flags meaningful run-dependence (Fix 3)


# --------------------------------------------------------------- Fix 1: true combined-rule cohort

class FrozenExp0017Detector:
    """Reproduces EXP-0017's combined rule (protocol OR pressure-bounds OR
    Isolation Forest) for TRAIN, VALIDATION, and TEST windows, using only
    frozen constants from the checksummed EXP-0017 artifact. The Isolation
    Forest is refit in-process (not serialized in the artifact) with the
    exact same hyperparameters/seed and verified element-wise against the
    frozen TEST arrays before any TRAIN/VAL number is trusted. This IS
    "the current combined production rule", reproduced read-only;
    `iforest_detector.run_detector` itself is never called and never
    modified."""

    def __init__(self, R):
        wins = sorted(build_windows(), key=lambda w: w.w_index)
        self.windows = wins
        split, tr, va, te = manifest_indices(wins)
        x_raw = np.array([[w.features[f] for f in WINDOW_FEATURES] for w in wins], dtype=float)
        y = np.array([w.is_attack for w in wins])
        tr_normal = tr[y[tr] == 0]

        mu, sd = np.asarray(R.mu, dtype=float), np.asarray(R.sd, dtype=float)
        if_idx = [WINDOW_FEATURES.index(f) for f in IF_FEATURES]
        x_z = (x_raw - mu) / sd

        clf = IsolationForest(n_estimators=300, max_samples="auto", contamination="auto",
                              random_state=IF_SEED, n_jobs=-1)
        clf.fit(x_z[np.ix_(tr_normal, if_idx)])
        self.clf = clf
        self.mu, self.sd, self.if_idx = mu, sd, if_idx
        self.threshold = float(R.threshold)

        rule = DeterministicRuleLayer()
        rule.valid_func_codes = R.valid_func_codes
        rule.valid_addresses = R.valid_addresses
        rule._fitted = True
        self.rule = rule

        bounds = PressureBounds(low=float(R.pressure_bounds[0]), high=float(R.pressure_bounds[1]),
                                source="frozen EXP-0016/EXP-0017 artifact, reused exactly")
        pressure = PressureBoundsRule()
        pressure.bounds = bounds
        pressure._fitted = True
        self.pressure = pressure

        by_bucket = align_egress_pressure()
        self.win_pressure = window_pressure_min_max(by_bucket)

        def score_block(indices):
            s = -clf.score_samples(x_z[np.ix_(indices, if_idx)])
            if_pred = (s >= self.threshold).astype(int)
            protocol_pred = np.array(
                [int(rule.evaluate(wins[i]).fired) for i in indices], dtype=int,
            )
            pressure_pred = np.array(
                [int(pressure.evaluate(*self.win_pressure.get(wins[i].w_index, (None, None, 0))[:2]).fired)
                 for i in indices],
                dtype=int,
            )
            comb_pred = (protocol_pred | pressure_pred | if_pred).astype(int)
            return {
                "if_pred": if_pred, "protocol_pred": protocol_pred,
                "pressure_pred": pressure_pred, "comb_pred": comb_pred,
                "windows": [wins[i] for i in indices],
            }

        self.train = score_block(tr)
        self.val = score_block(va)
        self.test = score_block(te)
        self.y_test = y[te]

        # ---- Fix 1 identity gate: TEST must reproduce the frozen artifact exactly ----
        gate = {
            "if_pred_matches": bool(np.array_equal(self.test["if_pred"], np.asarray(R.if_pred, dtype=int))),
            "protocol_pred_matches": bool(np.array_equal(
                self.test["protocol_pred"], np.asarray(R.protocol_pred, dtype=int))),
            "pressure_pred_matches": bool(np.array_equal(
                self.test["pressure_pred"], np.asarray(R.pressure_pred, dtype=int))),
            "comb_pred_matches": bool(np.array_equal(self.test["comb_pred"], np.asarray(R.comb_pred, dtype=int))),
        }
        tn = int(((self.test["comb_pred"] == 0) & (self.y_test == 0)).sum())
        fp = int(((self.test["comb_pred"] == 1) & (self.y_test == 0)).sum())
        fn = int(((self.test["comb_pred"] == 0) & (self.y_test == 1)).sum())
        tp = int(((self.test["comb_pred"] == 1) & (self.y_test == 1)).sum())
        gate["test_confusion_matches_exp0017"] = (tn, fp, fn, tp) == EXP0017_TEST_CONFUSION
        self.gate = gate
        if not all(gate.values()):
            raise RuntimeError(f"EXP-0032b Fix-1 reproduction of EXP-0017 failed on TEST: {gate}")


# --------------------------------------------------------------- cohort dataset assembly (per config)

def _dataset_for(train_frame, val_frame, test_frame, cohort_key: str, family: str):
    names = FEATURE_FAMILIES[family]

    def split_rows(frame):
        pos_mask = frame[cohort_key] & frame["missed_by_rule"] & frame["defined"]
        neg_mask = frame["normal"] & frame["defined"]
        pos_rows = [r for r, m in zip(frame["rows"], pos_mask) if m]
        neg_rows = [r for r, m in zip(frame["rows"], neg_mask) if m]
        pos_idx = frame["idx"][pos_mask]
        neg_idx = frame["idx"][neg_mask]
        X = rows_to_matrix(pos_rows + neg_rows, names)
        yv = np.concatenate([np.ones(len(pos_rows)), np.zeros(len(neg_rows))]).astype(int)
        idx = np.concatenate([pos_idx, neg_idx])
        order = np.argsort(idx, kind="stable")
        return X[order], yv[order], idx[order]

    return {
        "train": split_rows(train_frame), "val": split_rows(val_frame), "test": split_rows(test_frame),
    }


def _train_and_score(X_tr, y_tr, X_val):
    if len(np.unique(y_tr)) < 2 or len(X_tr) < 10:
        return None
    clf = XGBClassifier(**XGB_PARAMS)
    clf.fit(X_tr, y_tr)
    return clf, clf.predict_proba(X_val)[:, 1]


def _run_family(train_frame, val_frame, test_frame, cohort_key: str, family: str,
                n_bootstrap: int, n_permutations: int,
                bootstrap_seed: int, permutation_seed: int) -> dict:
    ds = _dataset_for(train_frame, val_frame, test_frame, cohort_key, family)
    X_tr, y_tr, idx_tr = ds["train"]
    X_val, y_val, idx_val = ds["val"]
    X_test, y_test, idx_test = ds["test"]

    trained = _train_and_score(X_tr, y_tr, X_val)
    if trained is None:
        return {
            "insufficient_data": True, "n_train": int(len(X_tr)),
            "n_train_positive": int(y_tr.sum()) if len(y_tr) else 0,
        }
    clf, val_scores = trained
    val_normal_scores = val_scores[y_val == 0]
    threshold, achieved_fpr = fit_threshold(val_normal_scores, MAX_NORMAL_FPR)
    real_recall = recall_at_threshold(val_scores, y_val, threshold)

    rng_boot = np.random.default_rng(bootstrap_seed)
    events = contiguous_events(idx_val)
    boot_recalls = []
    for _ in range(n_bootstrap):
        sample_pos = event_grouped_bootstrap_resample(events, rng_boot)
        if len(sample_pos) == 0:
            continue
        boot_recalls.append(recall_at_threshold(val_scores[sample_pos], y_val[sample_pos], threshold))
    recall_ci = percentile_ci(boot_recalls)

    rng_perm = np.random.default_rng(permutation_seed)
    train_events = contiguous_events(idx_tr)
    null_recalls = []
    for _ in range(n_permutations):
        y_perm = event_grouped_permute_labels(train_events, y_tr, rng_perm)
        if len(np.unique(y_perm)) < 2:
            null_recalls.append(0.0)
            continue
        clf_perm = XGBClassifier(**XGB_PARAMS)
        clf_perm.fit(X_tr, y_perm)
        perm_val_scores = clf_perm.predict_proba(X_val)[:, 1]
        perm_threshold, _ = fit_threshold(perm_val_scores[y_val == 0], MAX_NORMAL_FPR)
        null_recalls.append(recall_at_threshold(perm_val_scores, y_val, perm_threshold))
    null_p95 = float(np.percentile(null_recalls, 95)) if null_recalls else 0.0
    clears_null = bool(recall_ci[0] > null_p95)

    test_scores = clf.predict_proba(X_test)[:, 1] if len(X_test) else np.array([])
    if len(X_test):
        test_normal_scores = test_scores[y_test == 0]
        test_fp = int((test_normal_scores > threshold).sum())
        test_fpr = test_fp / len(test_normal_scores) if len(test_normal_scores) else 0.0
        test_recall = recall_at_threshold(test_scores, y_test, threshold)
    else:
        test_fp, test_fpr, test_recall = 0, 0.0, 0.0

    return {
        "n_train": int(len(X_tr)), "n_train_positive": int(y_tr.sum()),
        "n_val": int(len(X_val)), "n_val_positive": int(y_val.sum()),
        "n_test": int(len(X_test)), "n_test_positive": int(y_test.sum()),
        "threshold": threshold, "val_normal_fpr_achieved": achieved_fpr,
        "val_recall_point_estimate": real_recall,
        "val_recall_bootstrap_ci95": list(recall_ci),
        "val_bootstrap_n": len(boot_recalls),
        "permutation_null_recalls": null_recalls,
        "permutation_null_p95": null_p95,
        "clears_permutation_null": clears_null,
        "test_scored_once": {"normal_fp": test_fp, "normal_fpr": test_fpr, "recall": test_recall},
        "feature_names": FEATURE_FAMILIES[family],
        "feature_importances": [float(v) for v in clf.feature_importances_],
    }


def _compute_verdict(family_results: dict) -> dict:
    def clears(fam):
        r = family_results.get(fam, {})
        return bool(r.get("clears_permutation_null")) if not r.get("insufficient_data") else False

    f2_clears, f3_clears, combined_clears = clears("F2"), clears("F3"), clears("combined")
    combined_importances = family_results.get("combined", {}).get("feature_importances", [])
    combined_names = family_results.get("combined", {}).get("feature_names", [])
    dominant_family = None
    if combined_importances:
        top_idx = int(np.argmax(combined_importances))
        dominant_family = CAUSALITY_TABLE.get(combined_names[top_idx], ("unknown",))[0]

    causality_audit = (
        build_causality_audit(combined_names, combined_importances)
        if combined_importances and not family_results.get("combined", {}).get("insufficient_data")
        else []
    )
    causality_clean = all(row["keep"] for row in causality_audit) if causality_audit else False

    proceed_0030 = bool((f2_clears or (combined_clears and dominant_family == "F2")) and causality_clean)
    proceed_0031 = bool((f3_clears or (combined_clears and dominant_family == "F3")) and causality_clean)
    any_clears = any(family_results.get(f, {}).get("clears_permutation_null", False) for f in FAMILIES)
    if proceed_0030 and proceed_0031:
        verdict = "PROCEED-BOTH"
    elif proceed_0030:
        verdict = "PROCEED-0030"
    elif proceed_0031:
        verdict = "PROCEED-0031"
    elif any_clears and not causality_clean:
        verdict = "NO-GO (ambiguous: cleared bar but causality audit flagged artifact concern)"
    else:
        verdict = "NO-GO-CEILING"

    return {
        "verdict": verdict, "dominant_feature_family_combined_model": dominant_family,
        "causality_audit_combined_model": causality_audit, "causality_audit_clean": causality_clean,
        "proceed_0030": proceed_0030, "proceed_0031": proceed_0031,
    }


# --------------------------------------------------------------- Fix 3: leave-one-attack-run-out

def _gather(frame, mask):
    idx = frame["idx"][mask]
    rows = [r for r, m in zip(frame["rows"], mask) if m]
    order = np.argsort(idx, kind="stable")
    return idx[order], [rows[i] for i in order]


def leave_one_run_out(train_frame, val_frame, cohort_key: str, family: str,
                      min_run_size: int = MIN_RUN_SIZE_FOR_LORO,
                      min_train_positives: int = MIN_TRAIN_POSITIVES_FOR_LORO) -> dict:
    """Fix 3: for `family`, pool TRAIN+VAL residual-positive rows (disclosed
    simplification for this generalization sub-check ONLY — the main VAL
    bootstrap result above never trains on VAL; pooling here exists purely
    to have enough distinct attack runs and per-run examples to hold out).
    Group residual-positive rows into contiguous-window-index "runs" (same
    grouping unit `contiguous_events` uses for the bootstrap). For every run
    with >= `min_run_size` examples, retrain on every OTHER run's positive
    rows plus all pooled Normal rows, and report that run's OWN held-out
    recall — not just an average — so a feature secretly tied to one
    specific attack-generation run cannot hide behind a healthy pooled
    mean."""
    names = FEATURE_FAMILIES[family]

    pos_idx_parts, pos_rows_parts = [], []
    for frame in (train_frame, val_frame):
        mask = frame[cohort_key] & frame["missed_by_rule"] & frame["defined"]
        idx, rows = _gather(frame, mask)
        pos_idx_parts.append(idx)
        pos_rows_parts.append(rows)
    pos_idx = np.concatenate(pos_idx_parts)
    pos_rows = pos_rows_parts[0] + pos_rows_parts[1]
    order = np.argsort(pos_idx, kind="stable")
    pos_idx = pos_idx[order]
    pos_rows = [pos_rows[i] for i in order]

    neg_idx_parts, neg_rows_parts = [], []
    for frame in (train_frame, val_frame):
        mask = frame["normal"] & frame["defined"]
        idx, rows = _gather(frame, mask)
        neg_idx_parts.append(idx)
        neg_rows_parts.append(rows)
    neg_idx = np.concatenate(neg_idx_parts)
    neg_rows = neg_rows_parts[0] + neg_rows_parts[1]
    neg_order = np.argsort(neg_idx, kind="stable")
    neg_rows = [neg_rows[i] for i in neg_order]
    X_neg = rows_to_matrix(neg_rows, names) if neg_rows else np.zeros((0, len(names)))

    runs = contiguous_events(pos_idx)
    run_reports = []
    for run_positions in runs:
        if len(run_positions) < min_run_size:
            continue
        held_out = set(run_positions.tolist())
        train_positions = [i for i in range(len(pos_idx)) if i not in held_out]
        if len(train_positions) < min_train_positives or len(X_neg) < 10:
            continue
        X_tr_pos = rows_to_matrix([pos_rows[i] for i in train_positions], names)
        X_tr = np.vstack([X_tr_pos, X_neg])
        y_tr = np.concatenate([np.ones(len(train_positions)), np.zeros(len(X_neg))]).astype(int)
        if len(np.unique(y_tr)) < 2:
            continue
        clf = XGBClassifier(**XGB_PARAMS)
        clf.fit(X_tr, y_tr)
        neg_scores = clf.predict_proba(X_neg)[:, 1]
        threshold, achieved_fpr = fit_threshold(neg_scores, MAX_NORMAL_FPR)
        X_held = rows_to_matrix([pos_rows[i] for i in run_positions], names)
        held_scores = clf.predict_proba(X_held)[:, 1]
        recall = float((held_scores > threshold).sum()) / len(held_scores)
        run_reports.append({
            "run_start_w_index": int(pos_idx[run_positions[0]]),
            "run_end_w_index": int(pos_idx[run_positions[-1]]),
            "n_examples": int(len(run_positions)),
            "held_out_recall": recall,
            "threshold_normal_fpr_achieved": achieved_fpr,
        })

    recalls = [r["held_out_recall"] for r in run_reports]
    return {
        "family": family, "cohort": cohort_key, "n_runs_evaluated": len(run_reports),
        "per_run": run_reports,
        "mean_recall": float(np.mean(recalls)) if recalls else None,
        "std_recall": float(np.std(recalls)) if recalls else None,
        "min_recall": float(np.min(recalls)) if recalls else None,
        "max_recall": float(np.max(recalls)) if recalls else None,
        "run_dependent": (
            bool(np.std(recalls) > RUN_DEPENDENT_STD_THRESHOLD) if len(recalls) >= 2 else None
        ),
        "note": (
            "TRAIN+VAL pooled for this generalization sub-check only (disclosed); "
            "main VAL-bootstrap decision-rule numbers above never train on VAL."
        ),
    }


# --------------------------------------------------------------- experiment

def run_experiment() -> dict:
    t0 = time.time()
    R = load_result()
    comb = np.asarray(R.comb_pred, dtype=int)
    prot = np.asarray(R.protocol_pred, dtype=int)
    press = np.asarray(R.pressure_pred, dtype=int)
    ifp = np.asarray(R.if_pred, dtype=int)
    y_test_R = np.asarray(R.y_test, dtype=int)
    gate_elementwise = bool(np.array_equal(comb, prot | press | ifp))
    tn = int(((comb == 0) & (y_test_R == 0)).sum())
    fp = int(((comb == 1) & (y_test_R == 0)).sum())
    fn = int(((comb == 0) & (y_test_R == 1)).sum())
    tp = int(((comb == 1) & (y_test_R == 1)).sum())
    gate_confusion = (tn, fp, fn, tp) == EXP0017_TEST_CONFUSION
    if not (gate_elementwise and gate_confusion):
        raise RuntimeError(
            f"EXP-0017 identity gate failed: elementwise={gate_elementwise} "
            f"confusion={(tn, fp, fn, tp)} vs {EXP0017_TEST_CONFUSION}"
        )
    bounds = (float(R.pressure_bounds[0]), float(R.pressure_bounds[1]))
    if bounds != (0.482759, 38.7471):
        raise RuntimeError(f"EXP-0016 pressure bounds changed: {bounds}")

    blocks = Blocks()
    if (blocks.split_id, blocks.split_sha256) != (R.split_id, R.split_sha256):
        raise RuntimeError("manifest identity differs from the EXP-0017 artifact")

    # ---- Fix 1: reproduce the TRUE combined rule for TRAIN/VAL/TEST ----
    detector = FrozenExp0017Detector(R)

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

    known_fn_mask_nmri = test_frame["nmri_pure"] & test_frame["missed_by_rule"]
    known_fn_mask_cmri = test_frame["cmri_pure"] & test_frame["missed_by_rule"]
    n_known_nmri_fn = int(known_fn_mask_nmri.sum())
    n_known_cmri_fn = int(known_fn_mask_cmri.sum())

    # For comparison/disclosure: how big was EXP-0032's proxy cohort vs the
    # corrected one, on TRAIN and VAL (Fix 1 effect-size reporting).
    def proxy_missed(windows):
        out = []
        for w in windows:
            positions = si.positions_by_bucket.get(w.w_index)
            if not positions:
                out.append(False)
                continue
            vals = si.values[positions]
            fired = bool(np.any((vals < bounds[0]) | (vals > bounds[1])))
            out.append(not fired)
        return np.array(out, dtype=bool)

    cohort_comparison = {}
    for name, frame, block_key, cohort_key in (
        ("NMRI_train", train_frame, "train", "nmri_pure"),
        ("NMRI_val", val_frame, "val", "nmri_pure"),
        ("CMRI_train", train_frame, "train", "cmri_pure"),
        ("CMRI_val", val_frame, "val", "cmri_pure"),
    ):
        proxy = proxy_missed(getattr(detector, block_key)["windows"])
        corrected_n = int((frame[cohort_key] & frame["missed_by_rule"] & frame["defined"]).sum())
        proxy_n = int((frame[cohort_key] & proxy & frame["defined"]).sum())
        cohort_comparison[name] = {
            "exp0032_proxy_residual_positive_n": proxy_n,
            "exp0032b_corrected_residual_positive_n": corrected_n,
            "delta": corrected_n - proxy_n,
        }

    per_attack: dict[str, dict] = {}
    control_strength_runs: dict[str, dict] = {}
    loro_reports: dict[str, dict] = {}

    for attack_name, cat, cohort_key, n_known_fn in (
        ("NMRI", NMRI, "nmri_pure", n_known_nmri_fn),
        ("CMRI", CMRI, "cmri_pure", n_known_cmri_fn),
    ):
        configs = {}
        for cfg_name, n_boot, n_perm in (
            ("reduced_60_20", N_BOOTSTRAP_REDUCED, N_PERMUTATIONS_REDUCED),
            ("full_200_50", N_BOOTSTRAP_FULL, N_PERMUTATIONS_FULL),
        ):
            family_results = {}
            for family in FAMILIES:
                family_results[family] = _run_family(
                    train_frame, val_frame, test_frame, cohort_key, family,
                    n_boot, n_perm, BOOTSTRAP_SEED, PERMUTATION_SEED,
                )
            verdict_info = _compute_verdict(family_results)
            configs[cfg_name] = {
                "n_bootstrap": n_boot, "n_permutations": n_perm,
                "families": family_results, **verdict_info,
            }
        control_strength_runs[attack_name] = configs
        control_strength_stable = configs["reduced_60_20"]["verdict"] == configs["full_200_50"]["verdict"]

        loro_f2 = leave_one_run_out(train_frame, val_frame, cohort_key, "F2")
        loro_f3 = leave_one_run_out(train_frame, val_frame, cohort_key, "F3")
        loro_reports[attack_name] = {"F2": loro_f2, "F3": loro_f3}

        def _generalizes(loro: dict) -> bool:
            return bool(loro["n_runs_evaluated"] >= 2 and loro["run_dependent"] is False)

        f2_generalizes = _generalizes(loro_f2)
        f3_generalizes = _generalizes(loro_f3)

        full = configs["full_200_50"]
        # Fix 3 gates EACH component of the verdict independently by ITS OWN
        # feature family's leave-one-run-out check — not just the family that
        # happens to dominate the combined model's importances. A component
        # that clears the permutation-null bar but whose feature is run-
        # dependent (e.g. F3's quantile/entropy features below) must not
        # ride PROCEED-BOTH on F2's generalization result.
        proceed_0030_final = bool(full.get("proceed_0030")) and f2_generalizes
        proceed_0031_final = bool(full.get("proceed_0031")) and f3_generalizes
        control_strength_ok = control_strength_stable

        if not control_strength_ok:
            final_verdict = "NO-GO-CEILING"
        elif proceed_0030_final and proceed_0031_final:
            final_verdict = "PROCEED-BOTH"
        elif proceed_0030_final:
            final_verdict = "PROCEED-0030"
        elif proceed_0031_final:
            final_verdict = "PROCEED-0031"
        else:
            final_verdict = "NO-GO-CEILING"

        per_attack[attack_name] = {
            "known_false_negatives_test": n_known_fn,
            "control_strength_stable": control_strength_stable,
            "primary_config": "full_200_50",
            "primary_result": full,
            "loro_f2_generalizes": f2_generalizes,
            "loro_f3_generalizes": f3_generalizes,
            "proceed_0030_before_loro_gate": bool(full.get("proceed_0030")),
            "proceed_0031_before_loro_gate": bool(full.get("proceed_0031")),
            "proceed_0030_final": proceed_0030_final,
            "proceed_0031_final": proceed_0031_final,
            "final_verdict": final_verdict,
        }

    overall_verdicts = {k: v["final_verdict"] for k, v in per_attack.items()}
    if any(v.startswith("PROCEED") for v in overall_verdicts.values()):
        overall = " / ".join(f"{k}: {v}" for k, v in overall_verdicts.items())
    else:
        overall = "NO-GO-CEILING"

    elapsed_seconds = time.time() - t0

    return {
        "status": "TESTED — CORRECTED DIAGNOSTIC PROBE; NO DETECTOR BUILT; run_detector NOT modified",
        "experiment": "EXP-0032b",
        "supersedes": "EXP-0032 (docs/experiments/EXP-0032_RESULTS.md) — PROCEED-BOTH verdict was SUSPENDED "
                       "pending this corrected re-run per the pre-registered amendment",
        "identity_gates": {
            "exp0017_artifact_loaded_and_verified": True,
            "comb_equals_protocol_or_pressure_or_if": gate_elementwise,
            "whole_test_confusion_matches_exp0017": bool(gate_confusion),
            "exp0017_confusion": list(EXP0017_TEST_CONFUSION),
            "exp0016_bounds": list(bounds),
            "run_detector_modified": False,
            "fix1_train_val_test_comb_pred_reproduction": detector.gate,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "fix1_residual_cohort_definition": {
            "all_splits": (
                "TRUE combined rule (protocol OR pressure-bounds OR Isolation Forest), "
                "reproduced exactly for TRAIN, VALIDATION, and TEST via FrozenExp0017Detector, "
                "not approximated. TEST additionally cross-checked element-wise against the "
                "frozen comb_pred array; TRAIN/VAL have no frozen array to check against, so "
                "the guarantee there rests on: (a) reusing every frozen scalar constant "
                "(mu, sd, threshold, valid_func_codes, valid_addresses, pressure_bounds) "
                "unchanged, (b) an Isolation Forest refit with identical hyperparameters and "
                "the identical fixed seed, and (c) that refit's element-wise agreement with "
                "the frozen TEST if_pred (the strongest evidence available that the refit "
                "process is deterministic and faithful)."
            ),
        },
        "fix1_cohort_size_comparison_vs_exp0032_proxy": cohort_comparison,
        "n_known_false_negatives_test": {"NMRI": n_known_nmri_fn, "CMRI": n_known_cmri_fn},
        "fix2_control_strength": {
            "reduced_counts": [N_BOOTSTRAP_REDUCED, N_PERMUTATIONS_REDUCED],
            "full_counts": [N_BOOTSTRAP_FULL, N_PERMUTATIONS_FULL],
            "note": (
                "bootstrap restored to the spec's full 200 (cheap: resamples already-computed "
                "scores, no refit); permutation draws restored to 50 (the spec's 50-200 low "
                "end, disclosed for session compute-time tractability: every permutation draw "
                "refits an XGBoost model, x2 attack types x4 families)."
            ),
            "per_attack": control_strength_runs,
        },
        "fix3_leave_one_attack_run_out": loro_reports,
        "per_attack": per_attack,
        "decision_rule": {
            "bar": "VAL event-grouped-bootstrap recall-at-<=0.30%-FPR 95% CI lower bound "
                   "must exceed the label-permutation null distribution's 95th percentile, "
                   "on the Fix-1-corrected residual cohort, at Fix-2-restored control "
                   "strength, AND the dominant feature family must pass Fix-3's "
                   "leave-one-attack-run-out generalization check",
            "verdicts": overall_verdicts,
            "overall": overall,
            "frozen_ceiling_if_no_go": {"NMRI_pct": 79.02, "CMRI_pct": 54.59},
            "no_further_amendments": (
                "Per the pre-registered amendment: this corrected re-run's verdict is final. "
                "If ambiguous, the default is NO-GO per this project's standing conservative bias."
            ),
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "scipy": version("scipy"), "scikit_learn": version("scikit-learn"),
            "xgboost": version("xgboost"),
        },
        "runtime_seconds": elapsed_seconds,
        "limitations": [
            "Fix 3's leave-one-attack-run-out check pools TRAIN+VAL for training (disclosed "
            "simplification specific to that sub-check only); the main VAL-bootstrap decision "
            "numbers above never train on VAL.",
            "The Isolation Forest is refit, not loaded from a serialized object (none exists "
            "in the frozen artifact); its exact TEST-element-wise agreement with the frozen "
            "if_pred is the evidence this refit is faithful for TRAIN/VAL too.",
            "Permutation draws (50) are at the spec's disclosed low end for compute-time "
            "tractability, not the illustrative upper bound (200); the 60/20-vs-200/50 "
            "comparison is reported specifically so this doesn't hide a fragile verdict.",
            "run_detector() was NOT called and NOT modified anywhere in this module.",
            "Pressure is the ARFF-aligned value, not a live 0x03 byte decode; register "
            "map/scale undocumented.",
            "One testbed; egress-only; measurement only.",
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


def _format_report(r: Mapping) -> str:
    lines = [
        "# EXP-0032b — CORRECTED admissible-information ceiling audit (supersedes EXP-0032)",
        "",
        f"run_detector() modified: {r['identity_gates']['run_detector_modified']}",
        f"Fix-1 TEST reproduction gate: {r['identity_gates']['fix1_train_val_test_comb_pred_reproduction']}",
        f"Known TEST false negatives: NMRI={r['n_known_false_negatives_test']['NMRI']}  "
        f"CMRI={r['n_known_false_negatives_test']['CMRI']}",
        "",
        "## Fix 1 — cohort size, corrected vs EXP-0032's proxy",
        "",
    ]
    for k, v in r["fix1_cohort_size_comparison_vs_exp0032_proxy"].items():
        lines.append(f"- {k}: proxy={v['exp0032_proxy_residual_positive_n']} "
                     f"corrected={v['exp0032b_corrected_residual_positive_n']} delta={v['delta']}")
    lines.append("")
    for attack, block in r["per_attack"].items():
        lines += [f"## {attack}", "",
                  f"Control-strength stable (60/20 vs 200/50 same verdict): {block['control_strength_stable']}",
                  f"F2 (ulp_distance_to_train_normal) LORO generalizes: {block['loro_f2_generalizes']}  "
                  f"-> PROCEED-0030: {block['proceed_0030_before_loro_gate']} -> after LORO gate: "
                  f"{block['proceed_0030_final']}",
                  f"F3 (distribution features) LORO generalizes: {block['loro_f3_generalizes']}  "
                  f"-> PROCEED-0031: {block['proceed_0031_before_loro_gate']} -> after LORO gate: "
                  f"{block['proceed_0031_final']}",
                  f"**Final verdict: {block['final_verdict']}**", ""]
    dr = r["decision_rule"]
    lines += ["## Overall decision-rule verdict", f"{dr['overall']}", "",
              "_Diagnostic only; no detector was built or wired. run_detector NOT modified._"]
    return "\n".join(lines)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
