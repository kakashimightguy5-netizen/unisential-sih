#!/usr/bin/env python3
"""EXP-0029 — regime-aware rolling baseline (causal relative deviation) for
the missed NMRI false negatives, with a CMRI generalization check.

Every existing rule (EXP-0016 pressure bounds, IF) compares against a GLOBAL
notion of "normal". This experiment asks whether the 150/715 (23.4%) pure-NMRI
TEST windows EXP-0017 misses are anomalous relative to the IMMEDIATELY
PRECEDING run instead — a regime-local baseline — even when the raw value is
globally in-bounds.

Diagnostic-then-build, same discipline as EXP-0018/0019/0020/0028.
`ml/iforest_detector.run_detector` is NOT modified and NOT called. EXP-0017 is
reproduced from its checksummed saved artifact (`exp0017_operational.load_result`)
and asserted element-wise `comb == protocol | pressure | IF` with whole-TEST
confusion (4767, 40, 2166, 2374) before any score is read, exactly as
EXP-0018/0019/0020/0021/0028.

Hard constraints (pre-registered, unchanged): no `source`/`crc_rate`/testbed
metadata; only decoded pressure and values derived from a ROLLING window over
it (median, MAD), CAUSAL only (strictly-before-t samples, never centered or
future-looking); TRAIN/VALIDATION/TEST membership from the frozen checksummed
manifest, never rederived; threshold fit on VAL only; TEST scored exactly
once. This is a DIFFERENT baseline model, NOT a rate-of-change feature — it
does not reintroduce EXP-0019/0020's |dp|/dt framing under a new name: the
feature here is a relative-deviation z-score against a trailing sample-count
window's robust (median/MAD) location and scale, with no time derivative.

Feature (pre-registered, k = 5, 10, 20 samples fixed BEFORE any VAL/TEST
score, no post-hoc grid search):
    z_t = (P_t - median(P[t-k:t-1])) / (MAD(P[t-k:t-1]) + epsilon)

Pressure is the ARFF-aligned "pressure measurement" value from the Mississippi
State ICS testbed dataset (Turnipseed 2015), used here as egress traffic
extracted from Mississippi State ICS testbed dataset, used as a simulated
diode-observer view — never real diode capture data.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0029).
"""
from __future__ import annotations

import json
import math
import os
import platform
from importlib.metadata import version
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
from scipy.stats import mannwhitneyu

from exp0017_operational import load_result
from exp0019_pressure_rate_plausibility import (
    Blocks, EXP0017_TEST_CONFUSION, align_egress_pressure_timeseries, bucket_of,
    _cohort_mask, _q,
)
from features_windowed import build_windows

ROOT = Path(__file__).resolve().parent.parent
RESULT_PATH = ROOT / "data" / "experiments" / "exp0029_regime_baseline.json"
NMRI = 1
CMRI = 2

# ---- pre-registered method constants ----
K_CANDIDATES = (5, 10, 20)        # window sizes in SAMPLES, fixed up front
EPSILON = 1e-6

# ---- pre-registered decision rule (fixed; EXP-0029 spec) ----
DIAGNOSTIC_MIN_ABS_D = 0.5
BASELINE_PURE_NMRI_RECALL = 565 / 715      # EXP-0017 combined, given/prior
BASELINE_PURE_CMRI_RECALL_EXP0028 = 654 / 1198   # PressureBoundsRule alone (EXP-0028 bar)
MAX_NORMAL_FPR = 0.0030
ARTIFACT_ALPHA = 0.05
ARTIFACT_MIN_ABS_D = 0.2


# --------------------------------------------------------------- rolling causal z-score

def causal_z_scores(values: Sequence[float], k: int, epsilon: float = EPSILON) -> np.ndarray:
    """z_t = (P_t - median(P[t-k:t-1])) / (MAD(P[t-k:t-1]) + epsilon) for every
    t with >= k strictly-preceding samples (t is 0-indexed into `values`).
    Undefined (NaN) for t < k. Never looks at values[t] or later in the
    window it standardizes against (causal)."""
    values = np.asarray(values, dtype=float)
    n = len(values)
    z = np.full(n, np.nan)
    for t in range(k, n):
        window = values[t - k:t]
        med = float(np.median(window))
        mad = float(np.median(np.abs(window - med)))
        z[t] = (values[t] - med) / (mad + epsilon)
    return z


def window_max_abs_z(z: np.ndarray, times: Sequence[float]) -> dict[int, float]:
    """Per-window (bucket) max |z_t| over samples whose timestamp falls in
    that bucket, mirroring EXP-0019/0028's max-over-endings aggregation.
    Buckets with no defined z sample are absent (undefined, not flaggable)."""
    out: dict[int, float] = {}
    for zi, ti in zip(z, times):
        if not math.isfinite(zi):
            continue
        b = bucket_of(ti)
        az = abs(float(zi))
        if b not in out or az > out[b]:
            out[b] = az
    return out


# --------------------------------------------------------------- eval helpers

def cohens_d(a: Sequence[float], b: Sequence[float]) -> float:
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if len(a) < 2 or len(b) < 2:
        return 0.0
    na, nb = len(a), len(b)
    pooled_var = ((na - 1) * a.var(ddof=1) + (nb - 1) * b.var(ddof=1)) / (na + nb - 2)
    pooled = math.sqrt(pooled_var) if pooled_var > 0 else 0.0
    return 0.0 if pooled == 0 else float((a.mean() - b.mean()) / pooled)


def fit_threshold(normal_scores: np.ndarray, max_fpr: float) -> tuple[float, float]:
    """Smallest threshold such that firing on score > threshold keeps the
    empirical Normal FPR <= max_fpr. Returns (threshold, achieved_fpr)."""
    if len(normal_scores) == 0:
        raise RuntimeError("no VAL Normal scores to fit a threshold on")
    sorted_scores = np.sort(normal_scores)[::-1]
    n = len(sorted_scores)
    max_fp = int(math.floor(max_fpr * n))
    if max_fp <= 0:
        threshold = float(sorted_scores[0]) + 1e-9
        return threshold, 0.0
    threshold = float(sorted_scores[max_fp - 1])
    achieved = float(np.sum(normal_scores > threshold)) / n
    return threshold, achieved


def rule_recall(mask: np.ndarray, fired: np.ndarray) -> tuple[int, int, float]:
    n = int(mask.sum())
    hits = int(fired[mask].sum())
    return hits, n, (hits / n if n else 0.0)


def confusion(tp: int, n_pos: int, fp: int, n_neg: int) -> dict:
    fn, tn = n_pos - tp, n_neg - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / n_pos if n_pos else 0.0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": precision, "recall": recall,
        "fpr": fp / n_neg if n_neg else 0.0,
    }


# --------------------------------------------------------------- experiment

def run_experiment() -> dict:
    # ---- identity gate: reproduce EXP-0017 exactly ----
    R = load_result()
    comb = np.asarray(R.comb_pred, dtype=int)
    prot = np.asarray(R.protocol_pred, dtype=int)
    press = np.asarray(R.pressure_pred, dtype=int)
    ifp = np.asarray(R.if_pred, dtype=int)
    y = np.asarray(R.y_test, dtype=int)
    test_windows = R.test_windows
    gate_elementwise = bool(np.array_equal(comb, prot | press | ifp))
    tn = int(((comb == 0) & (y == 0)).sum())
    fp = int(((comb == 1) & (y == 0)).sum())
    fn = int(((comb == 0) & (y == 1)).sum())
    tp = int(((comb == 1) & (y == 1)).sum())
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

    series = align_egress_pressure_timeseries()
    values = np.array([p for _, p in series], dtype=float)
    times = np.array([t for t, _ in series], dtype=float)

    all_windows = sorted(build_windows(), key=lambda w: w.w_index)
    is_attack_by_win = {w.w_index: w.is_attack for w in all_windows}
    val_windows = sorted(
        [w for w in all_windows if w.w_index in blocks.validation], key=lambda w: w.w_index,
    )
    last_pressure_by_win: dict[int, float] = {}
    for t, p in series:
        last_pressure_by_win[bucket_of(t)] = p   # ascending -> last write wins

    z_by_k: dict[int, dict[int, float]] = {}
    for k in K_CANDIDATES:
        z_k = causal_z_scores(values, k)
        z_by_k[k] = window_max_abs_z(z_k, times)

    def build_frame(windows):
        idx = np.array([w.w_index for w in windows], dtype=int)
        categories = [set(w.categories) for w in windows]
        normal_mask = np.array([c == {0} for c in categories], dtype=bool)
        nmri_pure = np.array([NMRI in c and c <= {0, NMRI} for c in categories], dtype=bool)
        nmri_dominant = np.array(
            [([x for x in c if x != 0] or [0])[0] == NMRI for c in categories], dtype=bool,
        )
        nmri_containing = np.array([NMRI in c for c in categories], dtype=bool)
        cmri_pure = np.array([CMRI in c and c <= {0, CMRI} for c in categories], dtype=bool)
        cmri_dominant = np.array(
            [([x for x in c if x != 0] or [0])[0] == CMRI for c in categories], dtype=bool,
        )
        cmri_containing = np.array([CMRI in c for c in categories], dtype=bool)
        pred_pressure = np.array(
            [last_pressure_by_win.get(i - 1, np.nan) for i in idx], dtype=float,
        )
        pred_in_bounds = (pred_pressure >= bounds[0]) & (pred_pressure <= bounds[1])
        pred_attack = np.array(
            [bool(is_attack_by_win.get(i - 1, 0)) for i in idx], dtype=bool,
        )
        frame = {
            "idx": idx, "normal_mask": normal_mask,
            "nmri_pure": nmri_pure, "nmri_dominant": nmri_dominant, "nmri_containing": nmri_containing,
            "cmri_pure": cmri_pure, "cmri_dominant": cmri_dominant, "cmri_containing": cmri_containing,
            "pred_in_bounds": pred_in_bounds, "pred_attack": pred_attack,
        }
        for k in K_CANDIDATES:
            z = np.array([z_by_k[k].get(i, np.nan) for i in idx], dtype=float)
            frame[f"z_{k}"] = z
            frame[f"defined_{k}"] = ~np.isnan(z)
        return frame

    val_f = build_frame(val_windows)
    test_f = build_frame(test_windows)

    # -------- step 2: mandatory diagnostic (BEFORE building any detector) --------
    # 150/715 known pure-NMRI TEST false negatives of EXP-0017's combined
    # (pressure-bounds + IF) result: comb_pred == 0 restricted to the pure-NMRI cohort.
    fn_mask = test_f["nmri_pure"] & (comb == 0)
    n_known_fn = int(fn_mask.sum())

    diagnostics = {}
    for k in K_CANDIDATES:
        defined = test_f[f"defined_{k}"]
        a = test_f[f"z_{k}"][fn_mask & defined]         # missed-NMRI |z|
        b = test_f[f"z_{k}"][test_f["normal_mask"] & defined]   # pure-Normal TEST |z|
        d = cohens_d(a, b)
        u = p = None
        if len(a) > 1 and len(b) > 1:
            u_stat, p_val = mannwhitneyu(a, b, alternative="two-sided")
            u, p = float(u_stat), float(p_val)
        diagnostics[k] = {
            "n_missed_nmri_defined": int(len(a)), "n_normal_defined": int(len(b)),
            "median_missed_nmri_abs_z": float(np.median(a)) if len(a) else None,
            "median_normal_abs_z": float(np.median(b)) if len(b) else None,
            "cohens_d": d, "mannwhitney_u": u, "mannwhitney_p": p,
        }
    best_k_diag = max(K_CANDIDATES, key=lambda k: diagnostics[k]["cohens_d"])
    best_diag_d = diagnostics[best_k_diag]["cohens_d"]
    diagnostic_supported = best_diag_d >= DIAGNOSTIC_MIN_ABS_D

    result: dict = {
        "status": None,
        "experiment": "EXP-0029",
        "identity_gates": {
            "exp0017_artifact_loaded_and_verified": True,
            "comb_equals_protocol_or_pressure_or_if": gate_elementwise,
            "whole_test_confusion_matches_exp0017": bool(gate_confusion),
            "exp0017_confusion": list(EXP0017_TEST_CONFUSION),
            "exp0016_bounds": list(bounds),
            "run_detector_modified": False,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "known_false_negatives": {
            "cohort": "pure-NMRI TEST windows with EXP-0017 comb_pred == 0",
            "n": n_known_fn, "expected_n": 150, "matches_expected": n_known_fn == 150,
        },
        "method": {
            "feature": "z_t = (P_t - median(P[t-k:t-1])) / (MAD(P[t-k:t-1]) + epsilon); "
                       "causal, sample-count window, NOT a rate-of-change feature",
            "epsilon": EPSILON,
            "k_candidates_samples": list(K_CANDIDATES),
            "per_window_score": "max |z_t| over samples ending in the window",
        },
        "diagnostic": {
            "cohort": "150 known pure-NMRI EXP-0017 false negatives vs pure-Normal TEST, "
                      "|z_t| magnitude, per candidate k",
            "per_k": diagnostics,
            "best_k": best_k_diag,
            "best_cohens_d": best_diag_d,
            "min_required_abs_d": DIAGNOSTIC_MIN_ABS_D,
            "diagnostic_supported": diagnostic_supported,
        },
    }

    if not diagnostic_supported:
        result["status"] = "TESTED — DIAGNOSTIC FAILURE; NO DETECTOR BUILT"
        result["decision_rule"] = {
            "verdict_nmri": "NO-GO",
            "verdict_cmri_secondary": "NO-GO (not evaluated; diagnostic failed for the shared feature)",
            "reason": (
                f"best Cohen's d over k in {K_CANDIDATES} is {best_diag_d:.3f} "
                f"(k={best_k_diag}), below the {DIAGNOSTIC_MIN_ABS_D} pre-registered bar. "
                "Per the pre-registration, window size k is NOT iterated further as a "
                "post-hoc rescue after seeing this diagnostic."
            ),
        }
        return result

    # -------- step 3: threshold selection on VAL only (k chosen by VAL performance) --------
    val_normal_defined = {k: val_f["normal_mask"] & val_f[f"defined_{k}"] for k in K_CANDIDATES}
    thresholds, val_report = {}, {}
    for k in K_CANDIDATES:
        normal_scores = val_f[f"z_{k}"][val_normal_defined[k]]
        threshold, achieved_fpr = fit_threshold(normal_scores, MAX_NORMAL_FPR)
        fired = (val_f[f"z_{k}"] > threshold) & val_f[f"defined_{k}"]
        hits, n_nmri, recall = rule_recall(val_f["nmri_pure"], fired.astype(int))
        thresholds[k] = threshold
        val_report[k] = {
            "threshold": threshold, "val_normal_n": int(len(normal_scores)),
            "val_normal_fpr_achieved": achieved_fpr,
            "val_pure_nmri_hits": hits, "val_pure_nmri_n": n_nmri, "val_pure_nmri_recall": recall,
        }
    winning_k = max(K_CANDIDATES, key=lambda k: val_report[k]["val_pure_nmri_recall"])

    # -------- step 5: setpoint-change artifact check (pooled VAL+TEST, winning k) --------
    def pooled(field):
        return np.concatenate([val_f[field], test_f[field]])

    z_pooled = pooled(f"z_{winning_k}")
    defined_pooled = pooled(f"defined_{winning_k}")
    normal_pooled = pooled("normal_mask") & defined_pooled
    group_a = normal_pooled & pooled("pred_attack")          # follows an attack window
    group_b = normal_pooled & pooled("pred_in_bounds")        # in-bounds predecessor

    a, b = z_pooled[group_a], z_pooled[group_b]
    art_d = cohens_d(a, b)
    art_u = art_p = None
    if len(a) > 1 and len(b) > 1:
        u_stat, p_val = mannwhitneyu(a, b, alternative="two-sided")
        art_u, art_p = float(u_stat), float(p_val)
    artifact_inflated = bool(
        art_d >= ARTIFACT_MIN_ABS_D and art_p is not None and art_p < ARTIFACT_ALPHA
        and (np.median(a) > np.median(b) if len(a) and len(b) else False)
    )
    gate_applied = artifact_inflated

    def gated_defined(frame, k):
        d = frame[f"defined_{k}"].copy()
        if gate_applied:
            d = d & frame["pred_in_bounds"]
        return d

    test_defined = gated_defined(test_f, winning_k)
    winning_threshold = thresholds[winning_k]

    # -------- step 4: score TEST exactly once (winning k) --------
    z_fired_test = ((test_f[f"z_{winning_k}"] > winning_threshold) & test_defined).astype(int)
    test_normal_mask = test_f["normal_mask"] & test_defined
    n_neg = int(test_normal_mask.sum())
    z_alone_fp = int(z_fired_test[test_normal_mask].sum())
    z_alone_fpr = z_alone_fp / n_neg if n_neg else 0.0

    combined = (comb | z_fired_test).astype(int)
    w_tn = int(((combined == 0) & (y == 0)).sum())
    w_fp = int(((combined == 1) & (y == 0)).sum())
    w_fn = int(((combined == 0) & (y == 1)).sum())
    w_tp = int(((combined == 1) & (y == 1)).sum())

    nmri_pure_hits, nmri_pure_n, nmri_pure_recall = rule_recall(test_f["nmri_pure"], combined)
    nmri_dom_hits, nmri_dom_n, nmri_dom_recall = rule_recall(test_f["nmri_dominant"], combined)
    nmri_cont_hits, nmri_cont_n, nmri_cont_recall = rule_recall(test_f["nmri_containing"], combined)

    recovered = int((z_fired_test[fn_mask]).sum())   # of the 150 known FN, how many now fire

    passes_nmri_recall = nmri_pure_recall > BASELINE_PURE_NMRI_RECALL
    passes_nmri_fpr = z_alone_fpr <= MAX_NORMAL_FPR
    artifact_clean_or_gated = (not artifact_inflated) or gate_applied
    go_nmri = bool(passes_nmri_recall and passes_nmri_fpr and artifact_clean_or_gated)

    # -------- step 4 (spec item 4): CMRI generalization check, SAME winning rule --------
    cmri_pure_hits_z, cmri_pure_n, cmri_pure_recall_z = rule_recall(test_f["cmri_pure"], z_fired_test)
    cmri_combined = (comb | z_fired_test).astype(int)
    cmri_pure_hits_c, _, cmri_pure_recall_c = rule_recall(test_f["cmri_pure"], cmri_combined)
    passes_cmri_recall = cmri_pure_recall_c > BASELINE_PURE_CMRI_RECALL_EXP0028
    passes_cmri_fpr = z_alone_fpr <= MAX_NORMAL_FPR
    go_cmri = bool(passes_cmri_recall and passes_cmri_fpr and artifact_clean_or_gated)

    verdict_nmri = "GO" if go_nmri else "NO-GO"
    verdict_cmri = "GO" if go_cmri else "NO-GO"

    result["status"] = "VALIDATED — TEST SCORED ONCE; run_detector NOT modified"
    result["val_threshold_selection"] = val_report
    result["winning_k"] = winning_k
    result["winning_threshold"] = winning_threshold
    result["artifact_check"] = {
        "definition": (
            "group A: pure-Normal window whose immediate predecessor window (w_index-1) "
            "is attack-labelled (proxy for 'just after a disruptive event, not a routine "
            "setpoint change'). group B: pure-Normal window whose predecessor's last "
            "observed pressure sample is within the EXP-0016 TRAIN-normal bounds (routine "
            "operation, including ordinary setpoint changes). Pooled VAL+TEST, winning k."
        ),
        "n_group_a": int(len(a)), "n_group_b": int(len(b)),
        "median_group_a": float(np.median(a)) if len(a) else None,
        "median_group_b": float(np.median(b)) if len(b) else None,
        "cohens_d": art_d, "mannwhitney_u": art_u, "mannwhitney_p": art_p,
        "artifact_inflated": artifact_inflated, "gate_applied": gate_applied,
    }
    result["test_scoring"] = {
        "z_rule_alone_normal_fpr": z_alone_fpr, "z_rule_alone_normal_fp": z_alone_fp,
        "z_rule_alone_normal_n": n_neg,
        "recovered_of_150_known_fn": recovered, "recovered_of_150_fraction": recovered / 150.0,
        "combined_whole_test_confusion": {"tn": w_tn, "fp": w_fp, "fn": w_fn, "tp": w_tp},
        "combined_whole_test_confusion_delta": [
            w_tn - EXP0017_TEST_CONFUSION[0], w_fp - EXP0017_TEST_CONFUSION[1],
            w_fn - EXP0017_TEST_CONFUSION[2], w_tp - EXP0017_TEST_CONFUSION[3],
        ],
        "nmri_pure": {"hits": nmri_pure_hits, "n": nmri_pure_n, "recall": nmri_pure_recall},
        "nmri_dominant": {"hits": nmri_dom_hits, "n": nmri_dom_n, "recall": nmri_dom_recall},
        "nmri_containing": {"hits": nmri_cont_hits, "n": nmri_cont_n, "recall": nmri_cont_recall},
        "cmri_generalization": {
            "pure_n": cmri_pure_n,
            "z_rule_alone_pure_recall": cmri_pure_recall_z,
            "combined_pure_recall": cmri_pure_recall_c,
            "combined_pure_hits": cmri_pure_hits_c,
        },
    }
    result["decision_rule"] = {
        "baseline_pure_nmri_recall": BASELINE_PURE_NMRI_RECALL,
        "baseline_pure_cmri_recall_exp0028_bar": BASELINE_PURE_CMRI_RECALL_EXP0028,
        "max_normal_fpr": MAX_NORMAL_FPR,
        "passes_nmri_recall_bar": passes_nmri_recall,
        "passes_nmri_fpr_bar": passes_nmri_fpr,
        "passes_cmri_recall_bar": passes_cmri_recall,
        "passes_cmri_fpr_bar": passes_cmri_fpr,
        "artifact_check_clean_or_gated": artifact_clean_or_gated,
        "verdict_nmri": verdict_nmri,
        "verdict_cmri_secondary": verdict_cmri,
        "note_exp0028_comparison": (
            "EXP-0028 (CMRI trajectory-matching) was NO-GO (7.68% recall, 0.463% FPR); "
            f"this rule scores {100 * cmri_pure_recall_c:.2f}% pure-CMRI recall at "
            f"{100 * z_alone_fpr:.4f}% standalone FPR — reported per spec even though "
            "EXP-0028's own negative result made this comparison likely moot."
        ),
    }
    result["software"] = {
        "python": platform.python_version(), "numpy": version("numpy"),
        "scipy": version("scipy"), "scikit_learn": version("scikit-learn"),
    }
    result["limitations"] = [
        "Pressure is the ARFF-aligned value, not a live 0x03 byte decode; register "
        "map/scale undocumented.",
        "z_t is a sample-count (not time-based) rolling window; 0x03 cadence has ~7% "
        "gaps at 3-4x the median step, so k samples can span uneven elapsed time.",
        "Per-window score is a max over sample endings inside the window (EXP-0019/0028 "
        "aggregation convention), not an average.",
        "k selected on VAL pure-NMRI recall at a fixed VAL Normal FPR budget; the "
        "diagnostic Cohen's d (step 2) used the already-known TEST false-negative set, "
        "same disclosed pattern as EXP-0018/0019's threshold-independent signal tests.",
        "CMRI generalization is evaluated with the k/threshold selected for NMRI, not "
        "independently re-tuned for CMRI (per spec: same rule, secondary check).",
        "One testbed; egress-only; measurement only unless explicitly wired in.",
    ]
    return result


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
        "# EXP-0029 — regime-aware rolling baseline (causal relative deviation), NMRI + CMRI check",
        "",
        f"run_detector() modified: {r['identity_gates']['run_detector_modified']}",
        f"Known false negatives: {r['known_false_negatives']['n']} "
        f"(expected {r['known_false_negatives']['expected_n']}, "
        f"matches={r['known_false_negatives']['matches_expected']})",
        "",
        "## Diagnostic (step 2, mandatory, before any detector built)",
        "| k | median missed-NMRI |z| | median Normal |z| | Cohen's d | MW p |",
        "|---:|---:|---:|---:|---:|",
    ]
    for k, d in r["diagnostic"]["per_k"].items():
        lines.append(
            f"| {k} | {d['median_missed_nmri_abs_z']:.4f} | {d['median_normal_abs_z']:.4f} "
            f"| {d['cohens_d']:+.3f} | {d['mannwhitney_p']:.3g} |"
        )
    lines += [
        "",
        f"Best k={r['diagnostic']['best_k']}  d={r['diagnostic']['best_cohens_d']:+.3f}  "
        f"(bar >= {r['diagnostic']['min_required_abs_d']})  "
        f"diagnostic_supported={r['diagnostic']['diagnostic_supported']}",
        "",
    ]
    if r["status"].startswith("TESTED — DIAGNOSTIC FAILURE"):
        lines += [
            "## DECISION-RULE VERDICT",
            f"NMRI: {r['decision_rule']['verdict_nmri']}  "
            f"CMRI (secondary): {r['decision_rule']['verdict_cmri_secondary']}",
            r["decision_rule"]["reason"],
            "",
            "_Diagnostic failed -> per pre-registration, no detector was built; "
            "window size k is NOT iterated further as a post-hoc rescue._",
        ]
        return "\n".join(lines)

    vt = r["val_threshold_selection"]
    lines += [
        "## VAL threshold selection (fit on VAL only)",
        "| k | threshold | VAL Normal FPR | VAL pure-NMRI recall |",
        "|---:|---:|---:|---:|",
    ]
    for k, v in vt.items():
        lines.append(
            f"| {k} | {v['threshold']:.4f} | {100 * v['val_normal_fpr_achieved']:.4f}% "
            f"| {100 * v['val_pure_nmri_recall']:.2f}% |"
        )
    ac = r["artifact_check"]
    ts = r["test_scoring"]
    dr = r["decision_rule"]
    lines += [
        "",
        f"Winning k = {r['winning_k']} (highest VAL pure-NMRI recall); threshold = "
        f"{r['winning_threshold']:.4f}",
        "",
        f"## ARTIFACT CHECK: {'INFLATED -> gate applied' if ac['gate_applied'] else 'clean, no gate needed'}",
        f"median group A (post-attack) {ac['median_group_a']}  vs  "
        f"group B (in-bounds predecessor) {ac['median_group_b']}  "
        f"d={ac['cohens_d']:+.3f}  p={ac['mannwhitney_p']}",
        "",
        "## TEST scoring (scored once)",
        f"- z-rule alone Normal FPR: {100 * ts['z_rule_alone_normal_fpr']:.4f}% "
        f"({ts['z_rule_alone_normal_fp']}/{ts['z_rule_alone_normal_n']})",
        f"- recovered of the 150 known NMRI false negatives: "
        f"{ts['recovered_of_150_known_fn']}/150 "
        f"({100 * ts['recovered_of_150_fraction']:.2f}%)",
        f"- combined (comb OR z-rule) pure-NMRI recall: "
        f"{100 * ts['nmri_pure']['recall']:.2f}% ({ts['nmri_pure']['hits']}/{ts['nmri_pure']['n']})  "
        f"vs baseline {100 * dr['baseline_pure_nmri_recall']:.2f}%",
        f"- combined whole-TEST confusion TN/FP/FN/TP: "
        f"{ts['combined_whole_test_confusion']['tn']}/{ts['combined_whole_test_confusion']['fp']}/"
        f"{ts['combined_whole_test_confusion']['fn']}/{ts['combined_whole_test_confusion']['tp']}  "
        f"(delta {ts['combined_whole_test_confusion_delta']})",
        "",
        "### CMRI generalization check (secondary; same winning rule)",
        f"- combined pure-CMRI recall: {100 * ts['cmri_generalization']['combined_pure_recall']:.2f}% "
        f"({ts['cmri_generalization']['combined_pure_hits']}/{ts['cmri_generalization']['pure_n']})  "
        f"vs EXP-0028 bar {100 * dr['baseline_pure_cmri_recall_exp0028_bar']:.2f}%",
        f"- {dr['note_exp0028_comparison']}",
        "",
        f"## DECISION-RULE VERDICT — NMRI: {dr['verdict_nmri']}   "
        f"CMRI (secondary): {dr['verdict_cmri_secondary']}",
        f"- NMRI recall bar: {'PASS' if dr['passes_nmri_recall_bar'] else 'FAIL'}  "
        f"FPR bar: {'PASS' if dr['passes_nmri_fpr_bar'] else 'FAIL'}",
        f"- CMRI recall bar: {'PASS' if dr['passes_cmri_recall_bar'] else 'FAIL'}  "
        f"FPR bar: {'PASS' if dr['passes_cmri_fpr_bar'] else 'FAIL'}",
        f"- artifact check clean or gated: {dr['artifact_check_clean_or_gated']}",
        "",
        "_run_detector NOT modified; wiring this rule in is a separate decision._",
    ]
    return "\n".join(lines)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
