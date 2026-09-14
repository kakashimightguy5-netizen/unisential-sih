#!/usr/bin/env python3
"""EXP-0028 — CMRI trajectory-matching (DTW / nearest-neighbor discord) vs a
Normal reference library.

Fourth angle on the missed-CMRI line (after EXP-0018 AR(1) residual smoothness,
EXP-0019 raw rate-of-change bound, EXP-0020 rate-bound gated on in-bounds
predecessor — all CLOSED). Instead of a single-point or single-derivative
threshold, this compares the SHAPE of a trailing pressure sub-sequence against a
library of Normal-labelled shapes built from TRAIN only.

Measurement only; `ml/iforest_detector.run_detector` is NOT modified and NOT
called. EXP-0017 is reproduced from its checksummed saved artifact
(`exp0017_operational.load_result`) and asserted element-wise
`comb == protocol | pressure | IF` with whole-TEST confusion
(4767, 40, 2166, 2374) before anything else runs, exactly as EXP-0019/0020/0021.

Hard constraints (unchanged from the whole CMRI line): no `source` field, no
`crc_rate`, no other testbed/collection metadata; only decoded pressure and
values derived from it; only 0x03 read-response frames; TRAIN/VALIDATION/TEST
membership from the frozen checksummed manifest (`ml/exp0008_cadence_features
.load_pretest_split`), never rederived; threshold fit on VAL only; TEST scored
exactly once.

Library / distance implementation note: `dtaidistance` and `stumpy` were
attempted via `pip install` in this session but did not finish downloading
inside the available time budget (slow network; `llvmlite` alone is ~42 MB).
DTW and the nearest-neighbor "discord" score are therefore both implemented by
hand in this file: a standard O(n*m) dynamic-programming DTW (batched with
numpy across the whole reference library for speed) and a z-normalized
Euclidean nearest-neighbor distance to the same library (the matrix-profile
distance for two FIXED-length, non-warped sequences is exactly this Euclidean
NN distance, so no separate stumpy dependency is needed for the fixed-length
case used here). This is disclosed in the results doc.

Pressure is the ARFF-aligned "pressure measurement" value from the Mississippi
State ICS testbed dataset (Turnipseed 2015), used here as a simulated
diode-observer (egress-only) view — never real diode capture data.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0028).
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
RESULT_PATH = ROOT / "data" / "experiments" / "exp0028_cmri_trajectory.json"
CMRI = 2

# ---- pre-registered method constants ----
WINDOW_LENGTH_SAMPLES = 15         # sub-sequence length (spec: 10-20 samples)
GAP_TOLERANCE_FACTOR = 1.5         # x TRAIN-normal median 0x03 step Δt -> "no gap"
DEDUP_ROUND_DECIMALS = 4           # exact-duplicate collapse after rounding
MIN_LIBRARY_SIZE = 30
# Compute-tractability cap, fixed BEFORE any VAL/TEST score was computed (not a
# post-hoc rescue): 14,148 raw TRAIN-normal sub-sequences make an O(K) batched
# DTW against ~10-15k VAL/TEST candidates computationally infeasible in this
# session. Deterministic uniform-stride subsample to this many library rows.
LIBRARY_MAX_SIZE = 300
LIBRARY_SUBSAMPLE_SEED = 0

# ---- pre-registered decision rule (fixed; EXP-0028 spec) ----
BASELINE_PURE_CMRI_RECALL = 654 / 1198   # PressureBoundsRule alone, given/prior
MAX_NORMAL_FPR = 0.0030
ARTIFACT_ALPHA = 0.05
ARTIFACT_MIN_ABS_D = 0.2          # "small" effect threshold used elsewhere in this repo


# --------------------------------------------------------------- reference series

def train_normal_median_dt(series: Sequence[tuple[float, float]], blocks: Blocks) -> float:
    dts = [
        t1 - t0 for (t0, _), (t1, _) in zip(series, series[1:])
        if blocks.label(bucket_of(t0)) == "train_normal"
        and blocks.label(bucket_of(t1)) == "train_normal"
        and t1 > t0
    ]
    if len(dts) < 500:
        raise RuntimeError("too few TRAIN-normal 0x03 step gaps to fix a cadence")
    return float(np.median(dts))


def contiguous_runs(series: Sequence[tuple[float, float]], gap_tol: float,
                     keep_index) -> list[list[int]]:
    """Maximal runs of series indices with Δt in (0, gap_tol] between consecutive
    samples AND `keep_index(i)` true for every index in the run."""
    runs: list[list[int]] = []
    current: list[int] = []
    for i in range(len(series)):
        ok = keep_index(i)
        if ok and current and 0 < series[i][0] - series[i - 1][0] <= gap_tol:
            current.append(i)
        elif ok:
            if current:
                runs.append(current)
            current = [i]
        else:
            if current:
                runs.append(current)
            current = []
    if current:
        runs.append(current)
    return runs


def build_normal_library(series: Sequence[tuple[float, float]], blocks: Blocks,
                          gap_tol: float, length: int) -> np.ndarray:
    """Fixed-length pressure sub-sequences from Normal-labelled, contiguous (no
    data-gap) TRAIN stretches only. Deduplicated (exact match after rounding)."""
    is_train_normal = [blocks.label(bucket_of(t)) == "train_normal" for t, _ in series]
    runs = contiguous_runs(series, gap_tol, lambda i: is_train_normal[i])
    seen: set[tuple] = set()
    out: list[np.ndarray] = []
    for run in runs:
        if len(run) < length:
            continue
        values = np.array([series[i][1] for i in run], dtype=float)
        for start in range(len(values) - length + 1):
            seq = values[start:start + length]
            key = tuple(np.round(seq, DEDUP_ROUND_DECIMALS))
            if key in seen:
                continue
            seen.add(key)
            out.append(seq)
    if len(out) < MIN_LIBRARY_SIZE:
        raise RuntimeError(f"Normal reference library too small: {len(out)}")
    library = np.stack(out)
    if library.shape[0] > LIBRARY_MAX_SIZE:
        rng = np.random.default_rng(LIBRARY_SUBSAMPLE_SEED)
        keep = rng.choice(library.shape[0], size=LIBRARY_MAX_SIZE, replace=False)
        library = library[np.sort(keep)]
    return library


def z_normalize_rows(mat: np.ndarray) -> np.ndarray:
    mu = mat.mean(axis=-1, keepdims=True)
    sd = mat.std(axis=-1, keepdims=True)
    sd = np.where(sd < 1e-9, 1.0, sd)
    return (mat - mu) / sd


# --------------------------------------------------------------- distances

def dtw_nn_batch(query: np.ndarray, library: np.ndarray) -> float:
    """Nearest-neighbor DTW distance from `query` (L,) to every row of `library`
    (K, L), vectorized across the K library rows. Standard O(n*m) dynamic
    program, full (unconstrained) warping path, absolute-difference cost."""
    k, m = library.shape
    n = len(query)
    d_prev = np.full(m + 1, np.inf)
    d_prev[0] = 0.0
    d_prev = np.tile(d_prev, (k, 1))          # (k, m+1) row i-1
    for i in range(1, n + 1):
        d_cur = np.full((k, m + 1), np.inf)
        cost_row = np.abs(library - query[i - 1])   # (k, m)
        for j in range(1, m + 1):
            diag = d_prev[:, j - 1]
            up = d_prev[:, j]
            left = d_cur[:, j - 1]
            d_cur[:, j] = cost_row[:, j - 1] + np.minimum(np.minimum(diag, up), left)
        d_prev = d_cur
    return float(np.min(d_prev[:, m]))


def discord_nn_batch(query: np.ndarray, library: np.ndarray) -> float:
    """z-normalized Euclidean nearest-neighbor distance from `query` to every row
    of `library`. For fixed-length, non-warped sub-sequences this IS the
    matrix-profile distance against the reference set (a self-join discord score
    against a Normal reference, per the EXP-0028 spec)."""
    diffs = library - query
    return float(np.min(np.sqrt(np.sum(diffs * diffs, axis=1))))


# --------------------------------------------------------------- candidate scoring

def candidate_scores(series: Sequence[tuple[float, float]], gap_tol: float, length: int,
                      library_raw: np.ndarray, allowed_buckets: set[int]) -> tuple[dict, dict, dict]:
    """For every ALLOWED bucket that some sub-sequence ends in, the MAX (most
    anomalous) dtw / discord nearest-neighbor score over sub-sequences ending on
    a sample in that bucket (mirrors EXP-0019/0020's max-over-endings-in-window
    aggregation). `allowed_buckets` restricts the (expensive) DTW/discord
    computation to the VAL/TEST windows actually evaluated -- a compute-only
    restriction, not a data leak (the library is TRAIN-only regardless).
    Also returns, per bucket (ALL buckets, cheap), the LAST raw pressure sample
    observed in that bucket, for the in-bounds-predecessor artifact gate."""
    library_z = z_normalize_rows(library_raw)
    keep_index = lambda i: True
    runs = contiguous_runs(series, gap_tol, keep_index)
    dtw_by_win: dict[int, float] = {}
    discord_by_win: dict[int, float] = {}
    for run in runs:
        values = np.array([series[i][1] for i in run], dtype=float)
        times = [series[i][0] for i in run]
        for end in range(length - 1, len(run)):
            b = bucket_of(times[end])
            if b not in allowed_buckets:
                continue
            seq = values[end - length + 1:end + 1]
            q = z_normalize_rows(seq[None, :])[0]
            dtw = dtw_nn_batch(q, library_z)
            disc = discord_nn_batch(q, library_z)
            if b not in dtw_by_win or dtw > dtw_by_win[b]:
                dtw_by_win[b] = dtw
            if b not in discord_by_win or disc > discord_by_win[b]:
                discord_by_win[b] = disc
    last_pressure_by_win: dict[int, float] = {}
    for t, p in series:
        b = bucket_of(t)
        last_pressure_by_win[b] = p   # series ascending -> last write wins
    return dtw_by_win, discord_by_win, last_pressure_by_win


# --------------------------------------------------------------- eval helpers

def cohens_d(a: Sequence[float], b: Sequence[float]) -> float:
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if len(a) < 2 or len(b) < 2:
        return 0.0
    na, nb = len(a), len(b)
    pooled_var = ((na - 1) * a.var(ddof=1) + (nb - 1) * b.var(ddof=1)) / (na + nb - 2)
    pooled = math.sqrt(pooled_var) if pooled_var > 0 else 0.0
    return 0.0 if pooled == 0 else float((a.mean() - b.mean()) / pooled)


def val_windows(blocks: Blocks, all_windows) -> list:
    return [w for w in all_windows if w.w_index in blocks.validation]


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


def rule_recall(cmri_mask: np.ndarray, fired: np.ndarray) -> tuple[int, int, float]:
    n = int(cmri_mask.sum())
    hits = int(fired[cmri_mask].sum())
    return hits, n, (hits / n if n else 0.0)


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
    median_dt = train_normal_median_dt(series, blocks)
    gap_tol = GAP_TOLERANCE_FACTOR * median_dt

    library_raw = build_normal_library(series, blocks, gap_tol, WINDOW_LENGTH_SAMPLES)

    all_windows = sorted(build_windows(), key=lambda w: w.w_index)
    is_attack_by_win = {w.w_index: w.is_attack for w in all_windows}
    v_windows = val_windows(blocks, all_windows)
    allowed_buckets = {w.w_index for w in v_windows} | {w.w_index for w in test_windows}

    dtw_by_win, discord_by_win, last_pressure_by_win = candidate_scores(
        series, gap_tol, WINDOW_LENGTH_SAMPLES, library_raw, allowed_buckets,
    )

    def build_frame(windows):
        idx = np.array([w.w_index for w in windows], dtype=int)
        dtw = np.array([dtw_by_win.get(i, np.nan) for i in idx], dtype=float)
        disc = np.array([discord_by_win.get(i, np.nan) for i in idx], dtype=float)
        defined = ~np.isnan(dtw) & ~np.isnan(disc)
        pred_pressure = np.array(
            [last_pressure_by_win.get(i - 1, np.nan) for i in idx], dtype=float,
        )
        pred_in_bounds = (pred_pressure >= bounds[0]) & (pred_pressure <= bounds[1])
        pred_attack = np.array(
            [bool(is_attack_by_win.get(i - 1, 0)) for i in idx], dtype=bool,
        )
        categories = [set(w.categories) for w in windows]
        normal_mask = np.array([c == {0} for c in categories], dtype=bool)
        cmri_pure = np.array([CMRI in c and c <= {0, CMRI} for c in categories], dtype=bool)
        cmri_dominant = np.array(
            [([x for x in c if x != 0] or [0])[0] == CMRI for c in categories], dtype=bool,
        )
        cmri_containing = np.array([CMRI in c for c in categories], dtype=bool)
        return {
            "idx": idx, "dtw": dtw, "discord": disc, "defined": defined,
            "pred_in_bounds": pred_in_bounds, "pred_attack": pred_attack,
            "normal_mask": normal_mask, "cmri_pure": cmri_pure,
            "cmri_dominant": cmri_dominant, "cmri_containing": cmri_containing,
        }

    val_f = build_frame(v_windows)
    test_f = build_frame(test_windows)

    # -------- step 3: mandatory artifact diagnostic (VAL + TEST pooled) --------
    def pooled(field):
        return np.concatenate([val_f[field], test_f[field]])

    normal_all = pooled("normal_mask") & pooled("defined")
    pred_attack_all = pooled("pred_attack")
    pred_in_bounds_all = pooled("pred_in_bounds")
    dtw_all = pooled("dtw")
    disc_all = pooled("discord")

    group_a = normal_all & pred_attack_all          # follows a flagged/attack window
    group_b = normal_all & pred_in_bounds_all        # in-bounds predecessor

    artifact = {}
    for name, arr in (("dtw", dtw_all), ("discord", disc_all)):
        a = arr[group_a]
        b = arr[group_b]
        d = cohens_d(a, b)
        u = p = None
        if len(a) > 1 and len(b) > 1:
            u_stat, p_val = mannwhitneyu(a, b, alternative="two-sided")
            u, p = float(u_stat), float(p_val)
        inflated = bool(
            d >= ARTIFACT_MIN_ABS_D and p is not None and p < ARTIFACT_ALPHA
            and np.median(a) > np.median(b) if len(a) and len(b) else False
        )
        artifact[name] = {
            "n_group_a_post_attack_normal": int(len(a)),
            "n_group_b_in_bounds_predecessor_normal": int(len(b)),
            "median_group_a": float(np.median(a)) if len(a) else None,
            "median_group_b": float(np.median(b)) if len(b) else None,
            "cohens_d": d, "mannwhitney_u": u, "mannwhitney_p": p,
            "inflated_relative_to_group_b": inflated,
        }
    artifact_present = any(artifact[k]["inflated_relative_to_group_b"] for k in artifact)
    gate_applied = artifact_present

    # -------- gate application (only if artifact check flags inflation) --------
    def gated_defined(frame):
        d = frame["defined"].copy()
        if gate_applied:
            d = d & frame["pred_in_bounds"]
        return d

    val_defined = gated_defined(val_f)
    test_defined = gated_defined(test_f)

    # -------- step 4: threshold selection on VAL only --------
    val_normal = val_f["normal_mask"] & val_defined
    thresholds = {}
    val_report = {}
    for name, arr in (("dtw", val_f["dtw"]), ("discord", val_f["discord"])):
        normal_scores = arr[val_normal]
        threshold, achieved_fpr = fit_threshold(normal_scores, MAX_NORMAL_FPR)
        fired = (arr > threshold) & val_defined
        hits, n_cmri, recall = rule_recall(val_f["cmri_pure"], fired.astype(int))
        thresholds[name] = threshold
        val_report[name] = {
            "threshold": threshold, "val_normal_n": int(len(normal_scores)),
            "val_normal_fpr_achieved": achieved_fpr,
            "val_pure_cmri_hits": hits, "val_pure_cmri_n": n_cmri,
            "val_pure_cmri_recall": recall,
        }

    # pick whichever metric has the higher VAL pure-CMRI recall at its own bar
    primary_metric = max(("dtw", "discord"), key=lambda k: val_report[k]["val_pure_cmri_recall"])

    # -------- step 5: score TEST exactly once --------
    test_normal = test_f["normal_mask"] & test_defined
    test_out = {}
    for name, arr in (("dtw", test_f["dtw"]), ("discord", test_f["discord"])):
        threshold = thresholds[name]
        fired = ((arr > threshold) & test_defined).astype(int)
        n_neg = int(test_normal.sum())
        fp_n = int(fired[test_normal].sum())
        fpr = fp_n / n_neg if n_neg else 0.0
        pure_hits, pure_n, pure_recall = rule_recall(test_f["cmri_pure"], fired)
        dom_hits, dom_n, dom_recall = rule_recall(test_f["cmri_dominant"], fired)
        cont_hits, cont_n, cont_recall = rule_recall(test_f["cmri_containing"], fired)
        test_out[name] = {
            "threshold": threshold,
            "test_normal_n": n_neg, "test_normal_fp": fp_n, "test_normal_fpr": fpr,
            "pure_cmri": {"hits": pure_hits, "n": pure_n, "recall": pure_recall},
            "dominant_cmri": {"hits": dom_hits, "n": dom_n, "recall": dom_recall},
            "containing_cmri": {"hits": cont_hits, "n": cont_n, "recall": cont_recall},
        }

    primary = test_out[primary_metric]
    passes_recall = primary["pure_cmri"]["recall"] > BASELINE_PURE_CMRI_RECALL
    passes_fpr = primary["test_normal_fpr"] <= MAX_NORMAL_FPR
    artifact_clean_or_gated = (not artifact_present) or gate_applied
    go = bool(passes_recall and passes_fpr and artifact_clean_or_gated)
    verdict = "GO" if go else "NO-GO"

    return {
        "status": "VALIDATED — TEST SCORED ONCE; run_detector NOT modified",
        "experiment": "EXP-0028",
        "identity_gates": {
            "exp0017_artifact_loaded_and_verified": True,
            "comb_equals_protocol_or_pressure_or_if": gate_elementwise,
            "whole_test_confusion_matches_exp0017": bool(gate_confusion),
            "exp0017_confusion": list(EXP0017_TEST_CONFUSION),
            "exp0016_bounds": list(bounds),
            "run_detector_modified": False,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "distance_library_note": (
            "dtaidistance/stumpy pip installs did not finish inside the session's "
            "time budget; DTW is a hand-written O(n*m) dynamic program (batched with "
            "numpy over the reference library); the discord score is a z-normalized "
            "Euclidean nearest-neighbor distance to the same library, which equals "
            "the matrix-profile distance for the fixed-length, non-warped case used "
            "here."
        ),
        "method": {
            "window_length_samples": WINDOW_LENGTH_SAMPLES,
            "train_normal_median_0x03_step_seconds": median_dt,
            "gap_tolerance_seconds": gap_tol,
            "gap_tolerance_factor": GAP_TOLERANCE_FACTOR,
            "library_size_after_dedup": int(library_raw.shape[0]),
            "dedup_round_decimals": DEDUP_ROUND_DECIMALS,
            "per_window_score": (
                "max nearest-neighbor DTW / discord distance over sub-sequences "
                "ending on a sample inside the window; undefined if no full-length "
                "contiguous (no-gap) sub-sequence ends there"
            ),
        },
        "artifact_check": {
            "definition": (
                "group A: pure-Normal window whose immediate predecessor window "
                "(w_index - 1) is attack-labelled. group B: pure-Normal window whose "
                "immediate predecessor's last observed pressure sample is within the "
                "EXP-0016 TRAIN-normal bounds. Pooled over VAL+TEST, descriptive only."
            ),
            "per_metric": artifact,
            "artifact_present": artifact_present,
            "gate_applied": gate_applied,
            "gate_rule": (
                "only if artifact_present: restrict scoring (threshold fit AND TEST "
                "scoring) to windows whose predecessor's last pressure sample is "
                "within the EXP-0016 bounds, as EXP-0020 did for the rate rule"
            ),
        },
        "val_threshold_selection": val_report,
        "primary_metric": primary_metric,
        "test_scoring": test_out,
        "decision_rule": {
            "baseline_pure_cmri_recall": BASELINE_PURE_CMRI_RECALL,
            "baseline_pure_cmri_recall_pct": round(100 * BASELINE_PURE_CMRI_RECALL, 2),
            "max_normal_fpr": MAX_NORMAL_FPR,
            "primary_metric_test_pure_cmri_recall": primary["pure_cmri"]["recall"],
            "primary_metric_test_normal_fpr": primary["test_normal_fpr"],
            "passes_recall_bar": passes_recall,
            "passes_fpr_bar": passes_fpr,
            "artifact_check_clean_or_gated": artifact_clean_or_gated,
            "verdict": verdict,
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "scipy": version("scipy"), "scikit_learn": version("scikit-learn"),
        },
        "limitations": [
            "Pressure is the ARFF-aligned value, not a live 0x03 byte decode; register "
            "map/scale undocumented.",
            "dtaidistance/stumpy unavailable within the session time budget; DTW and "
            "the discord score are hand-written, not library-verified against a "
            "reference implementation.",
            "The Normal reference library is built once from TRAIN and never refit "
            "on VAL/TEST; sub-sequences overlap heavily (stride 1) before dedup, so "
            "library diversity is bounded by how much the TRAIN-normal process moves.",
            "Per-window score is a max over sub-sequence endings inside the window, "
            "matching EXP-0019/0020's aggregation style, not an average.",
            "EXP-0018/0019/0020 have each scored the frozen TEST set once against a "
            "pressure hypothesis about the missed CMRI; this is the fourth — a "
            "garden-of-forking-paths risk disclosed across the whole line.",
            "One testbed; egress-only; measurement only, nothing wired in.",
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
    dr = r["decision_rule"]
    m = r["method"]
    ac = r["artifact_check"]
    vt = r["val_threshold_selection"]
    ts = r["test_scoring"]
    lines = [
        "# EXP-0028 — CMRI trajectory-matching (DTW / discord) vs Normal reference library",
        "",
        f"run_detector() modified: {r['identity_gates']['run_detector_modified']}",
        f"Library size after dedup: {m['library_size_after_dedup']}  "
        f"window_length={m['window_length_samples']} samples  "
        f"gap_tolerance={m['gap_tolerance_seconds']:.3f}s",
        "",
        f"## ARTIFACT CHECK: {'PRESENT -> gate applied' if ac['gate_applied'] else 'clean, no gate needed'}",
        "| metric | median group A (post-attack) | median group B (in-bounds pred) | d | MW p | inflated |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for name, a in ac["per_metric"].items():
        lines.append(
            f"| {name} | {a['median_group_a']:.4f} | {a['median_group_b']:.4f} | "
            f"{a['cohens_d']:+.3f} | {a['mannwhitney_p']:.3g} | {a['inflated_relative_to_group_b']} |"
        )
    lines += ["", "## VAL threshold selection (fit on VAL only)",
              "| metric | threshold | VAL Normal FPR | VAL pure-CMRI recall |",
              "|---|---:|---:|---:|"]
    for name, v in vt.items():
        lines.append(
            f"| {name} | {v['threshold']:.4f} | {100 * v['val_normal_fpr_achieved']:.4f}% "
            f"| {100 * v['val_pure_cmri_recall']:.2f}% |"
        )
    lines += ["", f"Primary metric (higher VAL recall): **{r['primary_metric']}**", "",
              "## TEST scoring (scored once)",
              "| metric | Normal FPR | pure-CMRI recall | dominant-CMRI recall | containing-CMRI recall |",
              "|---|---:|---:|---:|---:|"]
    for name, t in ts.items():
        lines.append(
            f"| {name} | {100 * t['test_normal_fpr']:.4f}% "
            f"| {100 * t['pure_cmri']['recall']:.2f}% ({t['pure_cmri']['hits']}/{t['pure_cmri']['n']}) "
            f"| {100 * t['dominant_cmri']['recall']:.2f}% "
            f"| {100 * t['containing_cmri']['recall']:.2f}% |"
        )
    lines += [
        "",
        f"## DECISION-RULE VERDICT: {dr['verdict']}",
        f"- baseline pure-CMRI recall (PressureBoundsRule alone): {dr['baseline_pure_cmri_recall_pct']}%",
        f"- primary metric ({r['primary_metric']}) TEST pure-CMRI recall: "
        f"{100 * dr['primary_metric_test_pure_cmri_recall']:.2f}%  "
        f"({'beats' if dr['passes_recall_bar'] else 'does NOT beat'} baseline)",
        f"- primary metric TEST Normal FPR: {100 * dr['primary_metric_test_normal_fpr']:.4f}%  "
        f"(bar <= 0.30%, {'PASS' if dr['passes_fpr_bar'] else 'FAIL'})",
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
