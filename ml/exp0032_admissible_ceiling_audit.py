#!/usr/bin/env python3
"""EXP-0032 — admissible-information ceiling audit for the residual NMRI/CMRI
false negatives, using a supervised XGBoost classifier purely as an
information probe (NOT a detector build).

Four structurally different framings (EXP-0018 AR(1) residual energy,
EXP-0019 rate-of-change plausibility, EXP-0020 rate-bound gated on an
in-bounds predecessor, EXP-0028 DTW/discord trajectory matching, EXP-0029
regime-local median/MAD baseline) have all been NO-GO on the residual
NMRI/CMRI false negatives left after EXP-0017's combined rule. Before
building EXP-0030 (IEEE-754 float-provenance) or EXP-0031 (event-level
distribution fingerprint) as full detectors, this experiment cheaply probes
whether ANY recoverable signal exists in admissible features at all, and
which feature family (if any) carries it.

`ml/iforest_detector.run_detector` is NOT modified and NOT called beyond
identity-gate reproduction via the frozen `exp0017_operational.load_result`
artifact, exactly as EXP-0018/0019/0020/0021/0028/0029. EXP-0017 is
reproduced and asserted element-wise `comb == protocol | pressure | IF`
with whole-TEST confusion (4767, 40, 2166, 2374) before anything else runs.

Hard constraints (unchanged from the whole missed-NMRI/CMRI line): no
`source` field, no `crc_rate`, no filename/collection/run-ID metadata, no
other testbed artifact, ever. Only features causally available behind the
diode at (or before) the response frame: the decoded pressure value (raw
and derived), its IEEE-754 bit-level representation, and a trailing,
strictly-causal sample buffer's distribution statistics. TRAIN/VAL/TEST
membership from the frozen checksummed manifest
(`exp0008_cadence_features.load_pretest_split` via the `Blocks()` helper
used in exp0019/exp0028/exp0029), never rederived. Feature selection and
hyperparameter selection happen on TRAIN/VAL only; TEST is touched exactly
once, at the very end, purely to report a final honest number — it plays
NO role in the pre-registered decision rule below, which is judged on
event-grouped VAL bootstrap versus a label-permutation null.

Adaptation disclosed up front (documented explicitly, same convention as
EXP-0028's dtaidistance/stumpy substitution): the frozen EXP-0017 artifact
(`exp0017_operational.load_result`) only carries the combined rule's
predictions (`comb_pred`) for the TEST block; TRAIN/VAL windows have no
saved `comb_pred`. Reproducing the full combined rule (protocol + pressure
+ Isolation Forest) for TRAIN/VAL would require calling
`ml/iforest_detector.run_detector`, which this diagnostic is forbidden from
doing beyond the frozen-artifact identity gate. The "windows the current
rule already misses" residual cohort is therefore defined per split as
follows:
  - TEST: exactly `comb_pred == 0` from the frozen artifact (exact).
  - TRAIN / VALIDATION: the EXP-0016 pressure-bounds component ALONE
    (`pred rule fires` iff the window's own pressure samples are not all
    within `R.pressure_bounds`), reproduced from the frozen, checksummed
    `pressure_bounds` tuple — the cheapest exactly-reproducible piece of
    the combined rule. This proxy cohort is therefore a slight
    over-approximation of the true (protocol+pressure+IF) residual on
    TRAIN/VAL: a handful of windows the protocol rule or the Isolation
    Forest would independently catch may be retained as "residual" there.
    This is disclosed as a limitation; it does not touch TEST, where the
    exact frozen `comb_pred` is used, and it does not touch the decision
    rule's TEST-scoring step (touched once, exact `comb_pred`).

Pressure is the ARFF-aligned "pressure measurement" value — egress traffic
extracted from Mississippi State ICS testbed dataset, used as a simulated
diode-observer view — never real diode capture data.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0032).
"""
from __future__ import annotations

import json
import math
import os
import platform
import struct
from importlib.metadata import version
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
from scipy.stats import kurtosis as _scipy_kurtosis
from scipy.stats import skew as _scipy_skew
from scipy.stats import wasserstein_distance
from xgboost import XGBClassifier

from exp0017_operational import load_result
from exp0019_pressure_rate_plausibility import (
    Blocks, EXP0017_TEST_CONFUSION, align_egress_pressure_timeseries, bucket_of,
)
from features_windowed import build_windows

ROOT = Path(__file__).resolve().parent.parent
RESULT_PATH = ROOT / "data" / "experiments" / "exp0032_admissible_ceiling_audit.json"
NMRI = 1
CMRI = 2

# ---- pre-registered method constants (fixed BEFORE any VAL/TEST score) ----
TRAILING_BUFFER_SAMPLES = 30           # causal trailing sample buffer for F3
MANTISSA_LOW_BITS = 8                  # F2: low-order mantissa bit pattern width
QUANTIZATION_STEPS = (0.001, 0.01, 0.1, 0.5, 1.0)
ADC_LATTICE_STEPS = (0.0625, 0.125, 0.25)   # a DIFFERENT candidate grid than
                                             # quantization, per spec item F2
ENTROPY_HIST_BINS = 10
WASSERSTEIN_REF_MAX_SIZE = 500          # compute-tractability cap on the
WASSERSTEIN_REF_SEED = 0                # TRAIN-normal reference sample (disclosed,
                                         # same pattern as EXP-0028's LIBRARY_MAX_SIZE)

N_BOOTSTRAP = 60                        # event-grouped VAL bootstrap resamples;
BOOTSTRAP_SEED = 0                      # reduced from the spec's illustrative 200
N_PERMUTATIONS = 20                     # label-permutation null draws; reduced from
PERMUTATION_SEED = 1                    # the spec's illustrative 50-200 for session
                                         # compute-time tractability (disclosed)
MAX_NORMAL_FPR = 0.0030

XGB_PARAMS = dict(
    n_estimators=150, max_depth=4, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8, reg_lambda=1.0,
    random_state=0, n_jobs=-1, eval_metric="logloss",
    objective="binary:logistic",
)

FAMILIES = ("F1", "F2", "F3", "combined")
BASELINE_NMRI_CEILING = 0.7902
BASELINE_CMRI_CEILING = 0.5459


# --------------------------------------------------------------- IEEE-754 helpers

def ieee754_bits(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (exponent, mantissa_low_bits, trailing_zero_bits) for an array of
    float64 values, decoded from the raw IEEE-754 bit pattern only (no library
    float-formatting heuristics)."""
    values = np.asarray(values, dtype=np.float64)
    bits = values.view(np.uint64)
    exponent = ((bits >> np.uint64(52)) & np.uint64(0x7FF)).astype(np.int64)
    mantissa = bits & np.uint64((1 << 52) - 1)
    low_mask = np.uint64((1 << MANTISSA_LOW_BITS) - 1)
    mantissa_low = (mantissa & low_mask).astype(np.int64)
    trailing_zero = np.zeros(len(values), dtype=np.int64)
    for i, m in enumerate(mantissa.tolist()):
        if m == 0:
            trailing_zero[i] = 52
        else:
            trailing_zero[i] = int(bin(m & -m)[::-1].index("1")) if m else 52
    return exponent, mantissa_low, trailing_zero


def nearest_reference_distance(values: np.ndarray, reference_sorted: np.ndarray) -> np.ndarray:
    """|value - nearest reference value| via binary search; `reference_sorted`
    must already be sorted ascending and non-empty."""
    values = np.asarray(values, dtype=float)
    if len(reference_sorted) == 0:
        return np.full(len(values), np.nan)
    idx = np.searchsorted(reference_sorted, values)
    idx_lo = np.clip(idx - 1, 0, len(reference_sorted) - 1)
    idx_hi = np.clip(idx, 0, len(reference_sorted) - 1)
    d_lo = np.abs(values - reference_sorted[idx_lo])
    d_hi = np.abs(values - reference_sorted[idx_hi])
    return np.minimum(d_lo, d_hi)


def quantization_grid_distance(values: np.ndarray, steps: Sequence[float]) -> np.ndarray:
    """For each value, the minimum over `steps` of the distance to the nearest
    multiple of that step (a proxy for 'apparent quantization step')."""
    values = np.asarray(values, dtype=float)
    out = np.full(len(values), np.inf)
    for step in steps:
        remainder = np.abs(values / step - np.round(values / step)) * step
        out = np.minimum(out, remainder)
    return out


def mantissa_low_bits_entropy(mantissa_low: np.ndarray, n_bits: int = MANTISSA_LOW_BITS) -> float:
    """Empirical Shannon entropy (base 2, bits) of the low-order mantissa bit
    pattern over a (typically trailing-buffer) sample of values. Returns 0.0
    for fewer than 2 samples."""
    mantissa_low = np.asarray(mantissa_low, dtype=int)
    if len(mantissa_low) < 2:
        return 0.0
    counts = np.bincount(mantissa_low, minlength=1 << n_bits).astype(float)
    probs = counts[counts > 0] / counts.sum()
    return float(-np.sum(probs * np.log2(probs)))


# --------------------------------------------------------------- F3 distribution helpers

def distribution_features(buffer: np.ndarray, hist_range: tuple[float, float],
                           reference_sample: np.ndarray) -> dict[str, float]:
    """Per-window event-level distribution features over a trailing sample
    buffer. `reference_sample` is the (capped) TRAIN-normal reference used
    for the Wasserstein-1 distance-from-Normal-distribution feature."""
    buf = np.asarray(buffer, dtype=float)
    n = len(buf)
    out: dict[str, float] = {}
    quantile_ps = (1, 5, 10, 25, 50, 75, 90, 95, 99)
    if n == 0:
        for p in quantile_ps:
            out[f"q{p:02d}"] = 0.0
        out.update({
            "iqr_10_90": 0.0, "iqr_25_75": 0.0, "skewness": 0.0, "kurtosis": 0.0,
            "unique_count": 0.0, "repetition_rate": 0.0, "entropy": 0.0,
            "histogram_occupancy": 0.0, "max_gap": 0.0, "wasserstein_to_train_normal": 0.0,
        })
        return out
    qvals = {p: float(np.percentile(buf, p)) for p in quantile_ps}
    for p in quantile_ps:
        out[f"q{p:02d}"] = qvals[p]
    out["iqr_10_90"] = qvals[90] - qvals[10]
    out["iqr_25_75"] = qvals[75] - qvals[25]
    out["skewness"] = float(_scipy_skew(buf)) if n >= 3 and np.std(buf) > 0 else 0.0
    out["kurtosis"] = float(_scipy_kurtosis(buf)) if n >= 4 and np.std(buf) > 0 else 0.0
    uniq = np.unique(buf)
    out["unique_count"] = float(len(uniq))
    out["repetition_rate"] = float(1.0 - len(uniq) / n)
    lo, hi = hist_range
    if hi > lo:
        hist, _ = np.histogram(buf, bins=ENTROPY_HIST_BINS, range=(lo, hi))
        probs = hist[hist > 0] / hist.sum()
        out["entropy"] = float(-np.sum(probs * np.log2(probs))) if hist.sum() else 0.0
        out["histogram_occupancy"] = float(np.count_nonzero(hist) / ENTROPY_HIST_BINS)
    else:
        out["entropy"] = 0.0
        out["histogram_occupancy"] = 0.0
    out["max_gap"] = float(np.max(np.diff(uniq))) if len(uniq) > 1 else 0.0
    if len(reference_sample) > 0 and n > 0:
        out["wasserstein_to_train_normal"] = float(wasserstein_distance(buf, reference_sample))
    else:
        out["wasserstein_to_train_normal"] = 0.0
    return out


# --------------------------------------------------------------- event grouping / resampling

def contiguous_events(idx: np.ndarray) -> list[np.ndarray]:
    """Group row POSITIONS (0..len(idx)-1) into maximal runs of consecutive
    integer window indices (idx[i+1] == idx[i] + 1). `idx` need not be
    globally contiguous; gaps start a new event."""
    idx = np.asarray(idx)
    events: list[list[int]] = []
    current: list[int] = []
    for pos in range(len(idx)):
        if current and idx[pos] == idx[current[-1]] + 1:
            current.append(pos)
        else:
            if current:
                events.append(current)
            current = [pos]
    if current:
        events.append(current)
    return [np.array(e, dtype=int) for e in events]


def event_grouped_bootstrap_resample(events: Sequence[np.ndarray], rng: np.random.Generator) -> np.ndarray:
    """Sample len(events) events WITH replacement and concatenate their row
    positions; whole episodes are resampled together, never individual rows."""
    if not events:
        return np.array([], dtype=int)
    n = len(events)
    chosen = rng.integers(0, n, size=n)
    return np.concatenate([events[i] for i in chosen]) if n else np.array([], dtype=int)


def event_grouped_permute_labels(events: Sequence[np.ndarray], labels: np.ndarray,
                                  rng: np.random.Generator) -> np.ndarray:
    """Shuffle EVENT-LEVEL labels across events (a permutation, not an
    independent per-row shuffle): each event keeps its row count, but the
    (assumed-constant-within-event) label values are reassigned by a random
    permutation of the event list. Rows within an event whose original
    labels were not uniform (shouldn't happen for well-formed events) take
    the event's majority label before the permutation."""
    labels = np.asarray(labels)
    out = labels.copy()
    if not events:
        return out
    event_labels = []
    for ev in events:
        vals, counts = np.unique(labels[ev], return_counts=True)
        event_labels.append(vals[np.argmax(counts)])
    event_labels = np.asarray(event_labels)
    perm = rng.permutation(len(events))
    shuffled = event_labels[perm]
    for ev, lab in zip(events, shuffled):
        out[ev] = lab
    return out


# --------------------------------------------------------------- eval helpers

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


def recall_at_threshold(scores: np.ndarray, labels: np.ndarray, threshold: float) -> float:
    pos = labels == 1
    n_pos = int(pos.sum())
    if n_pos == 0:
        return 0.0
    return float(((scores > threshold) & pos).sum()) / n_pos


def percentile_ci(values: Sequence[float], lo: float = 2.5, hi: float = 97.5) -> tuple[float, float]:
    if len(values) == 0:
        return (0.0, 0.0)
    arr = np.asarray(values, dtype=float)
    return float(np.percentile(arr, lo)), float(np.percentile(arr, hi))


CAUSALITY_TABLE = {
    "last_pressure": ("F1", True, False, False),
    "abs_delta_predecessor": ("F1", True, False, False),
    "step_rate": ("F1", True, False, False),
    "exponent": ("F2", True, False, False),
    "mantissa_low_bits": ("F2", True, False, False),
    "trailing_zero_bits": ("F2", True, False, False),
    "ulp_distance_to_train_normal": ("F2", True, False, False),
    "quantization_distance": ("F2", True, False, False),
    "adc_lattice_distance": ("F2", True, False, False),
    "mantissa_entropy_local": ("F2", True, False, False),
    "q01": ("F3", True, False, False), "q05": ("F3", True, False, False),
    "q10": ("F3", True, False, False), "q25": ("F3", True, False, False),
    "q50": ("F3", True, False, False), "q75": ("F3", True, False, False),
    "q90": ("F3", True, False, False), "q95": ("F3", True, False, False),
    "q99": ("F3", True, False, False),
    "iqr_10_90": ("F3", True, False, False), "iqr_25_75": ("F3", True, False, False),
    "skewness": ("F3", True, False, False), "kurtosis": ("F3", True, False, False),
    "unique_count": ("F3", True, False, False), "repetition_rate": ("F3", True, False, False),
    "entropy": ("F3", True, False, False), "histogram_occupancy": ("F3", True, False, False),
    "max_gap": ("F3", True, False, False),
    "wasserstein_to_train_normal": ("F3", True, False, False),
}


def build_causality_audit(feature_names: Sequence[str], importances: Sequence[float],
                           top_k: int = 10) -> list[dict]:
    """For the `top_k` highest-importance features, look up the pre-registered
    causality answers (family, derived-from-egress-response, uses-future-data,
    uses-labels-indirectly) and compute a `keep` verdict: keep unless it
    uses future data or indirectly leaks labels."""
    order = np.argsort(importances)[::-1][:top_k]
    rows = []
    for i in order:
        name = feature_names[i]
        family, from_egress, uses_future, uses_labels = CAUSALITY_TABLE.get(
            name, ("unknown", False, True, True),
        )
        keep = bool(from_egress and not uses_future and not uses_labels)
        rows.append({
            "feature": name, "family": family, "importance": float(importances[i]),
            "derived_from_egress_response": from_egress, "uses_future_data": uses_future,
            "uses_labels_indirectly": uses_labels, "keep": keep,
        })
    return rows


# --------------------------------------------------------------- feature assembly

class SeriesIndex:
    """Aligned egress pressure series plus a bucket -> sample-position lookup,
    built once and shared across every window/feature computation."""

    def __init__(self, series: Sequence[tuple[float, float]]):
        self.times = np.array([t for t, _ in series], dtype=float)
        self.values = np.array([p for _, p in series], dtype=float)
        self.bucket_by_pos = np.array([bucket_of(t) for t in self.times], dtype=int)
        self.positions_by_bucket: dict[int, list[int]] = {}
        for pos, b in enumerate(self.bucket_by_pos):
            self.positions_by_bucket.setdefault(int(b), []).append(pos)


def window_row(si: SeriesIndex, w_index: int, train_normal_sorted: np.ndarray,
               train_normal_ref_sample: np.ndarray, hist_range: tuple[float, float],
               ) -> dict[str, float] | None:
    """Single feature row for one window. Returns None (undefined) if the
    window has no own pressure sample."""
    positions = si.positions_by_bucket.get(w_index)
    if not positions:
        return None
    last_pos = positions[-1]
    value = float(si.values[last_pos])
    row: dict[str, float] = {}

    # ---- F1: numeric pressure + EXP-0019/20-style derivative (baseline sanity) ----
    row["last_pressure"] = value
    if last_pos > 0:
        dt = si.times[last_pos] - si.times[last_pos - 1]
        dp = abs(value - si.values[last_pos - 1])
        row["abs_delta_predecessor"] = dp
        row["step_rate"] = dp / dt if dt > 0 else 0.0
    else:
        row["abs_delta_predecessor"] = 0.0
        row["step_rate"] = 0.0

    # ---- F2: IEEE-754 representation features ----
    exponent, mantissa_low, trailing_zero = ieee754_bits(np.array([value]))
    row["exponent"] = float(exponent[0])
    row["mantissa_low_bits"] = float(mantissa_low[0])
    row["trailing_zero_bits"] = float(trailing_zero[0])
    row["ulp_distance_to_train_normal"] = float(
        nearest_reference_distance(np.array([value]), train_normal_sorted)[0]
    )
    row["quantization_distance"] = float(
        quantization_grid_distance(np.array([value]), QUANTIZATION_STEPS)[0]
    )
    row["adc_lattice_distance"] = float(
        quantization_grid_distance(np.array([value]), ADC_LATTICE_STEPS)[0]
    )
    buf_start = max(0, last_pos - TRAILING_BUFFER_SAMPLES + 1)
    buffer = si.values[buf_start:last_pos + 1]
    _, buffer_mantissa_low, _ = ieee754_bits(buffer)
    row["mantissa_entropy_local"] = mantissa_low_bits_entropy(buffer_mantissa_low)

    # ---- F3: event-level (per-window trailing-buffer) distribution features ----
    row.update(distribution_features(buffer, hist_range, train_normal_ref_sample))
    return row


F1_NAMES = ["last_pressure", "abs_delta_predecessor", "step_rate"]
F2_NAMES = [
    "exponent", "mantissa_low_bits", "trailing_zero_bits",
    "ulp_distance_to_train_normal", "quantization_distance", "adc_lattice_distance",
    "mantissa_entropy_local",
]
F3_NAMES = [
    "q01", "q05", "q10", "q25", "q50", "q75", "q90", "q95", "q99",
    "iqr_10_90", "iqr_25_75", "skewness", "kurtosis", "unique_count",
    "repetition_rate", "entropy", "histogram_occupancy", "max_gap",
    "wasserstein_to_train_normal",
]
FEATURE_FAMILIES = {"F1": F1_NAMES, "F2": F2_NAMES, "F3": F3_NAMES,
                    "combined": F1_NAMES + F2_NAMES + F3_NAMES}


def rows_to_matrix(rows: Sequence[dict[str, float]], names: Sequence[str]) -> np.ndarray:
    return np.array([[r[n] for n in names] for r in rows], dtype=float)


# --------------------------------------------------------------- cohort construction

def _pure_mask(categories_list: Sequence[frozenset], cat: int) -> np.ndarray:
    return np.array([cat in c and c <= {0, cat} for c in categories_list], dtype=bool)


def _normal_mask(categories_list: Sequence[frozenset]) -> np.ndarray:
    return np.array([c == {0} for c in categories_list], dtype=bool)


def build_cohort_frame(windows, si: SeriesIndex, bounds: tuple[float, float],
                        train_normal_sorted: np.ndarray, train_normal_ref_sample: np.ndarray,
                        hist_range: tuple[float, float]) -> dict:
    idx = np.array([w.w_index for w in windows], dtype=int)
    categories = [set(w.categories) for w in windows]
    rows, defined = [], []
    for w in windows:
        r = window_row(si, w.w_index, train_normal_sorted, train_normal_ref_sample, hist_range)
        defined.append(r is not None)
        rows.append(r if r is not None else {n: 0.0 for n in FEATURE_FAMILIES["combined"]})
    defined = np.array(defined, dtype=bool)
    return {
        "idx": idx, "categories": categories, "defined": defined,
        "nmri_pure": _pure_mask(categories, NMRI), "cmri_pure": _pure_mask(categories, CMRI),
        "normal": _normal_mask(categories), "rows": rows,
    }


def pressure_rule_proxy_fires(si: SeriesIndex, w_index: int, bounds: tuple[float, float]) -> bool | None:
    """Reproduces the EXP-0016 pressure-bounds component ALONE for a TRAIN/VAL
    window (None if the window has no own sample -> undefined/excluded)."""
    positions = si.positions_by_bucket.get(w_index)
    if not positions:
        return None
    vals = si.values[positions]
    return bool(np.any((vals < bounds[0]) | (vals > bounds[1])))


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

    all_windows = sorted(build_windows(), key=lambda w: w.w_index)
    train_windows = sorted(
        [w for w in all_windows if w.w_index in blocks.train], key=lambda w: w.w_index,
    )
    val_windows = sorted(
        [w for w in all_windows if w.w_index in blocks.validation], key=lambda w: w.w_index,
    )

    # ---- residual cohorts ----
    # TEST: exact frozen comb_pred == 0.
    test_frame = build_cohort_frame(
        test_windows, si, bounds, train_normal_sorted, train_normal_ref_sample, hist_range,
    )
    test_frame["missed_by_rule"] = (comb == 0)

    # TRAIN / VAL: pressure-bounds-alone proxy (disclosed simplification).
    def proxy_missed(windows):
        out = []
        for w in windows:
            fired = pressure_rule_proxy_fires(si, w.w_index, bounds)
            out.append(False if fired is None else (not fired))
        return np.array(out, dtype=bool)

    train_frame = build_cohort_frame(
        train_windows, si, bounds, train_normal_sorted, train_normal_ref_sample, hist_range,
    )
    train_frame["missed_by_rule"] = proxy_missed(train_windows)
    val_frame = build_cohort_frame(
        val_windows, si, bounds, train_normal_sorted, train_normal_ref_sample, hist_range,
    )
    val_frame["missed_by_rule"] = proxy_missed(val_windows)

    known_fn_mask = test_frame["nmri_pure"] & test_frame["missed_by_rule"]
    n_known_nmri_fn = int(known_fn_mask.sum())
    known_cmri_fn_mask = test_frame["cmri_pure"] & test_frame["missed_by_rule"]
    n_known_cmri_fn = int(known_cmri_fn_mask.sum())

    def dataset_for(attack_cat: int, cohort_key: str, family: str):
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

        X_tr, y_tr, idx_tr = split_rows(train_frame)
        X_val, y_val, idx_val = split_rows(val_frame)
        X_test, y_test, idx_test = split_rows(test_frame)
        return {
            "train": (X_tr, y_tr, idx_tr), "val": (X_val, y_val, idx_val),
            "test": (X_test, y_test, idx_test),
        }

    def train_and_score(X_tr, y_tr, X_val):
        if len(np.unique(y_tr)) < 2 or len(X_tr) < 10:
            return None
        clf = XGBClassifier(**XGB_PARAMS)
        clf.fit(X_tr, y_tr)
        return clf, clf.predict_proba(X_val)[:, 1]

    per_attack: dict[str, dict] = {}
    rng_boot = np.random.default_rng(BOOTSTRAP_SEED)
    rng_perm = np.random.default_rng(PERMUTATION_SEED)

    for attack_name, cat, cohort_key, n_known_fn in (
        ("NMRI", NMRI, "nmri_pure", n_known_nmri_fn),
        ("CMRI", CMRI, "cmri_pure", n_known_cmri_fn),
    ):
        family_results = {}
        winning_clf = None
        winning_names = None
        for family in FAMILIES:
            ds = dataset_for(cat, cohort_key, family)
            X_tr, y_tr, idx_tr = ds["train"]
            X_val, y_val, idx_val = ds["val"]
            X_test, y_test, idx_test = ds["test"]

            trained = train_and_score(X_tr, y_tr, X_val)
            if trained is None:
                family_results[family] = {
                    "insufficient_data": True, "n_train": int(len(X_tr)),
                    "n_train_positive": int(y_tr.sum()) if len(y_tr) else 0,
                }
                continue
            clf, val_scores = trained
            val_normal_scores = val_scores[y_val == 0]
            threshold, achieved_fpr = fit_threshold(val_normal_scores, MAX_NORMAL_FPR)
            real_recall = recall_at_threshold(val_scores, y_val, threshold)

            events = contiguous_events(idx_val)
            boot_recalls, boot_fprs = [], []
            for _ in range(N_BOOTSTRAP):
                sample_pos = event_grouped_bootstrap_resample(events, rng_boot)
                if len(sample_pos) == 0:
                    continue
                s_scores = val_scores[sample_pos]
                s_labels = y_val[sample_pos]
                boot_recalls.append(recall_at_threshold(s_scores, s_labels, threshold))
                neg = s_labels == 0
                boot_fprs.append(
                    float((s_scores[neg] > threshold).sum()) / int(neg.sum()) if neg.sum() else 0.0
                )
            recall_ci = percentile_ci(boot_recalls)

            train_events = contiguous_events(idx_tr)
            null_recalls = []
            for _ in range(N_PERMUTATIONS):
                y_perm = event_grouped_permute_labels(train_events, y_tr, rng_perm)
                if len(np.unique(y_perm)) < 2:
                    null_recalls.append(0.0)
                    continue
                clf_perm = XGBClassifier(**XGB_PARAMS)
                clf_perm.fit(X_tr, y_perm)
                perm_val_scores = clf_perm.predict_proba(X_val)[:, 1]
                perm_normal_scores = perm_val_scores[y_val == 0]
                perm_threshold, _ = fit_threshold(perm_normal_scores, MAX_NORMAL_FPR)
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

            family_results[family] = {
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
                "test_scored_once": {
                    "normal_fp": test_fp, "normal_fpr": test_fpr, "recall": test_recall,
                },
                "feature_names": FEATURE_FAMILIES[family],
                "feature_importances": [float(v) for v in clf.feature_importances_],
            }
            if family == "combined":
                winning_clf, winning_names = clf, FEATURE_FAMILIES[family]

        causality_audit = (
            build_causality_audit(winning_names, family_results["combined"]["feature_importances"])
            if winning_clf is not None and "combined" in family_results
            and not family_results["combined"].get("insufficient_data") else []
        )

        # ---- verdict logic (fixed decision rule; not amended after seeing results) ----
        def clears(fam):
            r = family_results.get(fam, {})
            return bool(r.get("clears_permutation_null")) if not r.get("insufficient_data") else False

        f2_clears = clears("F2")
        f3_clears = clears("F3")
        combined_clears = clears("combined")
        combined_importances = family_results.get("combined", {}).get("feature_importances", [])
        combined_names = family_results.get("combined", {}).get("feature_names", [])
        dominant_family = None
        if combined_importances:
            top_idx = int(np.argmax(combined_importances))
            dominant_family = CAUSALITY_TABLE.get(combined_names[top_idx], ("unknown",))[0]

        causality_clean = all(row["keep"] for row in causality_audit) if causality_audit else False

        proceed_0030 = bool((f2_clears or (combined_clears and dominant_family == "F2")) and causality_clean)
        proceed_0031 = bool((f3_clears or (combined_clears and dominant_family == "F3")) and causality_clean)
        any_clears = any(
            family_results.get(f, {}).get("clears_permutation_null", False) for f in FAMILIES
        )
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

        per_attack[attack_name] = {
            "known_false_negatives_test": n_known_fn,
            "families": family_results,
            "dominant_feature_family_combined_model": dominant_family,
            "causality_audit_combined_model": causality_audit,
            "causality_audit_clean": causality_clean,
            "verdict": verdict,
        }

    overall_verdicts = {k: v["verdict"] for k, v in per_attack.items()}
    if any(v.startswith("PROCEED") for v in overall_verdicts.values()):
        overall = " / ".join(f"{k}: {v}" for k, v in overall_verdicts.items())
    else:
        overall = "NO-GO-CEILING"

    return {
        "status": "TESTED — DIAGNOSTIC PROBE; NO DETECTOR BUILT; run_detector NOT modified",
        "experiment": "EXP-0032",
        "identity_gates": {
            "exp0017_artifact_loaded_and_verified": True,
            "comb_equals_protocol_or_pressure_or_if": gate_elementwise,
            "whole_test_confusion_matches_exp0017": bool(gate_confusion),
            "exp0017_confusion": list(EXP0017_TEST_CONFUSION),
            "exp0016_bounds": list(bounds),
            "run_detector_modified": False,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "residual_cohort_definition": {
            "test": "exact frozen comb_pred == 0 (protocol | pressure | IF)",
            "train_validation": (
                "EXP-0016 pressure-bounds component ALONE, reproduced from the frozen "
                "pressure_bounds tuple (protocol rule and Isolation Forest are not "
                "reproduced for TRAIN/VAL to avoid calling run_detector; documented "
                "over-approximation, see module docstring)"
            ),
        },
        "n_known_false_negatives_test": {"NMRI": n_known_nmri_fn, "CMRI": n_known_cmri_fn},
        "method": {
            "trailing_buffer_samples": TRAILING_BUFFER_SAMPLES,
            "mantissa_low_bits": MANTISSA_LOW_BITS,
            "quantization_steps": list(QUANTIZATION_STEPS),
            "adc_lattice_steps": list(ADC_LATTICE_STEPS),
            "entropy_hist_bins": ENTROPY_HIST_BINS,
            "wasserstein_ref_max_size": WASSERSTEIN_REF_MAX_SIZE,
            "n_bootstrap": N_BOOTSTRAP, "n_permutations": N_PERMUTATIONS,
            "max_normal_fpr": MAX_NORMAL_FPR,
            "xgb_params": XGB_PARAMS,
            "note_reduced_resample_counts": (
                "spec's illustrative 200 bootstrap / 50-200 permutation counts reduced "
                "to 60 / 20 for session compute-time tractability (2 attack types x 4 "
                "families x (1 real + 20 permutation) XGBoost fits); disclosed, same "
                "convention as EXP-0028's LIBRARY_MAX_SIZE compute cap."
            ),
        },
        "per_attack": per_attack,
        "decision_rule": {
            "bar": "VAL event-grouped-bootstrap recall-at-<=0.30%-FPR 95% CI lower bound "
                   "must exceed the label-permutation null distribution's 95th percentile",
            "proceed_0030_condition": "F2-only OR combined-dominated-by-F2 clears bar AND "
                                       "causality audit clean",
            "proceed_0031_condition": "F3-only OR combined-dominated-by-F3 clears bar AND "
                                       "causality audit clean",
            "no_go_ceiling_condition": "no family clears the bar for either attack type",
            "verdicts": overall_verdicts,
            "overall": overall,
            "frozen_ceiling_if_no_go": {"NMRI_pct": 79.02, "CMRI_pct": 54.59},
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "scipy": version("scipy"), "scikit_learn": version("scikit-learn"),
            "xgboost": version("xgboost"),
        },
        "limitations": [
            "TRAIN/VALIDATION residual cohort uses the pressure-bounds-alone proxy for "
            "'the rule already misses' (see module docstring); TEST uses the exact "
            "frozen comb_pred. This may make the TRAIN/VAL positive class a mild "
            "over-approximation of the true residual (a few windows the protocol rule "
            "or IF would independently catch may be retained).",
            "Per-window feature row is computed from the LAST pressure sample ending in "
            "the window plus a trailing causal buffer, not a max/aggregate over multiple "
            "sample endings (simpler than EXP-0019/0028/0029's per-window aggregation "
            "convention; a completeness-vs-compute tradeoff for this diagnostic probe).",
            "Bootstrap/permutation counts reduced from the spec's illustrative upper "
            "range for session compute-time tractability (documented above).",
            "The Wasserstein-1 distance-from-Normal feature uses a capped, deterministic "
            "uniform-stride TRAIN-normal reference subsample (WASSERSTEIN_REF_MAX_SIZE), "
            "not the full TRAIN-normal population, for the same reason.",
            "Diagnostic only: no detector was built or wired regardless of the outcome; "
            "EXP-0030/EXP-0031 (if triggered by this verdict) are separate, later work.",
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
        "# EXP-0032 — admissible-information ceiling audit (NMRI/CMRI residual false negatives)",
        "",
        f"run_detector() modified: {r['identity_gates']['run_detector_modified']}",
        f"Known TEST false negatives: NMRI={r['n_known_false_negatives_test']['NMRI']}  "
        f"CMRI={r['n_known_false_negatives_test']['CMRI']}",
        "",
    ]
    for attack, block in r["per_attack"].items():
        lines += [f"## {attack}", "",
                  "| family | VAL recall (point) | VAL recall 95% CI | permutation null p95 | clears null |",
                  "|---|---:|---:|---:|---|"]
        for fam, fr in block["families"].items():
            if fr.get("insufficient_data"):
                lines.append(f"| {fam} | insufficient data (n_train={fr['n_train']}) | - | - | - |")
                continue
            ci = fr["val_recall_bootstrap_ci95"]
            lines.append(
                f"| {fam} | {100*fr['val_recall_point_estimate']:.2f}% "
                f"| [{100*ci[0]:.2f}%, {100*ci[1]:.2f}%] "
                f"| {100*fr['permutation_null_p95']:.2f}% "
                f"| {fr['clears_permutation_null']} |"
            )
        lines += [
            "",
            f"Dominant feature family (combined model): {block['dominant_feature_family_combined_model']}",
            f"Causality audit clean: {block['causality_audit_clean']}",
            f"**Verdict: {block['verdict']}**",
            "",
        ]
    dr = r["decision_rule"]
    lines += [
        "## Overall decision-rule verdict",
        f"{dr['overall']}",
        "",
        "_Diagnostic only; no detector was built or wired. run_detector NOT modified._",
    ]
    return "\n".join(lines)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
