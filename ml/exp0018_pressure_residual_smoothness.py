#!/usr/bin/env python3
"""EXP-0018 — residual-smoothness test for the CMRI forgeries EXP-0017 misses.

Diagnostic-then-build, same discipline as EXP-0014/0015/0016. A new standalone
detector is built and measured; `ml/iforest_detector.run_detector` is NOT modified.
The EXP-0017 combined detector is reproduced from its checksummed saved artifact
(`exp0017_operational.load_result` re-verifies every tracked source sha256, the
envelope checksum, the manifest identity and the VALIDATED status) and asserted
element-wise `comb == protocol | pressure | IF` with whole-TEST confusion
(4767, 40, 2166, 2374) before any score is read.

Hypothesis (external research, tested here — not assumed): a smooth CMRI
response-value forgery that stays inside the EXP-0016 pressure bounds is still
*unnaturally quiet* — its one-step prediction residuals are suppressed relative to
TRAIN-normal. Two-sided: abnormally LOW residual energy (over-smooth) and
abnormally HIGH residual energy (noisy / unstable) are separate hypotheses, each
calibrated against the TRAIN-normal residual-energy distribution.

Structural constraint (see EXPERIMENT_LOG.md, EXP-0018): egress 0x03 pressure
cadence is 1-2 samples per 5 s window, so the predictor and the residual-energy
statistic are defined over the GLOBAL chronological sequence of 0x03 responses,
with a causal K-sample rolling window that spans several 5 s windows.

Pressure is the ARFF `pressure measurement` value, row-index aligned to the TXT
exactly as EXP-0009 / EXP-0016 (canonical 0x03 read responses). Bounds/coefficients
are empirical TRAIN-normal statistics, not a physical spec; one testbed; egress
only. See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0018, 2026-09-10).
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

import exp0008_cadence_features as cf
from exp0016_pressure_bounds_rule import align_egress_pressure
from exp0017_operational import load_result
from features_windowed import build_windows

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0018_pressure_residual_smoothness.json"
)
CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]
CMRI = 2

# ---- fixed method constants (pre-registered, EXPERIMENT_LOG.md EXP-0018) ----
ROLL_K = 15                      # causal rolling window, samples (~11 windows / ~55 s)
CALIB_LOW_Q = 0.005              # TRAIN-normal energy quantile -> over-smooth threshold
CALIB_HIGH_Q = 0.995            # TRAIN-normal energy quantile -> noisy threshold

EXP0017_TEST_CONFUSION = (4767, 40, 2166, 2374)  # tn, fp, fn, tp (comb_pred)

# ---- fixed decision rule (pre-registered) ----
STRONG_MIN_NEW_RECALL = 0.25
ACCEPTABLE_MIN_NEW_RECALL = 0.10
MAX_NEW_NORMAL_FP_RATE = 0.0030
MIN_COMBINED_PRECISION = 0.970
SIGNAL_ALPHA = 0.01


# --------------------------------------------------------------- pressure series

def build_global_samples(
    by_bucket: Mapping[int, Sequence[float]],
) -> tuple[np.ndarray, np.ndarray]:
    """Global chronological 0x03 pressure sequence: ascending bucket, then
    within-bucket append (file) order. Returns (values, bucket_id) arrays.
    Non-finite values are dropped (they carry no register reading)."""
    values: list[float] = []
    buckets: list[int] = []
    for b in sorted(by_bucket):
        for v in by_bucket[b]:
            fv = float(v)
            if math.isfinite(fv):
                values.append(fv)
                buckets.append(int(b))
    return np.asarray(values, dtype=float), np.asarray(buckets, dtype=int)


# --------------------------------------------------------------- blocks

class Blocks:
    """TRAIN / VALIDATION / TEST bucket sets from the checksummed manifest,
    constructed exactly as EXP-0017 (manifest ids for TRAIN/VAL; buckets after
    the final pre-TEST bucket minus the first 2*GUARD_WINDOWS for TEST).
    TRAIN-normal = TRAIN buckets whose build_windows() window is not attack."""

    def __init__(self) -> None:
        split = cf.load_pretest_split()
        self.split_id = split.split_id
        self.split_sha256 = split.membership_sha256
        wins = sorted(build_windows(), key=lambda w: w.w_index)
        ids = [w.w_index for w in wins]
        idpos = {b: i for i, b in enumerate(ids)}
        self.train = set(split.train_bucket_ids)
        self.validation = set(split.validation_bucket_ids)
        if not self.train <= set(ids) or not self.validation <= set(ids):
            raise RuntimeError("manifest bucket id absent from build_windows()")
        after = sorted(b for b in ids if b > split.final_pretest_bucket_id)
        self.test = set(after[2 * cf.GUARD_WINDOWS:])
        self.train_normal = {
            b for b in self.train if wins[idpos[b]].is_attack == 0
        }

    def label(self, bucket: int) -> str:
        if bucket in self.train_normal:
            return "train_normal"
        if bucket in self.train:
            return "train_attack"
        if bucket in self.validation:
            return "validation"
        if bucket in self.test:
            return "test"
        return "other"


# --------------------------------------------------------------- AR(1) residuals

class ResidualModel:
    """Lag-1 (Yule-Walker) AR model fitted on TRAIN-normal 0x03 pressure only."""

    def __init__(self, values: np.ndarray, buckets: np.ndarray, blocks: Blocks) -> None:
        block = np.array([blocks.label(int(b)) for b in buckets])
        tn = block == "train_normal"
        if tn.sum() < 100:
            raise RuntimeError("too few TRAIN-normal pressure samples for AR(1)")
        self.mu = float(values[tn].mean())
        c = values - self.mu

        prev_tn = np.zeros(len(values), dtype=bool)
        prev_tn[1:] = tn[:-1] & tn[1:]                 # both members TRAIN-normal
        num = float(np.sum(c[:-1][tn[:-1] & tn[1:]] * c[1:][tn[:-1] & tn[1:]]))
        den = float(np.sum(c[:-1][tn[:-1] & tn[1:]] ** 2))
        self.phi = num / den
        self.phi_persistence = 1.0                     # reported for context only

        # residual for every sample with a predecessor
        self.resid = np.full(len(values), np.nan)
        self.resid[1:] = c[1:] - self.phi * c[:-1]
        self.resid_persistence = np.full(len(values), np.nan)
        self.resid_persistence[1:] = c[1:] - c[:-1]

        cal = prev_tn & np.isfinite(self.resid)
        self.sigma = float(np.std(self.resid[cal]))
        self.sigma_persistence = float(np.std(self.resid_persistence[cal]))
        if not self.sigma > 0:
            raise RuntimeError("degenerate TRAIN-normal residual sigma")

        self.z2 = (self.resid / self.sigma) ** 2
        self.z2_persistence = (self.resid_persistence / self.sigma_persistence) ** 2
        self.values, self.buckets, self.block = values, buckets, block

    def rolling_energy_by_bucket(self, z2: np.ndarray) -> dict[int, float]:
        """E_b = mean(z^2) over the K samples ending at the last sample of bucket b.
        Buckets with < K preceding samples are omitted (undefined)."""
        last_pos: dict[int, int] = {}
        for i, b in enumerate(self.buckets):
            last_pos[int(b)] = i
        out: dict[int, float] = {}
        for b, j in last_pos.items():
            lo = j - ROLL_K + 1
            if lo < 1:                                  # z undefined at index 0
                continue
            window = z2[lo:j + 1]
            if np.all(np.isfinite(window)) and len(window) == ROLL_K:
                out[b] = float(window.mean())
        return out

    def calibration_energies(self, energy: Mapping[int, float]) -> np.ndarray:
        """E_b for buckets whose whole K-sample window is TRAIN-normal."""
        last_pos: dict[int, int] = {}
        for i, b in enumerate(self.buckets):
            last_pos[int(b)] = i
        keep = []
        for b, e in energy.items():
            j = last_pos[b]
            if np.all(self.block[j - ROLL_K + 1:j + 1] == "train_normal"):
                keep.append(e)
        return np.asarray(keep, dtype=float)


# --------------------------------------------------------------- scoring helpers

def confusion(tp: int, n_pos: int, fp: int, n_neg: int) -> dict:
    fn, tn = n_pos - tp, n_neg - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / n_pos if n_pos else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / n_neg if n_neg else 0.0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "recall_pct": round(100 * recall, 3), "precision_pct": round(100 * precision, 3),
        "f1_pct": round(100 * f1, 3), "fpr_pct": round(100 * fpr, 4),
    }


def classify_verdict(
    new_recall: float, new_normal_fp_rate: float, combined_precision: float,
) -> str:
    """Pre-registered decision rule (EXPERIMENT_LOG.md EXP-0018)."""
    bars_ok = (
        new_normal_fp_rate <= MAX_NEW_NORMAL_FP_RATE
        and combined_precision >= MIN_COMBINED_PRECISION
    )
    if new_recall >= STRONG_MIN_NEW_RECALL and bars_ok:
        return "STRONG"
    if new_recall >= ACCEPTABLE_MIN_NEW_RECALL and bars_ok:
        return "ACCEPTABLE"
    return "WEAK / HYPOTHESIS NOT SUPPORTED"


def _dominant(cats: set[int]) -> int:
    atk = [c for c in cats if c != 0]
    return min(atk) if atk else 0


def _cohort_mask(test_windows, cat: int, mode: str) -> np.ndarray:
    out = []
    for w in test_windows:
        cs = set(w.categories)
        if mode == "pure_normal":
            keep = cs == {0}
        elif mode == "pure":
            keep = cat in cs and cs <= {0, cat}
        elif mode == "dominant":
            keep = _dominant(cs) == cat
        elif mode == "containing":
            keep = cat in cs
        else:
            raise ValueError(mode)
        out.append(keep)
    return np.asarray(out, dtype=bool)


# --------------------------------------------------------------- experiment

def run_experiment() -> dict:
    # ---- reproduce EXP-0017 from its checksummed artifact (identity gate) ----
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

    # ---- pressure sequence, blocks, AR(1) residual model ----
    blocks = Blocks()
    if (blocks.split_id, blocks.split_sha256) != (R.split_id, R.split_sha256):
        raise RuntimeError("manifest identity differs from the EXP-0017 artifact")
    values, buckets = build_global_samples(align_egress_pressure())
    model = ResidualModel(values, buckets, blocks)

    energy = model.rolling_energy_by_bucket(model.z2)
    energy_persist = model.rolling_energy_by_bucket(model.z2_persistence)
    calib = model.calibration_energies(energy)
    low_thr = float(np.quantile(calib, CALIB_LOW_Q))
    high_thr = float(np.quantile(calib, CALIB_HIGH_Q))

    def fired(mode: str):
        def f(w_index: int) -> int:
            e = energy.get(int(w_index))
            if e is None:
                return 0
            if mode == "both":
                return int(e < low_thr or e > high_thr)
            if mode == "low":
                return int(e < low_thr)
            return int(e > high_thr)
        return f

    res_both = np.array([fired("both")(w.w_index) for w in test_windows], dtype=int)
    res_low = np.array([fired("low")(w.w_index) for w in test_windows], dtype=int)
    res_high = np.array([fired("high")(w.w_index) for w in test_windows], dtype=int)
    e_defined = np.array([int(w.w_index) in energy for w in test_windows], dtype=bool)

    # ---- evaluation cohort: CMRI TEST windows EXP-0017 misses ----
    normal_mask = _cohort_mask(test_windows, 0, "pure_normal")
    n_neg = int(normal_mask.sum())
    res_normal_fp = int(res_both[normal_mask].sum())
    new_normal_fp_rate = res_normal_fp / n_neg

    cohorts_out = []
    per_missed = {}
    for mode in ("pure", "dominant", "containing"):
        cmri = _cohort_mask(test_windows, CMRI, mode)
        missed = cmri & (comb == 0)
        missed_def = missed & e_defined
        for tag, arr in (("both", res_both), ("low", res_low), ("high", res_high)):
            new_hits = int(arr[missed_def].sum())
            rec = new_hits / int(missed_def.sum()) if missed_def.sum() else 0.0
            cohorts_out.append({
                "cohort": mode, "variant": tag,
                "cmri_windows": int(cmri.sum()),
                "exp0017_missed": int(missed.sum()),
                "missed_with_defined_energy": int(missed_def.sum()),
                "missed_energy_undefined": int((missed & ~e_defined).sum()),
                "new_detections": new_hits,
                "new_recall": rec, "new_recall_pct": round(100 * rec, 3),
            })
        per_missed[mode] = missed_def

    pure_missed = per_missed["pure"]
    new_recall = (
        int(res_both[pure_missed].sum()) / int(pure_missed.sum())
        if pure_missed.sum() else 0.0
    )
    persist_calib = model.calibration_energies(energy_persist)
    p_lo = float(np.quantile(persist_calib, CALIB_LOW_Q))
    p_hi = float(np.quantile(persist_calib, CALIB_HIGH_Q))
    persist_fired = np.array([
        0 if energy_persist.get(int(w.w_index)) is None
        else int(energy_persist[int(w.w_index)] < p_lo
                 or energy_persist[int(w.w_index)] > p_hi)
        for w in test_windows
    ], dtype=int)
    new_recall_persistence = (
        int(persist_fired[pure_missed].sum()) / int(pure_missed.sum())
        if pure_missed.sum() else 0.0
    )

    # ---- threshold-independent signal test ----
    e_missed = np.array(
        [energy[int(w.w_index)] for w, m in zip(test_windows, pure_missed) if m],
        dtype=float,
    )
    e_normal = np.array(
        [energy[int(w.w_index)] for w, m in zip(test_windows, normal_mask)
         if m and int(w.w_index) in energy],
        dtype=float,
    )
    u_stat, p_two = mannwhitneyu(e_missed, e_normal, alternative="two-sided")
    missed_lower = bool(np.median(e_missed) < np.median(e_normal))
    signal_present = bool(p_two < SIGNAL_ALPHA and missed_lower)

    def _q(a):
        return {
            "n": int(len(a)), "median": float(np.median(a)),
            "iqr": [float(np.quantile(a, 0.25)), float(np.quantile(a, 0.75))],
            "min": float(np.min(a)), "max": float(np.max(a)),
        }

    # ---- whole TEST block: combined OR residual ----
    comb2 = (comb | res_both).astype(int)
    w_tn = int(((comb2 == 0) & (y == 0)).sum())
    w_fp = int(((comb2 == 1) & (y == 0)).sum())
    w_fn = int(((comb2 == 0) & (y == 1)).sum())
    w_tp = int(((comb2 == 1) & (y == 1)).sum())
    combined_precision = w_tp / (w_tp + w_fp) if (w_tp + w_fp) else 0.0

    # ---- residual-alone standalone metrics ----
    standalone = {
        "whole_attack_class": confusion(
            int(res_both[y == 1].sum()), int((y == 1).sum()),
            res_normal_fp, n_neg,
        ),
    }
    noregress = {}
    for name, c in (("NMRI", 1), ("MFCI", 5), ("Recon", 7)):
        m = _cohort_mask(test_windows, c, "pure")
        standalone[name + "_pure"] = confusion(
            int(res_both[m].sum()), int(m.sum()), res_normal_fp, n_neg,
        )
        e17 = int(comb[m].sum())
        e18 = int(comb2[m].sum())
        noregress[name + "_pure"] = {
            "n": int(m.sum()), "exp0017_combined_flagged": e17,
            "combined_or_residual_flagged": e18, "delta": e18 - e17,
        }

    # ---- decision-rule verdict ----
    verdict = classify_verdict(new_recall, new_normal_fp_rate, combined_precision)

    return {
        "status": "VALIDATED — DETECTOR BUILT AND SCORED; run_detector NOT modified",
        "experiment": "EXP-0018",
        "hypothesis": (
            "Smooth CMRI response forgeries inside the EXP-0016 pressure bounds are "
            "still detectable as suppressed one-step AR(1) prediction residual energy "
            "(over-smooth) — two-sided against TRAIN-normal, also flagging excess energy."
        ),
        "identity_gates": {
            "exp0017_artifact_loaded_and_verified": True,
            "comb_equals_protocol_or_pressure_or_if": gate_elementwise,
            "whole_test_confusion_matches_exp0017": bool(gate_confusion),
            "exp0017_confusion": list(EXP0017_TEST_CONFUSION),
            "run_detector_modified": False,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "pressure_source": (
            "ARFF 'pressure measurement' (data col 13), row-index aligned to the TXT "
            "and verified; canonical 0x03 read responses; reuses exp0016.align_egress_pressure"
        ),
        "method": {
            "predictor": "AR(1) lag-1 Yule-Walker on TRAIN-normal 0x03 pressure only",
            "mu": model.mu, "phi": model.phi, "sigma_residual": model.sigma,
            "phi_persistence_context": model.phi_persistence,
            "sigma_persistence_context": model.sigma_persistence,
            "rolling_window_samples_K": ROLL_K,
            "rolling_energy": "mean squared standardised residual over the K samples "
                              "ending at the last 0x03 response of the 5 s window (causal)",
            "train_normal_pressure_samples": int((model.block == "train_normal").sum()),
            "global_pressure_samples": int(len(values)),
        },
        "calibration": {
            "set": "TRAIN-normal windows whose whole K-sample window is TRAIN-normal",
            "n_windows": int(len(calib)),
            "low_quantile": CALIB_LOW_Q, "high_quantile": CALIB_HIGH_Q,
            "low_thr": low_thr, "high_thr": high_thr,
            "median": float(np.median(calib)),
            "q01": float(np.quantile(calib, 0.01)),
            "q99": float(np.quantile(calib, 0.99)),
            "skew_note": (
                "energy is a mean of squares -> right-skewed; low and high thresholds "
                "are separate empirical quantiles, not a symmetric band"
            ),
        },
        "evaluation_cohort": (
            "CMRI-labelled TEST windows with EXP-0017 comb_pred == 0 and a defined "
            "rolling energy; 'new detection' = residual detector fires AND comb_pred == 0"
        ),
        "decision_rule": {
            "strong": f"new pure-CMRI recall >= {STRONG_MIN_NEW_RECALL:.0%} "
                      f"AND new pure-Normal FP <= {MAX_NEW_NORMAL_FP_RATE:.2%} "
                      f"AND combined precision >= {MIN_COMBINED_PRECISION:.1%}",
            "acceptable": f"recall >= {ACCEPTABLE_MIN_NEW_RECALL:.0%} AND same bars",
            "new_pure_cmri_recall": new_recall,
            "new_pure_cmri_recall_persistence_context": new_recall_persistence,
            "new_pure_normal_fp": res_normal_fp,
            "new_pure_normal_fp_rate": new_normal_fp_rate,
            "combined_precision": combined_precision,
            "verdict": verdict,
        },
        "signal_test": {
            "test": "Mann-Whitney U, two-sided; missed pure-CMRI vs pure-Normal rolling energy",
            "u_statistic": float(u_stat), "p_value": float(p_two),
            "alpha": SIGNAL_ALPHA,
            "missed_cmri_energy_lower_than_normal": missed_lower,
            "signal_present_in_hypothesised_direction": signal_present,
            "energy_distribution": {
                "missed_pure_cmri": _q(e_missed),
                "pure_normal_test": _q(e_normal),
                "train_normal_calibration": _q(calib),
            },
        },
        "per_cohort_new_detection": cohorts_out,
        "pure_normal_test_false_positives": {
            "n_windows": n_neg,
            "residual_detector_fp": res_normal_fp,
            "residual_detector_fpr_pct": round(100 * new_normal_fp_rate, 4),
            "exp0017_combined_fp": int(comb[normal_mask].sum()),
            "combined_or_residual_fp": int(comb2[normal_mask].sum()),
        },
        "residual_detector_standalone": standalone,
        "no_regression": noregress,
        "whole_test_block_binary_confusion": {
            "cohort": "all 9,347 TEST windows; positive = is_attack",
            "exp0017_comb": dict(zip(("tn", "fp", "fn", "tp"), EXP0017_TEST_CONFUSION)),
            "combined_or_residual": {"tn": w_tn, "fp": w_fp, "fn": w_fn, "tp": w_tp},
            "delta_tn_fp_fn_tp": [
                w_tn - EXP0017_TEST_CONFUSION[0], w_fp - EXP0017_TEST_CONFUSION[1],
                w_fn - EXP0017_TEST_CONFUSION[2], w_tp - EXP0017_TEST_CONFUSION[3],
            ],
            "combined_or_residual_precision": combined_precision,
            "note": "run_detector() NOT modified. Wiring this rule in would change "
                    "EXP-0017's frozen TEST confusion by this delta — a separate decision.",
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "scipy": version("scipy"), "scikit_learn": version("scikit-learn"),
        },
        "limitations": [
            "Pressure is the ARFF-aligned value; a PCAP-replay deployment would decode "
            "it from 0x03 response bytes and that register map/scale is undocumented.",
            "AR(1) coefficient, sigma and energy thresholds are empirical TRAIN-normal "
            "statistics, not a physical process model.",
            "1-2 pressure samples per 5 s window: the rolling window spans ~11 windows, "
            "so a window's verdict reflects ~55 s of surrounding telemetry, not itself "
            "alone. A TEST window's causal context may include VALIDATION/guard samples.",
            "Judged only on CMRI windows EXP-0017 already misses; incidental effects on "
            "other categories are reported, not tuned for.",
            "One testbed; egress-only.",
        ],
    }


def _json_ready(value):
    if isinstance(value, Mapping):
        return {k: _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(v) for v in value]
    if isinstance(value, np.generic):
        return _json_ready(value.item())
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
    st = r["signal_test"]
    wt = r["whole_test_block_binary_confusion"]
    fp = r["pure_normal_test_false_positives"]
    m = r["method"]
    lines = [
        "# EXP-0018 — residual-smoothness test for missed CMRI",
        "",
        f"AR(1): mu={m['mu']:.4f}  phi={m['phi']:.5f}  sigma={m['sigma_residual']:.4f}  "
        f"K={m['rolling_window_samples_K']} samples",
        f"Energy thresholds (TRAIN-normal {r['calibration']['low_quantile']:.1%}/"
        f"{r['calibration']['high_quantile']:.1%} quantiles): "
        f"low<{r['calibration']['low_thr']:.4f}  high>{r['calibration']['high_thr']:.4f}  "
        f"(median {r['calibration']['median']:.4f}, n={r['calibration']['n_windows']})",
        f"run_detector() modified: {r['identity_gates']['run_detector_modified']}",
        "",
        f"## DECISION-RULE VERDICT: {dr['verdict']}",
        f"- new pure-CMRI recall (windows EXP-0017 misses): "
        f"{100 * dr['new_pure_cmri_recall']:.2f}%  (strong >=25%, acceptable >=10%)",
        f"- new pure-Normal FP: {dr['new_pure_normal_fp']}/{fp['n_windows']} = "
        f"{100 * dr['new_pure_normal_fp_rate']:.4f}%  (bar <=0.30%)",
        f"- combined precision (comb OR residual): {100 * dr['combined_precision']:.3f}%  "
        f"(bar >=97.0%)",
        f"- persistence-model context recall: "
        f"{100 * dr['new_pure_cmri_recall_persistence_context']:.2f}%",
        "",
        f"## SIGNAL TEST (threshold-independent): "
        f"{'PRESENT' if st['signal_present_in_hypothesised_direction'] else 'NOT SUPPORTED'}",
        f"- Mann-Whitney U={st['u_statistic']:.0f}  p={st['p_value']:.3g}  (alpha {st['alpha']})",
        f"- missed-CMRI energy lower than Normal: {st['missed_cmri_energy_lower_than_normal']}",
        f"- median energy  missed-CMRI {st['energy_distribution']['missed_pure_cmri']['median']:.4f}"
        f"  | Normal {st['energy_distribution']['pure_normal_test']['median']:.4f}"
        f"  | TRAIN-normal {st['energy_distribution']['train_normal_calibration']['median']:.4f}",
        "",
        "## New detections on CMRI windows EXP-0017 misses",
        "| cohort | variant | missed (defined E) | new detections | new recall% |",
        "|---|---|---:|---:|---:|",
    ]
    for c in r["per_cohort_new_detection"]:
        lines.append(
            f"| {c['cohort']} | {c['variant']} | {c['missed_with_defined_energy']} "
            f"| {c['new_detections']} | {c['new_recall_pct']:.2f} |"
        )
    lines += [
        "",
        "## Whole 9,347-window TEST block (binary attack/Normal)",
        f"- EXP-0017 comb : TN/FP/FN/TP = "
        f"{wt['exp0017_comb']['tn']}/{wt['exp0017_comb']['fp']}/"
        f"{wt['exp0017_comb']['fn']}/{wt['exp0017_comb']['tp']}",
        f"- comb OR residual: TN/FP/FN/TP = "
        f"{wt['combined_or_residual']['tn']}/{wt['combined_or_residual']['fp']}/"
        f"{wt['combined_or_residual']['fn']}/{wt['combined_or_residual']['tp']}",
        f"- delta (TN,FP,FN,TP): {wt['delta_tn_fp_fn_tp']}",
        f"- {wt['note']}",
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
