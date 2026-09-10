#!/usr/bin/env python3
"""EXP-0019 — physical rate-of-change plausibility test for the CMRI EXP-0017 misses.

Diagnostic-then-build, measurement only, same discipline as EXP-0016 / EXP-0018.
`ml/iforest_detector.run_detector` is NOT modified and NOT called. EXP-0017 is
reproduced from its checksummed saved artifact (`exp0017_operational.load_result`
re-verifies every tracked source sha256, the envelope checksum, the manifest
identity and the VALIDATED status) and asserted element-wise
`comb == protocol | pressure | IF` with whole-TEST confusion (4767, 40, 2166, 2374)
before any score is read.

Hypothesis (tested — not assumed): a real physical process has a maximum plausible
RATE of pressure change. A forged CMRI injection can jump the reported value faster
than the process could physically move in the real elapsed time since the last
`0x03` reading, even when the value is inside the EXP-0016 bounds and the raw jump
size resembles a legitimate swing. This differs from EXP-0018, which tested residual
energy against a fixed-variance AR(1) model and ignored elapsed time.

Timing (reused from EXP-0007/0008, re-confirmed): TXT timestamps are strictly
monotonic; consecutive egress `0x03` `Δt` median 3.39 s, ~93% within ±15% of one
cadence, with ~7% gaps at 3-4x cadence. Dividing `|Δp|` by the true `Δt` makes a
jump spread across a gap correctly more plausible.

Pressure is the ARFF `pressure measurement` value, row-index aligned to the TXT
exactly as EXP-0009 / EXP-0016 (canonical `0x03` read responses). The plausibility
bound is an empirical TRAIN-normal statistic, not a physical spec (register
map/scale undocumented); one testbed; egress only.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0019, 2026-09-10).
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
from scipy.stats import mannwhitneyu

import exp0008_cadence_features as cf
from exp0009_payload import (
    ARFF_SHA256, RAW_ARFF, TXT_SHA256, _arff_data_rows, _parse_optional_float, _sha256,
)
from exp0017_operational import load_result
from features_txt import RAW_TXT, iter_records
from features_windowed import build_windows

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0019_pressure_rate_plausibility.json"
)
CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]
CMRI = 2
WINDOW_SECONDS = 5.0
READ_RESPONSE = (0x03, 23, 0)                    # function_code, frame_len_bytes, is_request

EXP0017_TEST_CONFUSION = (4767, 40, 2166, 2374)  # tn, fp, fn, tp (comb_pred)

# ---- fixed method constants (pre-registered, EXPERIMENT_LOG.md EXP-0019) ----
CUTOFF_PERCENTILE = 99.9         # TRAIN-normal |Δp|/Δt percentile -> plausibility bound

# ---- fixed decision rule (pre-registered) ----
STRONG_MIN_NEW_RECALL = 0.25
ACCEPTABLE_MIN_NEW_RECALL = 0.10
MAX_NEW_NORMAL_FP_RATE = 0.0030
MIN_COMBINED_PRECISION = 0.970
SIGNAL_ALPHA = 0.01


# --------------------------------------------------------------- aligned series

def align_egress_pressure_timeseries(
    *, txt_path: Path = RAW_TXT, arff_path: Path = RAW_ARFF,
) -> list[tuple[float, float]]:
    """Row-index alignment of TXT to ARFF (EXP-0016 verification loop) keeping
    `(timestamp, pressure)` for every egress canonical `0x03` read response.
    Global order is ascending timestamp (the TXT is monotonic). Non-finite
    pressures are dropped."""
    if _sha256(txt_path) != TXT_SHA256:
        raise ValueError("TXT sha256 mismatch")
    if _sha256(arff_path) != ARFF_SHA256:
        raise ValueError("ARFF sha256 mismatch")
    rows = _arff_data_rows(arff_path)
    sentinel = object()
    row_iterator = iter(rows)
    out: list[tuple[float, float]] = []
    row_count = 0
    for record in iter_records(txt_path):
        row = next(row_iterator, sentinel)
        if row is sentinel:
            raise ValueError("ARFF has fewer rows than TXT")
        row_count += 1
        if record.record_index != row_count:
            raise ValueError(f"TXT row index mismatch at row {row_count}")
        if record.destination != 1:
            continue
        if len(row) != 20:
            raise ValueError(f"ARFF row {row_count} has {len(row)} fields, expected 20")
        if (
            int(row[15]) != 0
            or float(row[16]) != record.timestamp
            or int(row[18]) != record.categorized_attack
            or int(row[19]) != record.specific_attack
        ):
            raise ValueError(f"TXT/ARFF alignment mismatch at row {row_count}")
        if (record.function_code, record.frame_len_bytes, record.is_request) != READ_RESPONSE:
            continue
        value = _parse_optional_float(row[13])
        if value is None or not math.isfinite(value):
            continue
        out.append((float(record.timestamp), float(value)))
    if next(row_iterator, sentinel) is not sentinel:
        raise ValueError("ARFF has more rows than TXT")
    if any(b[0] < a[0] for a, b in zip(out, out[1:])):
        raise ValueError("egress 0x03 timestamps are not monotonic")
    return out


# --------------------------------------------------------------- blocks

class Blocks:
    """TRAIN / VALIDATION / TEST bucket sets from the checksummed manifest,
    constructed exactly as EXP-0017 / EXP-0018."""

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
        self.train_normal = {b for b in self.train if wins[idpos[b]].is_attack == 0}

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


# --------------------------------------------------------------- rate feature

def bucket_of(ts: float) -> int:
    return math.floor(ts / WINDOW_SECONDS)


def step_rates(series: list[tuple[float, float]]):
    """Consecutive-pair |Δp|/Δt. Returns (rate, later_bucket, later_ts) arrays for
    every pair with Δt > 0 (Δt <= 0 dropped defensively; impossible here)."""
    rates, buckets, later_ts = [], [], []
    for (t0, p0), (t1, p1) in zip(series, series[1:]):
        dt = t1 - t0
        if dt <= 0:
            continue
        rates.append(abs(p1 - p0) / dt)
        buckets.append(bucket_of(t1))
        later_ts.append(t1)
    return np.asarray(rates), np.asarray(buckets, dtype=int), np.asarray(later_ts)


def window_max_rate(rates: np.ndarray, buckets: np.ndarray) -> dict[int, float]:
    """rate_w = max step rate over pairs whose LATER sample falls in window w."""
    by_win: dict[int, float] = {}
    for r, b in zip(rates, buckets):
        b = int(b)
        if b not in by_win or r > by_win[b]:
            by_win[b] = float(r)
    return by_win


def train_normal_step_rates(series: list[tuple[float, float]], blocks: Blocks) -> np.ndarray:
    out = []
    for (t0, p0), (t1, p1) in zip(series, series[1:]):
        dt = t1 - t0
        if dt <= 0:
            continue
        if (blocks.label(bucket_of(t0)) == "train_normal"
                and blocks.label(bucket_of(t1)) == "train_normal"):
            out.append(abs(p1 - p0) / dt)
    return np.asarray(out, dtype=float)


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
    """Pre-registered decision rule (EXPERIMENT_LOG.md EXP-0019)."""
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


def _q(a: np.ndarray) -> dict:
    return {
        "n": int(len(a)), "median": float(np.median(a)),
        "iqr": [float(np.quantile(a, 0.25)), float(np.quantile(a, 0.75))],
        "min": float(np.min(a)), "max": float(np.max(a)),
    }


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

    # ---- aligned pressure time series, blocks, rate feature ----
    blocks = Blocks()
    if (blocks.split_id, blocks.split_sha256) != (R.split_id, R.split_sha256):
        raise RuntimeError("manifest identity differs from the EXP-0017 artifact")
    series = align_egress_pressure_timeseries()
    rates, later_buckets, later_ts = step_rates(series)
    by_win = window_max_rate(rates, later_buckets)
    tn_rates = train_normal_step_rates(series, blocks)
    if len(tn_rates) < 500:
        raise RuntimeError("too few TRAIN-normal step rates for a percentile bound")

    pct = {
        "p50": float(np.percentile(tn_rates, 50)),
        "p90": float(np.percentile(tn_rates, 90)),
        "p99": float(np.percentile(tn_rates, 99)),
        "p99_9": float(np.percentile(tn_rates, 99.9)),
        "p99_99": float(np.percentile(tn_rates, 99.99)),
        "max": float(np.max(tn_rates)),
    }
    cutoff = float(np.percentile(tn_rates, CUTOFF_PERCENTILE))
    cutoff_max = pct["max"]

    def fired_for(thr: float) -> np.ndarray:
        return np.array(
            [int(by_win.get(int(w.w_index), -1.0) > thr) for w in test_windows],
            dtype=int,
        )

    rate_fired = fired_for(cutoff)
    rate_fired_maxbound = fired_for(cutoff_max)
    rate_defined = np.array([int(w.w_index) in by_win for w in test_windows], dtype=bool)

    # For each window, the earlier bucket of the pair that produced its max rate
    # (same pair filter as step_rates: Δt > 0).
    max_pair_earlier: dict[int, int] = {}
    _best: dict[int, float] = {}
    for (t0, p0), (t1, p1) in zip(series, series[1:]):
        dt = t1 - t0
        if dt <= 0:
            continue
        r = abs(p1 - p0) / dt
        b1 = bucket_of(t1)
        if b1 not in _best or r > _best[b1]:
            _best[b1] = r
            max_pair_earlier[b1] = bucket_of(t0)
    comb_by_bucket = {int(w.w_index): int(comb[i]) for i, w in enumerate(test_windows)}
    attack_by_bucket = {int(w.w_index): int(w.is_attack) for w in test_windows}

    # ---- evaluation cohort: CMRI TEST windows EXP-0017 misses ----
    normal_mask = _cohort_mask(test_windows, 0, "pure_normal")
    n_neg = int(normal_mask.sum())
    rate_normal_fp = int(rate_fired[normal_mask].sum())
    new_normal_fp_rate = rate_normal_fp / n_neg
    # strict TRAIN-normal-max cutoff: also report its Normal FP and combined precision
    mb_normal_fp = int(rate_fired_maxbound[normal_mask].sum())
    comb_mb = (comb | rate_fired_maxbound).astype(int)
    mb_tp = int(((comb_mb == 1) & (y == 1)).sum())
    mb_fp = int(((comb_mb == 1) & (y == 0)).sum())
    mb_combined_precision = mb_tp / (mb_tp + mb_fp) if (mb_tp + mb_fp) else 0.0

    # Diagnostic: how many pure-Normal FPs are a boundary artifact — the max-rate
    # pair steps DOWN from a preceding window that EXP-0017 already flags / that is
    # attack-labelled, i.e. the rule credits a Normal window for pressure returning
    # to normal after an anomaly rather than for its own behaviour.
    fp_boundary_artifact = 0
    fp_total = 0
    for w, m, f in zip(test_windows, normal_mask, rate_fired):
        if not (m and f):
            continue
        fp_total += 1
        prev_b = max_pair_earlier.get(int(w.w_index))
        if prev_b is not None and (comb_by_bucket.get(prev_b, 0) == 1
                                   or attack_by_bucket.get(prev_b, 0) == 1):
            fp_boundary_artifact += 1

    cohorts_out = []
    per_missed_defined = {}
    for mode in ("pure", "dominant", "containing"):
        cmri = _cohort_mask(test_windows, CMRI, mode)
        missed = cmri & (comb == 0)
        missed_def = missed & rate_defined
        for tag, arr in (("p99.9", rate_fired), ("train_normal_max", rate_fired_maxbound)):
            hits = int(arr[missed_def].sum())
            rec = hits / int(missed_def.sum()) if missed_def.sum() else 0.0
            cohorts_out.append({
                "cohort": mode, "cutoff_variant": tag,
                "cmri_windows": int(cmri.sum()),
                "exp0017_missed": int(missed.sum()),
                "missed_with_defined_rate": int(missed_def.sum()),
                "missed_rate_undefined": int((missed & ~rate_defined).sum()),
                "new_detections": hits,
                "new_recall": rec, "new_recall_pct": round(100 * rec, 3),
            })
        per_missed_defined[mode] = missed_def

    pure_missed = per_missed_defined["pure"]
    new_recall = (
        int(rate_fired[pure_missed].sum()) / int(pure_missed.sum())
        if pure_missed.sum() else 0.0
    )
    new_recall_maxbound = (
        int(rate_fired_maxbound[pure_missed].sum()) / int(pure_missed.sum())
        if pure_missed.sum() else 0.0
    )

    # ---- threshold-independent signal test ----
    e_missed = np.array(
        [by_win[int(w.w_index)] for w, m in zip(test_windows, pure_missed) if m],
        dtype=float,
    )
    e_normal = np.array(
        [by_win[int(w.w_index)] for w, m in zip(test_windows, normal_mask)
         if m and int(w.w_index) in by_win],
        dtype=float,
    )
    u_stat, p_two = mannwhitneyu(e_missed, e_normal, alternative="two-sided")
    missed_higher = bool(np.median(e_missed) > np.median(e_normal))
    signal_present = bool(p_two < SIGNAL_ALPHA and missed_higher)

    # ---- whole TEST block: combined OR rate ----
    comb2 = (comb | rate_fired).astype(int)
    w_tn = int(((comb2 == 0) & (y == 0)).sum())
    w_fp = int(((comb2 == 1) & (y == 0)).sum())
    w_fn = int(((comb2 == 0) & (y == 1)).sum())
    w_tp = int(((comb2 == 1) & (y == 1)).sum())
    combined_precision = w_tp / (w_tp + w_fp) if (w_tp + w_fp) else 0.0

    standalone = {
        "whole_attack_class": confusion(
            int(rate_fired[y == 1].sum()), int((y == 1).sum()), rate_normal_fp, n_neg,
        ),
    }
    noregress = {}
    for name, c in (("NMRI", 1), ("MFCI", 5), ("Recon", 7)):
        m = _cohort_mask(test_windows, c, "pure")
        standalone[name + "_pure"] = confusion(
            int(rate_fired[m].sum()), int(m.sum()), rate_normal_fp, n_neg,
        )
        e17 = int(comb[m].sum())
        e19 = int(comb2[m].sum())
        noregress[name + "_pure"] = {
            "n": int(m.sum()), "exp0017_combined_flagged": e17,
            "combined_or_rate_flagged": e19, "delta": e19 - e17,
        }

    verdict = classify_verdict(new_recall, new_normal_fp_rate, combined_precision)

    return {
        "status": "VALIDATED — RATE RULE BUILT AND SCORED; run_detector NOT modified",
        "experiment": "EXP-0019",
        "hypothesis": (
            "A forged CMRI jump can exceed the physically plausible rate of pressure "
            "change (|Δp|/Δt) given the real elapsed time since the last 0x03 reading, "
            "even when the value is inside the EXP-0016 bounds."
        ),
        "identity_gates": {
            "exp0017_artifact_loaded_and_verified": True,
            "comb_equals_protocol_or_pressure_or_if": gate_elementwise,
            "whole_test_confusion_matches_exp0017": bool(gate_confusion),
            "exp0017_confusion": list(EXP0017_TEST_CONFUSION),
            "run_detector_modified": False,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "timing": {
            "txt_timestamps_monotonic": True,
            "egress_0x03_samples": len(series),
            "train_normal_step_rate_pairs": int(len(tn_rates)),
            "note": "consecutive 0x03 Δt median ~3.39 s; ~7% of steps are 3-4x cadence "
                    "gaps (EXP-0007/0008). Δt divides |Δp| so gap jumps are more plausible.",
        },
        "pressure_source": (
            "ARFF 'pressure measurement' (data col 13), row-index aligned to the TXT "
            "and verified; canonical 0x03 read responses; keeps (timestamp, pressure)"
        ),
        "method": {
            "feature": "rate_i = |p_i - p_{i-1}| / (t_i - t_{i-1}) over consecutive "
                       "egress 0x03 responses; Δt from real TXT timestamps",
            "per_window": "rate_w = max step rate over pairs whose later sample is in w; "
                          "undefined (not flaggable) if w has no such pair",
            "cutoff_reasoning": (
                "register map/scale undocumented, so no engineering dP/dt limit exists; "
                "TRAIN-normal already contains the process's fastest legitimate valve/pump "
                "transitions. Bound = TRAIN-normal 99.9th percentile of rate (drops the "
                "~20 most extreme normal steps / 13 sub-cadence pairs; robust and still "
                "'as fast as the process was credibly seen to move'). k·σ rejected "
                "(EXP-0018: statistic too heavy-tailed for a Gaussian scale)."
            ),
            "train_normal_rate_percentiles": pct,
            "cutoff_primary_p99_9": cutoff,
            "cutoff_strict_train_normal_max": cutoff_max,
        },
        "evaluation_cohort": (
            "CMRI-labelled TEST windows with EXP-0017 comb_pred == 0 and a defined "
            "rate_w; 'new detection' = rate rule fires AND comb_pred == 0"
        ),
        "decision_rule": {
            "strong": f"new pure-CMRI recall >= {STRONG_MIN_NEW_RECALL:.0%} "
                      f"AND new pure-Normal FP <= {MAX_NEW_NORMAL_FP_RATE:.2%} "
                      f"AND combined precision >= {MIN_COMBINED_PRECISION:.1%}",
            "acceptable": f"recall >= {ACCEPTABLE_MIN_NEW_RECALL:.0%} AND same bars",
            "new_pure_cmri_recall": new_recall,
            "new_pure_normal_fp": rate_normal_fp,
            "new_pure_normal_fp_rate": new_normal_fp_rate,
            "combined_precision": combined_precision,
            "verdict": verdict,
            "train_normal_max_bound_variant": {
                "new_pure_cmri_recall": new_recall_maxbound,
                "new_pure_normal_fp": mb_normal_fp,
                "new_pure_normal_fp_rate": mb_normal_fp / n_neg,
                "combined_precision": mb_combined_precision,
                "verdict": classify_verdict(
                    new_recall_maxbound, mb_normal_fp / n_neg, mb_combined_precision,
                ),
            },
        },
        "signal_test": {
            "test": "Mann-Whitney U, two-sided; missed pure-CMRI vs pure-Normal rate_w",
            "u_statistic": float(u_stat), "p_value": float(p_two), "alpha": SIGNAL_ALPHA,
            "missed_cmri_rate_higher_than_normal": missed_higher,
            "signal_present_in_hypothesised_direction": signal_present,
            "rate_distribution": {
                "missed_pure_cmri": _q(e_missed),
                "pure_normal_test": _q(e_normal),
                "train_normal_step_rates": _q(tn_rates),
            },
        },
        "per_cohort_new_detection": cohorts_out,
        "pure_normal_test_false_positives": {
            "n_windows": n_neg,
            "rate_rule_fp": rate_normal_fp,
            "rate_rule_fpr_pct": round(100 * new_normal_fp_rate, 4),
            "exp0017_combined_fp": int(comb[normal_mask].sum()),
            "combined_or_rate_fp": int(comb2[normal_mask].sum()),
            "boundary_artifact_diagnostic": {
                "rate_rule_fp_total": fp_total,
                "fp_where_max_rate_pair_steps_from_flagged_or_attack_predecessor":
                    fp_boundary_artifact,
                "residual_fp_after_excluding_those": fp_total - fp_boundary_artifact,
                "residual_fpr_pct": round(
                    100 * (fp_total - fp_boundary_artifact) / n_neg, 4),
                "note": "diagnostic only; the pre-registered rule is NOT changed or "
                        "rescored. A follow-up would need a fresh pre-registration.",
            },
        },
        "rate_rule_standalone": standalone,
        "no_regression": noregress,
        "whole_test_block_binary_confusion": {
            "cohort": "all 9,347 TEST windows; positive = is_attack",
            "exp0017_comb": dict(zip(("tn", "fp", "fn", "tp"), EXP0017_TEST_CONFUSION)),
            "combined_or_rate": {"tn": w_tn, "fp": w_fp, "fn": w_fn, "tp": w_tp},
            "delta_tn_fp_fn_tp": [
                w_tn - EXP0017_TEST_CONFUSION[0], w_fp - EXP0017_TEST_CONFUSION[1],
                w_fn - EXP0017_TEST_CONFUSION[2], w_tp - EXP0017_TEST_CONFUSION[3],
            ],
            "combined_or_rate_precision": combined_precision,
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
            "The plausibility cutoff is an empirical TRAIN-normal percentile, not a "
            "physical dP/dt limit — TRAIN-normal may not contain every legitimate fast "
            "transient the process can make.",
            "1-2 pressure samples per 5 s window: rate_w is one step rate, and a "
            "window's later sample may pair with the previous window's last sample.",
            "Judged only on CMRI windows EXP-0017 already misses; incidental effects "
            "on other categories are reported, not tuned for.",
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
    rd = st["rate_distribution"]
    lines = [
        "# EXP-0019 — physical rate-of-change plausibility test for missed CMRI",
        "",
        f"TRAIN-normal |dp|/dt percentiles: p50={m['train_normal_rate_percentiles']['p50']:.4f}  "
        f"p99={m['train_normal_rate_percentiles']['p99']:.4f}  "
        f"p99.9={m['train_normal_rate_percentiles']['p99_9']:.4f}  "
        f"max={m['train_normal_rate_percentiles']['max']:.4f}",
        f"Primary cutoff (p99.9): rate_w > {m['cutoff_primary_p99_9']:.4f}   "
        f"strict cutoff (TRAIN-normal max): > {m['cutoff_strict_train_normal_max']:.4f}",
        f"run_detector() modified: {r['identity_gates']['run_detector_modified']}",
        "",
        f"## DECISION-RULE VERDICT: {dr['verdict']}",
        f"- new pure-CMRI recall (windows EXP-0017 misses): "
        f"{100 * dr['new_pure_cmri_recall']:.2f}%  (strong >=25%, acceptable >=10%)",
        f"- new pure-Normal FP: {dr['new_pure_normal_fp']}/{fp['n_windows']} = "
        f"{100 * dr['new_pure_normal_fp_rate']:.4f}%  (bar <=0.30%)",
        f"- combined precision (comb OR rate): {100 * dr['combined_precision']:.3f}%  (bar >=97.0%)",
        f"- strict (TRAIN-normal max) cutoff: recall "
        f"{100 * dr['train_normal_max_bound_variant']['new_pure_cmri_recall']:.2f}%  "
        f"new-Normal-FP {100 * dr['train_normal_max_bound_variant']['new_pure_normal_fp_rate']:.4f}%  "
        f"comb-prec {100 * dr['train_normal_max_bound_variant']['combined_precision']:.3f}%  "
        f"-> {dr['train_normal_max_bound_variant']['verdict']}",
        "",
        f"## SIGNAL TEST (threshold-independent): "
        f"{'PRESENT' if st['signal_present_in_hypothesised_direction'] else 'NOT SUPPORTED'}",
        f"- Mann-Whitney U={st['u_statistic']:.0f}  p={st['p_value']:.3g}  (alpha {st['alpha']})",
        f"- missed-CMRI rate higher than Normal: {st['missed_cmri_rate_higher_than_normal']}",
        f"- median rate_w  missed-CMRI {rd['missed_pure_cmri']['median']:.4f}"
        f"  | Normal {rd['pure_normal_test']['median']:.4f}"
        f"  | TRAIN-normal steps {rd['train_normal_step_rates']['median']:.4f}",
        "",
        "## New detections on CMRI windows EXP-0017 misses",
        "| cohort | cutoff | missed (defined rate) | new detections | new recall% |",
        "|---|---|---:|---:|---:|",
    ]
    for c in r["per_cohort_new_detection"]:
        lines.append(
            f"| {c['cohort']} | {c['cutoff_variant']} | {c['missed_with_defined_rate']} "
            f"| {c['new_detections']} | {c['new_recall_pct']:.2f} |"
        )
    lines += [
        "",
        "## Whole 9,347-window TEST block (binary attack/Normal)",
        f"- EXP-0017 comb : TN/FP/FN/TP = "
        f"{wt['exp0017_comb']['tn']}/{wt['exp0017_comb']['fp']}/"
        f"{wt['exp0017_comb']['fn']}/{wt['exp0017_comb']['tp']}",
        f"- comb OR rate  : TN/FP/FN/TP = "
        f"{wt['combined_or_rate']['tn']}/{wt['combined_or_rate']['fp']}/"
        f"{wt['combined_or_rate']['fn']}/{wt['combined_or_rate']['tp']}",
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
