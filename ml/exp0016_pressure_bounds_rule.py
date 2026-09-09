#!/usr/bin/env python3
"""EXP-0016 — decoded-pressure out-of-bounds rule for NMRI (first built fix).

Adds `rules.PressureBoundsRule` (additive, alongside the untouched
`DeterministicRuleLayer`) and measures it — alone and OR-ed into a reproduced
EXP-0004 combined detector — against the frozen TEST block. The operational
`ml/iforest_detector.run_detector` is NOT modified; the effect of adding the rule
to EXP-0004's frozen TEST confusion is measured and reported here.

Pressure is the ARFF `pressure measurement` value, row-index aligned to the TXT
exactly as EXP-0009 / EXP-0011a do, taken from canonical 0x03 read responses.
Bounds are the observed min/max of TRAIN-normal 0x03 pressure (no documented
range exists). See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0016, 2026-09-10).
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
from sklearn.ensemble import IsolationForest

import exp0008_cadence_features as cf
from exp0009_payload import (
    ARFF_SHA256, RAW_ARFF, TXT_SHA256, _arff_data_rows, _parse_optional_float,
    _sha256,
)
from features_txt import RAW_TXT, iter_records
from features_windowed import IF_FEATURES, WINDOW_FEATURES, build_windows
from iforest_detector import SEED, contiguous_blocks, run_detector
from rules import DeterministicRuleLayer, PressureBoundsRule

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0016_pressure_bounds_rule.json"
)
CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]
WINDOW_SECONDS = 5.0
READ_RESPONSE = (0x03, 23, 0)  # function_code, frame_len_bytes, is_request

EXP0004_THRESHOLD = 0.6745465823488428
EXP0004_TEST_CONFUSION = (4771, 36, 3793, 747)  # tn, fp, fn, tp for rule OR IF

# Fixed decision rule (pre-registered).
STRONG_MIN_RECALL = 0.50
ACCEPTABLE_MIN_RECALL = 0.30
MAX_NEW_NORMAL_FP_RATE = 0.0030


# --------------------------------------------------------------- pressure decode

def align_egress_pressure(
    *, txt_path: Path = RAW_TXT, arff_path: Path = RAW_ARFF,
) -> dict[int, list[float]]:
    """Row-index alignment of TXT to ARFF (same discipline as
    exp0009_payload.align_pretest_pressure) — but retains pressure for EVERY
    egress 0x03 read response, all blocks. Returns {w_index: [pressure values]}.
    """
    if _sha256(txt_path) != TXT_SHA256:
        raise ValueError("TXT sha256 mismatch")
    if _sha256(arff_path) != ARFF_SHA256:
        raise ValueError("ARFF sha256 mismatch")
    rows = _arff_data_rows(arff_path)
    sentinel = object()
    by_bucket: dict[int, list[float]] = {}
    row_count = 0
    row_iterator = iter(rows)
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
        if value is None:
            continue
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        by_bucket.setdefault(bucket, []).append(value)
    if next(row_iterator, sentinel) is not sentinel:
        raise ValueError("ARFF has more rows than TXT")
    return by_bucket


def window_pressure_min_max(
    by_bucket: Mapping[int, Sequence[float]],
) -> dict[int, tuple[float | None, float | None, int]]:
    out: dict[int, tuple[float | None, float | None, int]] = {}
    for bucket, values in by_bucket.items():
        finite = [v for v in values if math.isfinite(v)]
        if finite:
            out[bucket] = (min(finite), max(finite), len(finite))
        else:
            out[bucket] = (None, None, 0)
    return out


# --------------------------------------------------------------- frozen detector

class FrozenExp0004Detector:
    """EXP-0004 combined detector reproduced in-process; gated on element-wise
    TEST if_pred vs run_detector(), the frozen threshold, and the frozen TEST
    confusion, before any scoring."""

    def __init__(self) -> None:
        reference = run_detector()
        wins = sorted(build_windows(), key=lambda w: w.w_index)
        self.windows = wins
        n = len(wins)
        x_raw = np.array(
            [[w.features[f] for f in WINDOW_FEATURES] for w in wins], dtype=float,
        )
        y = np.array([w.is_attack for w in wins])
        tr, va, te = contiguous_blocks(n)
        tr_normal = tr[y[tr] == 0]

        split = cf.load_pretest_split()
        self.split_id = split.split_id
        self.split_sha256 = split.membership_sha256
        if tuple(int(wins[i].w_index) for i in tr) != split.train_bucket_ids:
            raise RuntimeError("EXP-0004 TRAIN buckets differ from the corrected manifest")
        if tuple(int(wins[i].w_index) for i in va) != split.validation_bucket_ids:
            raise RuntimeError("EXP-0004 VALIDATION buckets differ from the corrected manifest")
        te_buckets = [int(wins[i].w_index) for i in te]
        after_val = sorted(
            int(w.w_index) for w in wins if w.w_index > split.final_pretest_bucket_id
        )
        if te_buckets != after_val[2 * cf.GUARD_WINDOWS:]:
            raise RuntimeError("EXP-0004 TEST buckets differ from the manifest-derived construction")

        block = {}
        for i in tr:
            block[wins[i].w_index] = "TRAIN"
        for i in va:
            block[wins[i].w_index] = "VALIDATION"
        for i in te:
            block[wins[i].w_index] = "TEST"
        self.block = block

        self.mu, self.sd = reference.mu, reference.sd
        self.threshold = reference.threshold
        self.if_idx = [WINDOW_FEATURES.index(f) for f in IF_FEATURES]
        x_z = (x_raw - self.mu) / self.sd

        clf = IsolationForest(
            n_estimators=300, max_samples="auto", contamination="auto",
            random_state=SEED, n_jobs=-1,
        )
        clf.fit(x_z[np.ix_(tr_normal, self.if_idx)])
        self.clf = clf

        s_te = -clf.score_samples(x_z[np.ix_(te, self.if_idx)])
        if_pred_te = (s_te >= self.threshold).astype(int)
        if not np.array_equal(if_pred_te, reference.if_pred):
            raise RuntimeError("reproduced Isolation Forest does not match run_detector()")
        if abs(self.threshold - EXP0004_THRESHOLD) > 1e-12:
            raise RuntimeError("threshold != EXP-0004 frozen value")

        self.rule = DeterministicRuleLayer()
        self.rule.valid_func_codes = reference.valid_func_codes
        self.rule.valid_addresses = reference.valid_addresses
        self.rule._fitted = True

        rule_te = np.array([int(self.rule.evaluate(wins[i]).fired) for i in te], dtype=int)
        comb_te = (if_pred_te | rule_te).astype(int)
        y_te = y[te]
        conf = (
            int(((comb_te == 0) & (y_te == 0)).sum()),
            int(((comb_te == 1) & (y_te == 0)).sum()),
            int(((comb_te == 0) & (y_te == 1)).sum()),
            int(((comb_te == 1) & (y_te == 1)).sum()),
        )
        if conf != EXP0004_TEST_CONFUSION:
            raise RuntimeError(f"combined TEST confusion {conf} != EXP-0004 {EXP0004_TEST_CONFUSION}")

        self.test_windows = [wins[i] for i in te]
        self.y_test = y_te
        self.if_flag_test = if_pred_te
        self.rule_flag_test = rule_te
        self.train_normal_windows = [wins[i] for i in tr_normal]

    def train_normal_bucket_ids(self) -> set[int]:
        return {w.w_index for w in self.train_normal_windows}


# --------------------------------------------------------------- scoring

def confusion(tp: int, n_pos: int, fp: int, n_neg: int) -> dict:
    fn, tn = n_pos - tp, n_neg - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / n_pos if n_pos else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / n_neg if n_neg else 0.0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "precision_pct": round(100 * precision, 3), "recall_pct": round(100 * recall, 3),
        "f1_pct": round(100 * f1, 3), "fpr_pct": round(100 * fpr, 4),
    }


def _cohort_test_buckets(detector: FrozenExp0004Detector, cat: int, mode: str) -> list[int]:
    out = []
    for w in detector.test_windows:
        cs = w.categories
        if mode == "pure_normal":
            keep = cs == frozenset({0})
        elif mode == "pure":
            keep = cat in cs and cs <= {0, cat}
        elif mode == "containing":
            keep = cat in cs
        elif mode == "dominant":
            keep = w.dominant_attack_category == cat
        else:
            raise ValueError(mode)
        if keep:
            out.append(w.w_index)
    return out


def run_experiment() -> dict:
    detector = FrozenExp0004Detector()
    by_bucket = align_egress_pressure()
    win_pressure = window_pressure_min_max(by_bucket)

    # --- fit the rule from TRAIN-normal 0x03 pressure only ---
    train_normal_ids = detector.train_normal_bucket_ids()
    train_normal_values = [
        v for b, vs in by_bucket.items() if b in train_normal_ids for v in vs
        if math.isfinite(v)
    ]
    rule = PressureBoundsRule().fit(train_normal_values)
    low, high = rule.bounds.low, rule.bounds.high
    p_arr = np.array(train_normal_values, dtype=float)
    percentile_variant = {
        "low_p0.1": float(np.quantile(p_arr, 0.001)),
        "high_p99.9": float(np.quantile(p_arr, 0.999)),
        "note": "reported for context only; the frozen rule uses min/max",
    }

    idx_of = {w.w_index: i for i, w in enumerate(detector.test_windows)}

    def pressure_flag(w_index: int) -> int:
        lo, hi, _ = win_pressure.get(w_index, (None, None, 0))
        return int(rule.evaluate(lo, hi).fired)

    # negative class for every confusion table = pure-Normal TEST windows
    normal_ids = _cohort_test_buckets(detector, 0, "pure_normal")
    n_neg = len(normal_ids)
    rule_fp = sum(pressure_flag(b) for b in normal_ids)
    comb_fp = sum(
        int(
            detector.if_flag_test[idx_of[b]]
            or detector.rule_flag_test[idx_of[b]]
            or pressure_flag(b)
        )
        for b in normal_ids
    )
    exp0004_normal_fp = int(
        (detector.if_flag_test[[idx_of[b] for b in normal_ids]]
         | detector.rule_flag_test[[idx_of[b] for b in normal_ids]]).sum()
    )

    per_cohort: list[dict] = []
    for cat in range(1, 8):
        name = CATEGORY_NAMES[cat]
        modes = ["pure"]
        if cat in (1, 2):
            modes += ["containing", "dominant"]
        for mode in modes:
            ids = _cohort_test_buckets(detector, cat, mode)
            if not ids:
                continue
            rule_tp = sum(pressure_flag(b) for b in ids)
            comb_tp = sum(
                int(
                    detector.if_flag_test[idx_of[b]]
                    or detector.rule_flag_test[idx_of[b]]
                    or pressure_flag(b)
                )
                for b in ids
            )
            exp0004_tp = int(
                (detector.if_flag_test[[idx_of[b] for b in ids]]
                 | detector.rule_flag_test[[idx_of[b] for b in ids]]).sum()
            )
            per_cohort.append({
                "category": name, "cohort": mode, "n_positive": len(ids),
                "pressure_rule_alone": confusion(rule_tp, len(ids), rule_fp, n_neg),
                "exp0004_combined": confusion(exp0004_tp, len(ids), exp0004_normal_fp, n_neg),
                "combined_with_pressure_rule": confusion(comb_tp, len(ids), comb_fp, n_neg),
            })

    # --- whole TEST block (9,347 windows) binary attack/Normal confusion ---
    y = detector.y_test
    if_f = detector.if_flag_test
    rule_f = detector.rule_flag_test
    press_f = np.array(
        [pressure_flag(w.w_index) for w in detector.test_windows], dtype=int,
    )
    comb_full = (if_f | rule_f | press_f).astype(int)
    tn = int(((comb_full == 0) & (y == 0)).sum())
    fp = int(((comb_full == 1) & (y == 0)).sum())
    fn = int(((comb_full == 0) & (y == 1)).sum())
    tp = int(((comb_full == 1) & (y == 1)).sum())
    delta = (tn - EXP0004_TEST_CONFUSION[0], fp - EXP0004_TEST_CONFUSION[1],
             fn - EXP0004_TEST_CONFUSION[2], tp - EXP0004_TEST_CONFUSION[3])

    # --- decision-rule evaluation (pre-registered) ---
    nmri_pure = next(
        r for r in per_cohort if r["category"] == "NMRI" and r["cohort"] == "pure"
    )
    nmri_recall = nmri_pure["pressure_rule_alone"]["recall"]
    new_normal_fp_rate = rule_fp / n_neg
    if nmri_recall >= STRONG_MIN_RECALL and new_normal_fp_rate <= MAX_NEW_NORMAL_FP_RATE:
        verdict = "STRONG"
    elif nmri_recall >= ACCEPTABLE_MIN_RECALL and new_normal_fp_rate <= MAX_NEW_NORMAL_FP_RATE:
        verdict = "ACCEPTABLE"
    else:
        verdict = "WEAK / RECONSIDER"

    return {
        "status": "VALIDATED — RULE BUILT AND SCORED; run_detector NOT modified",
        "experiment": "EXP-0016",
        "detector": {
            "source": "EXP-0004 combined: DeterministicRuleLayer OR IsolationForest",
            "run_detector_modified": False,
            "identity_gates_passed": [
                "reproduced IF if_pred == run_detector().if_pred on real TEST (element-wise)",
                "reproduced threshold == EXP-0004 frozen 0.6745465823488428",
                "reproduced combined TEST confusion == EXP-0004 (4771,36,3793,747)",
            ],
        },
        "manifest": {
            "split_id": detector.split_id, "membership_sha256": detector.split_sha256,
        },
        "pressure_source": (
            "ARFF 'pressure measurement' (data col 13), row-index aligned to the TXT "
            "and verified (direction/timestamp/category/specific); canonical 0x03 read "
            "responses only; reuses exp0009_payload primitives"
        ),
        "rule": {
            "class": "rules.PressureBoundsRule (additive; DeterministicRuleLayer untouched)",
            "bounds_low": low, "bounds_high": high,
            "bounds_source": rule.bounds.source,
            "train_normal_value_count": len(train_normal_values),
            "percentile_variant_for_context": percentile_variant,
            "fires_when": "window min 0x03 pressure < low OR window max > high",
        },
        "decision_rule": {
            "strong": f"pure-NMRI TEST recall >= {STRONG_MIN_RECALL:.0%} "
                      f"AND new pure-Normal FP rate <= {MAX_NEW_NORMAL_FP_RATE:.2%}",
            "acceptable": f"recall >= {ACCEPTABLE_MIN_RECALL:.0%} AND FP <= {MAX_NEW_NORMAL_FP_RATE:.2%}",
            "nmri_pure_recall": nmri_recall,
            "new_pure_normal_fp": rule_fp,
            "new_pure_normal_fp_rate": new_normal_fp_rate,
            "verdict": verdict,
        },
        "pure_normal_test_false_positives": {
            "n_windows": n_neg,
            "pressure_rule_alone_fp": rule_fp,
            "pressure_rule_alone_fpr_pct": round(100 * rule_fp / n_neg, 4),
            "exp0004_combined_fp": exp0004_normal_fp,
            "combined_with_pressure_rule_fp": comb_fp,
        },
        "per_cohort_test": per_cohort,
        "whole_test_block_binary_confusion": {
            "cohort": "all 9,347 TEST windows; positive = is_attack",
            "exp0004_frozen": {
                "tn": EXP0004_TEST_CONFUSION[0], "fp": EXP0004_TEST_CONFUSION[1],
                "fn": EXP0004_TEST_CONFUSION[2], "tp": EXP0004_TEST_CONFUSION[3],
            },
            "with_pressure_rule": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "delta_tn_fp_fn_tp": list(delta),
            "note": (
                "run_detector() is NOT modified. Wiring PressureBoundsRule into the "
                "operational detector would change EXP-0004's frozen TEST confusion by "
                f"this delta ({list(delta)}) and update the baseline — a separate decision."
            ),
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "scikit_learn": version("scikit-learn"),
        },
        "limitations": [
            "Pressure is the ARFF-aligned value; a PCAP-replay deployment would decode it "
            "from the 0x03 response bytes and that register map/scale is undocumented.",
            "Bounds are an empirical TRAIN-normal range, not a physical spec.",
            "NMRI 'random value' forgeries land inside the normal range a meaningful "
            "fraction of the time, so a value-bound rule has a real ceiling below 100%.",
            "CMRI / MSCI incidental detections are reported per category, not tuned for.",
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
    temporary.write_text(
        json.dumps(_json_ready(result), indent=2) + "\n", encoding="utf-8",
    )
    os.replace(temporary, path)


def _format_report(r: Mapping) -> str:
    dr = r["decision_rule"]
    fp = r["pure_normal_test_false_positives"]
    wt = r["whole_test_block_binary_confusion"]
    lines = [
        "# EXP-0016 — decoded-pressure out-of-bounds rule for NMRI",
        "",
        f"Bounds (TRAIN-normal 0x03 pressure min/max): [{r['rule']['bounds_low']:.4f}, "
        f"{r['rule']['bounds_high']:.4f}]  (n={r['rule']['train_normal_value_count']})",
        f"run_detector() modified: {r['detector']['run_detector_modified']}",
        "",
        f"## DECISION-RULE VERDICT: {dr['verdict']}",
        f"- pure-NMRI TEST recall (rule alone): {100*dr['nmri_pure_recall']:.2f}%  "
        f"(bar: strong >= 50%, acceptable >= 30%)",
        f"- new pure-Normal TEST false positives (rule alone): {fp['pressure_rule_alone_fp']}"
        f"/{fp['n_windows']} = {fp['pressure_rule_alone_fpr_pct']}%  (bar: <= 0.30%)",
        "",
        "## Rule alone / EXP-0004 / combined+rule — TEST cohorts "
        "(negative = 4,807 pure-Normal TEST)",
        "",
        "| category | cohort | n+ | rule-alone recall% | rule-alone prec% | "
        "EXP-0004 recall% | combined+rule recall% |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for c in r["per_cohort_test"]:
        ra, e4, cw = c["pressure_rule_alone"], c["exp0004_combined"], c["combined_with_pressure_rule"]
        lines.append(
            f"| {c['category']} | {c['cohort']} | {c['n_positive']} "
            f"| {ra['recall_pct']:.2f} | {ra['precision_pct']:.2f} "
            f"| {e4['recall_pct']:.2f} | {cw['recall_pct']:.2f} |"
        )
    lines += [
        "",
        f"pure-Normal TEST FP: EXP-0004 {fp['exp0004_combined_fp']} -> "
        f"combined+rule {fp['combined_with_pressure_rule_fp']} (of {fp['n_windows']})",
        "",
        "## Whole 9,347-window TEST block (binary attack/Normal)",
        f"- EXP-0004 frozen : TN/FP/FN/TP = "
        f"{wt['exp0004_frozen']['tn']}/{wt['exp0004_frozen']['fp']}/"
        f"{wt['exp0004_frozen']['fn']}/{wt['exp0004_frozen']['tp']}",
        f"- with pressure rule: TN/FP/FN/TP = "
        f"{wt['with_pressure_rule']['tn']}/{wt['with_pressure_rule']['fp']}/"
        f"{wt['with_pressure_rule']['fn']}/{wt['with_pressure_rule']['tp']}",
        f"- delta (TN,FP,FN,TP): {wt['delta_tn_fp_fn_tp']}",
        f"- {wt['note']}",
        "",
        "_run_detector NOT modified; wiring the rule in would update EXP-0004's baseline._",
    ]
    return "\n".join(lines)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
