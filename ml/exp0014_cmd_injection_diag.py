#!/usr/bin/env python3
"""EXP-0014 — diagnostic: why does the EXP-0004 detector miss MSCI / MPCI?

Diagnostic / investigative only. No model is trained, retrained, re-thresholded,
or changed; no feature is added. The EXP-0004 combined detector (deterministic
rule layer OR Isolation Forest) is reproduced in-process from the same
ml/features_windowed + ml/iforest_detector primitives and asserted identical to
EXP-0004's frozen regression constants (threshold + TEST confusion, exactly what
tests/test_detector.py checks) before any per-window score is read.

ml/iforest_detector.py, ml/rules.py, ml/features_windowed.py are not modified.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0014, 2026-09-09).
"""
from __future__ import annotations

import bisect
import json
import math
import os
import platform
import statistics
from importlib.metadata import version
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

import exp0008_cadence_features as cf
from features_windowed import IF_FEATURES, WINDOW_FEATURES, Window, build_windows
from iforest_detector import SEED, contiguous_blocks
from rules import DeterministicRuleLayer

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0014_cmd_injection_diag.json"
)
CATEGORIES = {"MSCI": 3, "MPCI": 4}
DOS_CATEGORY = 6

EXP0004_THRESHOLD = 0.6745465823488428
EXP0004_TEST_CONFUSION = (4771, 36, 3793, 747)  # tn, fp, fn, tp for rule OR IF

# EXP-0003 / EXP-0004 effect-size convention.
def grade_effect(d: float) -> str:
    a = abs(d)
    if a < 0.2:
        return "negligible"
    if a < 0.5:
        return "small"
    if a < 0.8:
        return "medium"
    return "large"


# --------------------------------------------------------------- frozen detector

class FrozenExp0004Detector:
    """EXP-0004 combined detector, reproduced from ml/features_windowed +
    ml/iforest_detector primitives (one build_windows() call, no run_detector())
    and asserted identical to EXP-0004's frozen regression constants — the exact
    threshold and TEST confusion that tests/test_detector.py checks."""

    def __init__(self) -> None:
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
        tr_buckets = tuple(int(wins[i].w_index) for i in tr)
        va_buckets = tuple(int(wins[i].w_index) for i in va)
        te_buckets = [int(wins[i].w_index) for i in te]
        after_val = sorted(
            int(w.w_index) for w in wins if w.w_index > split.final_pretest_bucket_id
        )
        if tr_buckets != split.train_bucket_ids:
            raise RuntimeError("EXP-0004 TRAIN buckets differ from the corrected manifest")
        if va_buckets != split.validation_bucket_ids:
            raise RuntimeError("EXP-0004 VALIDATION buckets differ from the corrected manifest")
        if te_buckets != after_val[2 * cf.GUARD_WINDOWS:]:
            raise RuntimeError("EXP-0004 TEST buckets differ from the manifest-derived construction")

        block = {}
        for i in tr:
            block[wins[i].w_index] = "TRAIN"
        for i in va:
            block[wins[i].w_index] = "VALIDATION"
        for i in te:
            block[wins[i].w_index] = "TEST"
        self.block = block  # windows in the guard gaps are absent by design

        # standardiser frozen from TRAIN-normal (iforest_detector.zfit)
        mu = x_raw[tr_normal].mean(axis=0)
        sd = x_raw[tr_normal].std(axis=0)
        sd[sd == 0] = 1.0
        self.mu, self.sd = mu, sd
        self.if_idx = [WINDOW_FEATURES.index(f) for f in IF_FEATURES]
        x_z = (x_raw - mu) / sd

        clf = IsolationForest(
            n_estimators=300, max_samples="auto", contamination="auto",
            random_state=SEED, n_jobs=-1,
        )
        clf.fit(x_z[np.ix_(tr_normal, self.if_idx)])
        self.clf = clf

        # threshold = VALIDATION-normal 99th-percentile score (TARGET_FPR = 0.01)
        s_va = -clf.score_samples(x_z[np.ix_(va, self.if_idx)])
        self.threshold = float(np.quantile(s_va[y[va] == 0], 0.99))
        if abs(self.threshold - EXP0004_THRESHOLD) > 1e-12:
            raise RuntimeError(
                f"reproduced threshold {self.threshold} != EXP-0004 frozen {EXP0004_THRESHOLD}"
            )

        self.rule = DeterministicRuleLayer().fit([wins[i] for i in tr_normal])

        s_te = -clf.score_samples(x_z[np.ix_(te, self.if_idx)])
        if_pred_te = (s_te >= self.threshold).astype(int)

        comb_te = (if_pred_te | np.array(
            [int(self.rule.evaluate(wins[i]).fired) for i in te], dtype=int,
        )).astype(int)
        y_te = y[te]
        confusion = (
            int(((comb_te == 0) & (y_te == 0)).sum()),
            int(((comb_te == 1) & (y_te == 0)).sum()),
            int(((comb_te == 0) & (y_te == 1)).sum()),
            int(((comb_te == 1) & (y_te == 1)).sum()),
        )
        if confusion != EXP0004_TEST_CONFUSION:
            raise RuntimeError(f"combined TEST confusion {confusion} != EXP-0004 {EXP0004_TEST_CONFUSION}")

        self.pure_normal = [w for w in wins if w.categories == frozenset({0})]
        # Anchor + negative-class FP are computed on the held-out TEST pure-Normal
        # windows (the honest comparison; also keeps the scoring cost bounded).
        self.normal_test = [
            w for w in self.pure_normal if block.get(w.w_index) == "TEST"
        ]
        normal_test_scores = self.if_scores(self.normal_test)
        self.normal_mean_score = float(normal_test_scores.mean())
        self.normal_test_fp = int((
            (normal_test_scores >= self.threshold).astype(int)
            | self.rule_fires(self.normal_test)
        ).sum())

    def if_scores(self, windows: Sequence[Window]) -> np.ndarray:
        if not windows:
            return np.array([], dtype=float)
        matrix = np.array(
            [[w.features[f] for f in WINDOW_FEATURES] for w in windows], dtype=float,
        )
        z = (matrix - self.mu) / self.sd
        return -self.clf.score_samples(z[:, self.if_idx])

    def rule_fires(self, windows: Sequence[Window]) -> np.ndarray:
        return np.array([int(self.rule.evaluate(w).fired) for w in windows], dtype=int)


# --------------------------------------------------------------- stats helpers

def feature_summary(windows: Sequence[Window]) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for name in WINDOW_FEATURES:
        values = [float(w.features[name]) for w in windows]
        out[name] = {
            "mean": statistics.mean(values) if values else 0.0,
            "std": statistics.pstdev(values) if len(values) > 1 else 0.0,
            "n": len(values),
        }
    return out


def cohens_d(a: Mapping[str, float], b: Mapping[str, float]) -> float:
    pooled = math.sqrt((a["std"] ** 2 + b["std"] ** 2) / 2.0)
    if pooled == 0.0:
        return 0.0
    return (a["mean"] - b["mean"]) / pooled


def score_distribution(scores: np.ndarray) -> dict[str, float]:
    if scores.size == 0:
        return {}
    q = np.quantile(scores, [0.0, 0.10, 0.25, 0.50, 0.75, 0.90, 1.0])
    return {
        "n": int(scores.size),
        "min": float(q[0]), "p10": float(q[1]), "p25": float(q[2]),
        "median": float(q[3]), "p75": float(q[4]), "p90": float(q[5]),
        "max": float(q[6]), "mean": float(scores.mean()),
    }


def nearest_normal_matches(
    attack_windows: Sequence[Window], pure_normal_sorted: Sequence[Window],
) -> list[Window]:
    """For each attack window, the pure-Normal window with the closest w_index."""
    indices = [w.w_index for w in pure_normal_sorted]
    matched: list[Window] = []
    for aw in attack_windows:
        pos = bisect.bisect_left(indices, aw.w_index)
        candidates = []
        if pos < len(indices):
            candidates.append(pos)
        if pos > 0:
            candidates.append(pos - 1)
        best = min(candidates, key=lambda p: abs(indices[p] - aw.w_index))
        matched.append(pure_normal_sorted[best])
    return matched


# --------------------------------------------------------------- diagnostic

def _containing(windows: Sequence[Window], cat: int) -> list[Window]:
    return [w for w in windows if cat in w.categories]


def _pure(windows: Sequence[Window], cat: int) -> list[Window]:
    return [w for w in windows if cat in w.categories and w.categories <= {0, cat}]


def _block_counts(detector: FrozenExp0004Detector, windows: Sequence[Window]) -> dict:
    counts = {"TRAIN": 0, "VALIDATION": 0, "TEST": 0, "GUARD": 0}
    for w in windows:
        counts[detector.block.get(w.w_index, "GUARD")] += 1
    return counts


def _confusion(tp: int, n_pos: int, fp: int, n_neg: int) -> dict:
    fn, tn = n_pos - tp, n_neg - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / n_pos if n_pos else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": fp / n_neg if n_neg else 0.0,
        "precision_pct": round(100 * precision, 2), "recall_pct": round(100 * recall, 2),
        "f1_pct": round(100 * f1, 2), "fpr_pct": round(100 * (fp / n_neg if n_neg else 0.0), 4),
    }


def run_diagnostic() -> dict:
    detector = FrozenExp0004Detector()
    wins = detector.windows
    pure_normal = detector.pure_normal  # index-sorted
    normal_full = feature_summary(pure_normal)
    dos_counts = _block_counts(detector, _containing(wins, DOS_CATEGORY))

    # negative class for the confusion table = held-out TEST pure-Normal windows.
    normal_test = detector.normal_test
    neg_test_fp = detector.normal_test_fp

    per_category: dict[str, dict] = {}
    for name, cat in CATEGORIES.items():
        containing = _containing(wins, cat)
        pure = _pure(wins, cat)

        matched_normal = nearest_normal_matches(pure, pure_normal)
        pure_summary = feature_summary(pure)
        matched_summary = feature_summary(matched_normal)

        features = []
        for fname in WINDOW_FEATURES:
            d_full = cohens_d(pure_summary[fname], normal_full[fname])
            d_matched = cohens_d(pure_summary[fname], matched_summary[fname])
            features.append({
                "feature": fname,
                "is_if_input": fname in IF_FEATURES,
                "attack_mean": pure_summary[fname]["mean"],
                "attack_std": pure_summary[fname]["std"],
                "normal_full_mean": normal_full[fname]["mean"],
                "normal_full_std": normal_full[fname]["std"],
                "matched_normal_mean": matched_summary[fname]["mean"],
                "cohens_d_vs_full_normal": d_full,
                "cohens_d_vs_matched_normal": d_matched,
                "effect_vs_matched": grade_effect(d_matched),
            })
        features.sort(key=lambda r: -abs(r["cohens_d_vs_matched_normal"]))

        # score each window set once; derive IF flag, rule flag, combined from it
        scores_all = detector.if_scores(containing)
        rule_all = detector.rule_fires(containing)
        if_all = (scores_all >= detector.threshold).astype(int)
        comb_all = (if_all | rule_all).astype(int) if scores_all.size else np.array([], int)
        test_mask = np.array(
            [detector.block.get(w.w_index) == "TEST" for w in containing], dtype=bool,
        )
        scores_test = scores_all[test_mask]
        comb_test = comb_all[test_mask]

        confusion = {
            "cohort": "TEST block; positive = windows containing >=1 this-category "
                      "frame; negative = pure-Normal TEST windows; detector = EXP-0004 "
                      "rule OR IF (unchanged). FP/TN are EXP-0004's frozen Normal split.",
            "test_block": _confusion(
                int(comb_test.sum()), int(test_mask.sum()), neg_test_fp, len(normal_test),
            ),
        }
        frac_if_all = float(if_all.mean()) if scores_all.size else 0.0
        frac_if_test = float((scores_test >= detector.threshold).mean()) if scores_test.size else 0.0

        # where does the score mass sit: 0 = Normal mean, 1 = threshold
        span = detector.threshold - detector.normal_mean_score
        median_position = (
            (float(np.median(scores_all)) - detector.normal_mean_score) / span
            if scores_all.size and span else None
        )

        max_effect = max(abs(r["cohens_d_vs_matched_normal"]) for r in features)
        per_category[name] = {
            "categorized_result": cat,
            "definition": (
                "Malicious State Command Injection — command-side; alters pump / solenoid "
                "/ system-mode / forces critical condition"
                if name == "MSCI" else
                "Malicious Parameter Command Injection — command-side; alters setpoint / "
                "PID gain / reset rate / rate / deadband / cycle time"
            ),
            "egress_frame_note": (
                "every MSCI/MPCI-labelled egress frame is a function 0x10 8-byte "
                "write-echo, structurally identical to a normal write echo (start_register "
                "3049, quantity 18, byte_count -1, length_anomaly 0, entropy 3.0000)"
            ),
            "window_counts": {
                "containing_ge1_frame": _block_counts(detector, containing),
                "pure_only_this_and_normal": _block_counts(detector, pure),
                "total_containing": len(containing),
                "total_pure": len(pure),
            },
            "combined_detector_confusion": confusion,
            "feature_diagnostic": {
                "normal_reference": "pure-Normal windows; full population and "
                                    "nearest-index matched sample",
                "matched_sample_n": len(matched_normal),
                "matched_sample_n_unique": len({w.w_index for w in matched_normal}),
                "max_abs_cohens_d_vs_matched": max_effect,
                "features_with_nonnegligible_effect": [
                    r["feature"] for r in features
                    if abs(r["cohens_d_vs_matched_normal"]) >= 0.2
                ],
                "per_feature": features,
            },
            "if_score_diagnostic": {
                "threshold": detector.threshold,
                "normal_window_mean_score": detector.normal_mean_score,
                "all_blocks": score_distribution(scores_all),
                "test_block": score_distribution(scores_test),
                "fraction_if_flag_all_blocks": frac_if_all,
                "fraction_if_flag_test_block": frac_if_test,
                "rule_layer_fires_all_blocks": int(rule_all.sum()),
                "median_score_position_normal0_threshold1": median_position,
            },
        }

    return {
        "status": "VALIDATED — DIAGNOSTIC ONLY; NO MODEL TRAINED OR CHANGED",
        "experiment": "EXP-0014",
        "scope": "egress only (destination == 1); MSCI and MPCI vs Normal",
        "detector": {
            "source": "EXP-0004 combined: DeterministicRuleLayer OR IsolationForest",
            "modified": False,
            "identity_gates_passed": [
                "reproduced threshold == EXP-0004 frozen 0.6745465823488428",
                "reproduced combined TEST confusion == EXP-0004 (4771,36,3793,747)",
                "split == verified-egress-5s-exp0008-pretest-v1 (byte-identical)",
            ],
        },
        "manifest": {
            "split_id": detector.split_id,
            "membership_sha256": detector.split_sha256,
            "boundary_gate": "EXP-0004 contiguous_blocks split asserted byte-identical "
                             "to verified-egress-5s-exp0008-pretest-v1",
        },
        "class_size_context": {
            "note": "the current detector is UNSUPERVISED (fitted on Normal only), so "
                    "class size does not limit it directly; these counts bound a future "
                    "supervised fix",
            "DoS_containing_windows": dos_counts,
            "pure_normal_windows": _block_counts(detector, pure_normal),
        },
        "per_category": per_category,
        "software": {
            "python": platform.python_version(),
            "numpy": version("numpy"),
            "scikit_learn": version("scikit-learn"),
        },
        "limitations": [
            "Cohen's d compares aggregate window features; the matched-normal sample "
            "controls for slow drift by window index, not for every confounder.",
            "Pure-MSCI/MPCI windows still contain normal-labelled read responses whose "
            "payloads reflect attack-disturbed pressure; any entropy signal is that "
            "second-order effect, not the injected command itself.",
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


def _format_report(result: Mapping) -> str:
    lines = [
        "# EXP-0014 — diagnostic: MSCI / MPCI detection gap",
        "",
        "Diagnostic only. EXP-0004 detector reproduced and asserted identical; nothing "
        "trained or changed.",
        "",
    ]
    for name, block in result["per_category"].items():
        s = block["if_score_diagnostic"]
        c = block["combined_detector_confusion"]
        lines += [
            f"## {name} (categorized_result {block['categorized_result']})",
            "",
            f"- {block['definition']}",
            f"- egress: {block['egress_frame_note']}",
            f"- windows containing >=1 {name} frame: {block['window_counts']['containing_ge1_frame']}",
            f"- pure {name}(+Normal) windows: {block['window_counts']['pure_only_this_and_normal']}",
            "",
            "  EXP-0004 combined detector, TEST block (positive = attack-containing "
            "windows, negative = pure-Normal TEST windows):",
            "  | recall % | precision % | F1 % | FP % (of Normal) | TP | FN | FP | TN |",
            "  |---:|---:|---:|---:|---:|---:|---:|---:|",
            (
                lambda cc: f"  | {cc['recall_pct']:.2f} | {cc['precision_pct']:.2f} "
                f"| {cc['f1_pct']:.2f} | {cc['fpr_pct']:.4f} | {cc['tp']} | {cc['fn']} "
                f"| {cc['fp']} | {cc['tn']} |"
            )(c["test_block"]),
            "",
            f"- max |Cohen's d| vs matched Normal across all 16 features: "
            f"{block['feature_diagnostic']['max_abs_cohens_d_vs_matched']:.3f}",
            f"- features with |d| >= 0.2: "
            f"{block['feature_diagnostic']['features_with_nonnegligible_effect'] or 'none'}",
            "",
            f"- IF score (all blocks): median {s['all_blocks'].get('median', float('nan')):.4f}, "
            f"mean {s['all_blocks'].get('mean', float('nan')):.4f}  "
            f"[Normal-window mean {s['normal_window_mean_score']:.4f}, threshold {s['threshold']:.4f}]",
            f"- IF flags {s['fraction_if_flag_all_blocks']:.4f} of {name} windows (all blocks); "
            f"{s['fraction_if_flag_test_block']:.4f} on TEST; rule layer fires "
            f"{s['rule_layer_fires_all_blocks']} times",
            f"- median score position (0=Normal mean, 1=threshold): "
            f"{s['median_score_position_normal0_threshold1']}",
            "",
            "  | feature (top 6 by |d|) | attack mean | matched-Normal mean | d vs matched | effect |",
            "  |---|---:|---:|---:|---|",
        ]
        for row in block["feature_diagnostic"]["per_feature"][:6]:
            lines.append(
                f"  | {row['feature']}{'' if row['is_if_input'] else ' (rule-only)'} "
                f"| {row['attack_mean']:.4f} | {row['matched_normal_mean']:.4f} "
                f"| {row['cohens_d_vs_matched_normal']:+.3f} | {row['effect_vs_matched']} |"
            )
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    result = run_diagnostic()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
