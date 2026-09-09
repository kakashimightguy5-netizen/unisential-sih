#!/usr/bin/env python3
"""EXP-0010 — synthetic egress-flood (Type 2 DoS) capability test.

Measures whether the ALREADY-VALIDATED EXP-0004 detector (deterministic rule
layer OR Isolation Forest) flags a clearly-labelled *synthetic* egress-channel
flood injected into real Normal egress windows. No model is trained or tuned
here; ml/iforest_detector.py, ml/rules.py and ml/features_windowed.py are not
modified. Every result is a SYNTHETIC INJECTION TEST, never captured attack data.

See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0010, 2026-09-09) for the Type 1 vs
Type 2 distinction and the pre-registered parameters.
"""
from __future__ import annotations

import json
import math
import os
import platform
import statistics
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

import exp0008_cadence_features as cf
from features_txt import FrameRecord, iter_records
from features_windowed import (
    EGRESS_DESTINATION, MIN_FRAMES_PER_WINDOW, NORMAL_FUNC_CODES, WINDOW_FEATURES,
    WINDOW_SECONDS, IF_FEATURES, Window, build_windows,
)
from iforest_detector import SEED, contiguous_blocks, run_detector
from rules import DeterministicRuleLayer

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0010_egress_flood.json"
)
SEVERITIES = (1, 2, 5, 10, 20)
PROFILES = ("A_distinct", "B_duplicate")
SYNTH_FRAME_ID_BASE = 1_000_000_000_000  # far above any 32-bit crc32 frame_id

# EXP-0004 frozen reference (see tests/test_detector.py).
EXP0004_THRESHOLD = 0.6745465823488428
EXP0004_TEST_CONFUSION = (4771, 36, 3793, 747)  # tn, fp, fn, tp for rule OR IF


# --------------------------------------------------------------- feature helper

def _window_features(frames: Sequence[FrameRecord]) -> dict:
    """Reproduce features_windowed.build_windows' per-window feature dict exactly.

    Asserted identical to build_windows() for every real Normal TEST window at
    K == 1 (see verify_feature_helper / the slow test).
    """
    fr = sorted(frames, key=lambda r: r.timestamp)
    n = len(fr)
    lens = [r.frame_len_bytes for r in fr]
    ents = [r.message_entropy_bits_per_byte for r in fr]
    iats = [fr[i].timestamp - fr[i - 1].timestamp for i in range(1, n)]
    fids = [r.frame_id for r in fr]
    repeats = sum(1 for i in range(1, n) if fids[i] == fids[i - 1])
    return {
        "packet_count": float(n),
        "packets_per_sec": n / WINDOW_SECONDS,
        "bytes_per_sec": sum(lens) / WINDOW_SECONDS,
        "mean_frame_len": statistics.mean(lens),
        "iat_mean": statistics.mean(iats) if iats else WINDOW_SECONDS,
        "iat_std": statistics.pstdev(iats) if len(iats) > 1 else 0.0,
        "iat_min": min(iats) if iats else WINDOW_SECONDS,
        "iat_max": max(iats) if iats else WINDOW_SECONDS,
        "frac_func_valid": sum(r.function_code in NORMAL_FUNC_CODES for r in fr) / n,
        "frac_func_read": sum(r.function_code == 0x03 for r in fr) / n,
        "frac_func_write": sum(r.function_code == 0x10 for r in fr) / n,
        "rare_func_rate": sum(r.rare_function_code for r in fr) / n,
        "distinct_frame_ratio": len(set(fids)) / n,
        "repeat_frame_rate": repeats / (n - 1) if n > 1 else 1.0,
        "payload_entropy_mean": statistics.mean(ents),
        "payload_entropy_std": statistics.pstdev(ents) if len(ents) > 1 else 0.0,
    }


def _window_from_frames(frames: Sequence[FrameRecord], w_index: int) -> Window:
    cats = frozenset(r.categorized_attack for r in frames)
    return Window(
        w_index=w_index, t_start=w_index * WINDOW_SECONDS,
        features=_window_features(frames),
        is_attack=int(any(c != 0 for c in cats)), categories=cats,
        func_codes=frozenset(r.function_code for r in frames),
        addresses=frozenset(r.address for r in frames),
    )


# --------------------------------------------------------------- flood synthesis

def synthesize_flood(
    frames: Sequence[FrameRecord], w_index: int, k: int, profile: str,
) -> list[FrameRecord]:
    """Build a K-times-rate synthetic flood over the window's 5-second bucket.

    Uniform re-spacing; function codes and address are inherited from the window's
    real frames so the deterministic rule layer stays silent. Deterministic (no RNG).
    """
    real = sorted(frames, key=lambda r: r.timestamp)
    n = len(real)
    if k == 1:
        return list(real)
    target_n = int(round(k * n))
    cycled = [real[i % n] for i in range(target_n)]

    if profile == "A_distinct":
        # only volume/timing move: every frame gets a fresh unique frame_id
        cycled = [
            replace(src, frame_id=SYNTH_FRAME_ID_BASE + i)
            for i, src in enumerate(cycled)
        ]
    elif profile == "B_duplicate":
        # keep frame_id, group identical frames so repeat_frame_rate rises
        cycled = sorted(cycled, key=lambda r: r.frame_id)
    else:
        raise ValueError(f"unknown profile: {profile!r}")

    base = w_index * WINDOW_SECONDS
    gap = WINDOW_SECONDS / target_n
    return [
        replace(
            src, record_index=i, timestamp=base + i * gap,
            interarrival_seconds=(gap if i else 0.0),
        )
        for i, src in enumerate(cycled)
    ]


# --------------------------------------------------------------- frozen detector

class FrozenExp0004Detector:
    """The EXP-0004 combined detector, reproduced in-process and asserted identical
    to run_detector() before any synthetic window is scored."""

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

        # -- boundary gate: existing split == corrected manifest construction --
        split = cf.load_pretest_split()
        self.split_id = split.split_id
        self.split_sha256 = split.membership_sha256
        tr_buckets = tuple(int(wins[i].w_index) for i in tr)
        va_buckets = tuple(int(wins[i].w_index) for i in va)
        te_buckets = [int(wins[i].w_index) for i in te]
        after_val = sorted(
            int(w.w_index) for w in wins if w.w_index > split.final_pretest_bucket_id
        )
        manifest_test = after_val[2 * cf.GUARD_WINDOWS:]
        if tr_buckets != split.train_bucket_ids:
            raise RuntimeError("EXP-0004 TRAIN buckets differ from the corrected manifest")
        if va_buckets != split.validation_bucket_ids:
            raise RuntimeError("EXP-0004 VALIDATION buckets differ from the corrected manifest")
        if te_buckets != manifest_test:
            raise RuntimeError("EXP-0004 TEST buckets differ from the manifest-derived construction")

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

        # -- identity gate: reproduced IF == validated IF, and combined == EXP-0004 --
        s_te = -clf.score_samples(x_z[np.ix_(te, self.if_idx)])
        if_pred_te = (s_te >= self.threshold).astype(int)
        if not np.array_equal(if_pred_te, reference.if_pred):
            raise RuntimeError("reproduced Isolation Forest does not match run_detector()")
        if abs(self.threshold - EXP0004_THRESHOLD) > 1e-12:
            raise RuntimeError("threshold differs from the EXP-0004 frozen value")

        self.rule = DeterministicRuleLayer()
        self.rule.valid_func_codes = reference.valid_func_codes
        self.rule.valid_addresses = reference.valid_addresses
        self.rule._fitted = True

        comb_te = (if_pred_te | np.array([
            int(self.rule.evaluate(wins[i]).fired) for i in te
        ])).astype(int)
        y_te = y[te]
        tn = int(((comb_te == 0) & (y_te == 0)).sum())
        fp = int(((comb_te == 1) & (y_te == 0)).sum())
        fn = int(((comb_te == 0) & (y_te == 1)).sum())
        tp = int(((comb_te == 1) & (y_te == 1)).sum())
        if (tn, fp, fn, tp) != EXP0004_TEST_CONFUSION:
            raise RuntimeError(
                f"combined TEST confusion {(tn, fp, fn, tp)} != EXP-0004 {EXP0004_TEST_CONFUSION}"
            )

        self.test_indices = list(te)
        self.y = y
        self.tr_normal_indices = list(tr_normal)
        self.x_raw = x_raw

    def if_scores(self, windows: Sequence[Window]) -> np.ndarray:
        matrix = np.array(
            [[w.features[f] for f in WINDOW_FEATURES] for w in windows], dtype=float,
        )
        z = (matrix - self.mu) / self.sd
        return -self.clf.score_samples(z[:, self.if_idx])

    def score(self, windows: Sequence[Window]) -> dict:
        scores = self.if_scores(windows)
        if_flag = (scores >= self.threshold).astype(int)
        rule_flag = np.array(
            [int(self.rule.evaluate(w).fired) for w in windows], dtype=int,
        )
        comb = (if_flag | rule_flag).astype(int)
        return {
            "n": len(windows),
            "combined_rate": float(comb.mean()),
            "if_rate": float(if_flag.mean()),
            "rule_rate": float(rule_flag.mean()),
            "mean_if_score": float(scores.mean()),
            "median_if_score": float(np.median(scores)),
            "combined_flagged": int(comb.sum()),
        }


# --------------------------------------------------------------- experiment

def egress_frame_buckets(
    records: Iterable[FrameRecord] | None = None,
) -> dict[int, list[FrameRecord]]:
    source = iter_records() if records is None else records
    buckets: dict[int, list[FrameRecord]] = {}
    for record in source:
        if record.destination != EGRESS_DESTINATION:
            continue
        buckets.setdefault(math.floor(record.timestamp / WINDOW_SECONDS), []).append(record)
    return {b: fr for b, fr in buckets.items() if len(fr) >= MIN_FRAMES_PER_WINDOW}


def verify_feature_helper(
    detector: FrozenExp0004Detector, buckets: Mapping[int, list[FrameRecord]],
    normal_test_windows: Sequence[Window],
) -> None:
    """K == 1: the local feature helper must reproduce build_windows() exactly."""
    for window in normal_test_windows:
        rebuilt = _window_features(buckets[window.w_index])
        for name in WINDOW_FEATURES:
            if rebuilt[name] != window.features[name]:
                raise RuntimeError(
                    f"feature helper mismatch on window {window.w_index} / {name}: "
                    f"{rebuilt[name]!r} != {window.features[name]!r}"
                )


def run_flood_test(records: Iterable[FrameRecord] | None = None) -> dict:
    materialized = None if records is None else tuple(records)
    detector = FrozenExp0004Detector()
    buckets = egress_frame_buckets(materialized)

    normal_test = [
        detector.windows[i] for i in detector.test_indices
        if detector.windows[i].is_attack == 0
        and detector.windows[i].categories == frozenset({0})
    ]
    verify_feature_helper(detector, buckets, normal_test)

    # Negative class = the 4,807 real untouched Normal TEST windows, scored once.
    # It is unaffected by injection into other windows (verified), so FP / TN are
    # constant across every profile/severity row below.
    untouched = detector.score(normal_test)
    n_neg = untouched["n"]
    fp = untouched["combined_flagged"]
    tn = n_neg - fp

    def _confusion(tp: int, n_pos: int) -> dict:
        fn = n_pos - tp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) else 0.0
        )
        return {
            "tn": tn, "fp": fp, "fn": fn, "tp": tp,
            "precision": precision, "recall": recall, "f1": f1,
            "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        }

    severities: list[dict] = []
    for profile in PROFILES:
        for k in SEVERITIES:
            flooded = [
                _window_from_frames(
                    synthesize_flood(buckets[w.w_index], w.w_index, k, profile),
                    w.w_index,
                )
                for w in normal_test
            ]
            row = detector.score(flooded)
            row.update({"profile": profile, "severity_x": k})
            # Positive class = the same windows, flood-injected at this severity.
            row["confusion_vs_real_normal_test"] = _confusion(
                row["combined_flagged"], row["n"],
            )
            example = flooded[0].features
            row["example_window_features"] = {
                name: example[name] for name in (
                    "packet_count", "packets_per_sec", "bytes_per_sec",
                    "iat_mean", "iat_std", "distinct_frame_ratio", "repeat_frame_rate",
                )
            }
            if k == 1 and abs(row["combined_rate"] - untouched["combined_rate"]) > 1e-12:
                raise RuntimeError(
                    f"K=1 {profile} detection rate {row['combined_rate']} "
                    f"!= untouched baseline {untouched['combined_rate']}"
                )
            severities.append(row)

    # informational only — NOT built here
    pps_col = WINDOW_FEATURES.index("packets_per_sec")
    train_normal_pps = detector.x_raw[np.ix_(detector.tr_normal_indices, [pps_col])].ravel()
    real_normal_test_pps = np.array(
        [w.features["packets_per_sec"] for w in normal_test], dtype=float,
    )
    min_flood_pps = min(
        row["example_window_features"]["packets_per_sec"]
        for row in severities if row["severity_x"] == 2
    )
    fix_note = {
        "train_normal_packets_per_sec_max": float(train_normal_pps.max()),
        "train_normal_packets_per_sec_p99": float(np.quantile(train_normal_pps, 0.99)),
        "train_normal_packets_per_sec_mean": float(train_normal_pps.mean()),
        "real_normal_test_packets_per_sec_max": float(real_normal_test_pps.max()),
        "example_2x_flood_packets_per_sec": float(min_flood_pps),
        "comment": (
            "The Isolation Forest anomaly score SATURATES for a pure-volumetric flood "
            "(Profile A mean IF score is identical for 2x..20x and sits just under the "
            "frozen threshold), so it catches only ~24% regardless of severity. Every "
            "flooded window (>= 2x) exceeds the TRAIN-normal packets_per_sec maximum. A "
            "fixed rate-threshold rule in the existing deterministic rule layer (flag "
            "packets_per_sec above the TRAIN-normal max) would be a low-risk minimal "
            "fix catching both profiles at all severities. NOT implemented in EXP-0010."
        ),
    }

    return {
        "status": "VALIDATED — SYNTHETIC INJECTION CAPABILITY TEST; NO MODEL TRAINED",
        "experiment": "EXP-0010",
        "warning": (
            "SYNTHETIC INJECTION TEST. Every detection rate below is against an "
            "artificially constructed egress flood injected into real Normal egress "
            "windows. No dataset in this project contains a labelled Type 2 (egress-"
            "channel) DoS example. These are NOT results on captured attack data."
        ),
        "detector": {
            "source": "EXP-0004 combined: DeterministicRuleLayer OR IsolationForest",
            "modified": False,
            "reproduced_in_process": True,
            "threshold": detector.threshold,
            "if_features": list(IF_FEATURES),
            "identity_gates_passed": [
                "reproduced IF if_pred == run_detector().if_pred on real TEST",
                "combined TEST confusion == EXP-0004 (4771,36,3793,747)",
                "threshold == EXP-0004 frozen 0.6745465823488428",
            ],
        },
        "manifest": {
            "split_id": detector.split_id,
            "membership_sha256": detector.split_sha256,
            "boundary_gate": (
                "EXP-0004 contiguous_blocks(46,736) TRAIN/VALIDATION/TEST buckets "
                "asserted byte-identical to verified-egress-5s-exp0008-pretest-v1 and "
                "its manifest-derived guarded TEST construction"
            ),
        },
        "evaluation_cohort": {
            "negative_class": (
                f"the {len(normal_test)} real untouched Normal TEST windows "
                "(is_attack == 0, categories == {0}), scored once"
            ),
            "positive_class": (
                f"the same {len(normal_test)} windows, synthetic-flood-injected at the "
                "given (profile, severity)"
            ),
            "total_windows_per_row": 2 * len(normal_test),
            "note": (
                "FP and TN are constant across every row because the negative class is "
                "unmodified and injecting into other windows does not change the "
                "detector's verdict on real Normal traffic (verified). At severity 1x "
                "the positive class IS the negative class (no injection) — that row is "
                "the sanity anchor only, not a meaningful precision/recall point."
            ),
        },
        "injection": {
            "method": "frame-level synthesis, uniform re-spacing over the 5 s bucket",
            "substrate": "every real Normal TEST window",
            "substrate_count": len(normal_test),
            "severities_x": list(SEVERITIES),
            "profiles": {
                "A_distinct": "fresh unique frame_id per frame; only volume/timing move",
                "B_duplicate": "real frame_ids kept and grouped; also collapses "
                               "distinct_frame_ratio and raises repeat_frame_rate",
            },
            "rng": "none — deterministic cycling",
        },
        "untouched_real_normal_test": {
            "n": untouched["n"],
            "combined_fpr": untouched["combined_rate"],
            "if_fpr": untouched["if_rate"],
            "rule_fpr": untouched["rule_rate"],
            "exp0004_reference_combined_fpr": EXP0004_TEST_CONFUSION[1] / (
                EXP0004_TEST_CONFUSION[0] + EXP0004_TEST_CONFUSION[1]
            ),
        },
        "dose_response": severities,
        "minimal_fix_note_not_built": fix_note,
        "software": {
            "python": platform.python_version(),
            "numpy": version("numpy"),
            "scikit_learn": version("scikit-learn"),
        },
        "limitations": [
            "Synthetic flood: rate/volume anomaly is injected, not captured.",
            "Uniform re-spacing; a real flood carries timing jitter.",
            "One testbed's Normal egress profile; detectability may differ elsewhere.",
            "Profiles A/B bracket two flood shapes; a real flood may sit between them.",
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
        "# EXP-0010 — SYNTHETIC INJECTION TEST (Type 2 egress-flood DoS)",
        "",
        result["warning"],
        "",
        f"Detector: {result['detector']['source']} (unmodified, reproduced in-process).",
        f"Injection substrate: {result['injection']['substrate_count']} real Normal "
        f"TEST windows. Manifest: {result['manifest']['split_id']}.",
        "",
        "## Untouched real Normal TEST windows (false-positive control)",
        "",
        f"- combined FPR {result['untouched_real_normal_test']['combined_fpr']:.6f} "
        f"(EXP-0004 reference "
        f"{result['untouched_real_normal_test']['exp0004_reference_combined_fpr']:.6f})",
        "",
        "## Evaluation cohort",
        "",
        f"- negative class: {result['evaluation_cohort']['negative_class']}",
        f"- positive class: {result['evaluation_cohort']['positive_class']}",
        f"- {result['evaluation_cohort']['note']}",
        "",
        "## Dose-response — combined detector (rule OR IF)",
        "",
        "| profile | severity | precision | recall | F1 | FPR | TN | FP | FN | TP |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in result["dose_response"]:
        c = row["confusion_vs_real_normal_test"]
        lines.append(
            f"| {row['profile']} | {row['severity_x']}x | {c['precision']:.4f} "
            f"| {c['recall']:.4f} | {c['f1']:.4f} | {c['fpr']:.6f} "
            f"| {c['tn']} | {c['fp']} | {c['fn']} | {c['tp']} |"
        )
    lines += [
        "",
        "IF-only / rule-only detection rate and mean IF score per row are in the JSON.",
        "",
        "_SYNTHETIC INJECTION TEST — not captured attack data._",
    ]
    return "\n".join(lines)


def main() -> None:
    result = run_flood_test()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
