#!/usr/bin/env python3
"""EXP-0005b supervised and raw-feature diagnostic; does not alter EXP-0005."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from layer_a_detector import (
    LAYER_A_FEATURES, SEED, binary_metrics, build_windows, contiguous_blocks,
)

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0005b_diagnostic.json"
)


def run_diagnostic() -> dict:
    windows, n_frames = build_windows()
    matrix = np.array([
        [window.features[name] for name in LAYER_A_FEATURES] for window in windows
    ], dtype=float)
    pure_normal = np.array([window.is_pure_normal for window in windows])
    contains_dos = np.array([window.contains_dos for window in windows])
    train, validation, test = contiguous_blocks(len(windows))
    train_cohort = train[pure_normal[train] | contains_dos[train]]
    test_cohort = test[pure_normal[test] | contains_dos[test]]

    classifier = RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=SEED, n_jobs=-1,
    )
    classifier.fit(matrix[train_cohort], contains_dos[train_cohort].astype(int))
    probabilities = classifier.predict_proba(matrix[test_cohort])[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    labels = contains_dos[test_cohort].astype(int)

    dos_test = test[contains_dos[test]]
    normal_test = test[pure_normal[test]]
    rng = np.random.default_rng(SEED)
    normal_sample = rng.choice(normal_test, size=len(dos_test), replace=False)

    summaries = {}
    for name_index, name in enumerate(LAYER_A_FEATURES):
        dos_values = matrix[dos_test, name_index]
        normal_values = matrix[normal_sample, name_index]
        summaries[name] = {
            "dos_mean": float(dos_values.mean()),
            "dos_std": float(dos_values.std()),
            "normal_sample_mean": float(normal_values.mean()),
            "normal_sample_std": float(normal_values.std()),
        }

    return {
        "status": "VALIDATED", "experiment": "EXP-0005b",
        "model": {
            "type": "RandomForestClassifier", "n_estimators": 300,
            "class_weight": "balanced", "random_state": SEED,
            "probability_threshold": 0.5,
        },
        "label_rule": "positive if any categorized_attack == 6 frame is present",
        "counts": {
            "frames": n_frames, "windows": len(windows),
            "train_windows": len(train), "validation_windows": len(validation),
            "test_windows": len(test),
            "train_cohort_normal": int(pure_normal[train_cohort].sum()),
            "train_cohort_dos": int(contains_dos[train_cohort].sum()),
            "test_normal": int((labels == 0).sum()),
            "test_dos": int((labels == 1).sum()),
            "normal_summary_sample": len(normal_sample),
        },
        "metrics": binary_metrics(labels, predictions),
        "feature_summaries": summaries,
    }


def main() -> None:
    result = run_diagnostic()
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
