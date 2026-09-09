#!/usr/bin/env python3
"""EXP-0007 egress-only cadence CUSUM and supervised comparison."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from cadence_features import CADENCE_FEATURES, CadenceDataset, build_cadence_dataset
from features_txt import FrameRecord
from layer_a_detector import binary_metrics

SEED = 0
PROBABILITY_THRESHOLD = 0.5
RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0007_cadence.json"
)


def make_classifier() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=SEED, n_jobs=-1,
    )


def _cohort(dataset: CadenceDataset, indices: np.ndarray) -> np.ndarray:
    return np.array([
        index for index in indices
        if dataset.windows[index].is_pure_normal or dataset.windows[index].contains_dos
    ], dtype=int)


def _labels(dataset: CadenceDataset, indices: np.ndarray) -> np.ndarray:
    return np.array([
        int(dataset.windows[index].contains_dos) for index in indices
    ], dtype=int)


def _matrix(dataset: CadenceDataset) -> np.ndarray:
    return np.array([
        [window.features[name] for name in CADENCE_FEATURES]
        for window in dataset.windows
    ], dtype=float)


def _counts(dataset: CadenceDataset, indices: np.ndarray) -> dict[str, int]:
    cohort = _cohort(dataset, indices)
    labels = _labels(dataset, cohort)
    return {
        "windows": len(indices), "cohort": len(cohort),
        "normal": int((labels == 0).sum()), "dos": int((labels == 1).sum()),
        "excluded_other_attack": int(len(indices) - len(cohort)),
    }


def run_experiment(
    records: Iterable[FrameRecord] | None = None, *, score_test: bool = True,
) -> dict:
    """Run the frozen experiment; ``score_test=False`` supports pre-TEST checks."""
    dataset = build_cadence_dataset(records)
    matrix = _matrix(dataset)
    train_cohort = _cohort(dataset, dataset.train)
    validation_cohort = _cohort(dataset, dataset.validation)
    classifier = make_classifier()
    classifier.fit(matrix[train_cohort], _labels(dataset, train_cohort))

    def evaluate(indices: np.ndarray) -> dict:
        labels = _labels(dataset, indices)
        probabilities = classifier.predict_proba(matrix[indices])[:, 1]
        predictions = (probabilities >= PROBABILITY_THRESHOLD).astype(int)
        cusum_predictions = np.array([
            int(dataset.windows[index].features["cusum_alarm_count_total"] > 0)
            for index in indices
        ], dtype=int)
        return {
            "detector_a_cusum": binary_metrics(labels, cusum_predictions),
            "detector_b_random_forest": binary_metrics(labels, predictions),
        }

    result = {
        "status": "INVALIDATED — EXP-0007 TEST WAS VIEWED WITH METHOD DEFECTS" if score_test else "IMPLEMENTED — TEST NOT RUN",
        "experiment": "EXP-0007",
        "scope": {
            "direction": "egress only", "destination_values": sorted({
                record.destination for record in dataset.frames
            }), "frames": len(dataset.frames), "cadence_source": 3,
            "response_types": ["0x03", "0x10"],
            "cohort": "DoS-containing versus pure-Normal five-second windows",
        },
        "split_counts": {
            "train": _counts(dataset, dataset.train),
            "validation": _counts(dataset, dataset.validation),
            "test": _counts(dataset, dataset.test) if score_test else {
                "status": "NOT RUN"
            },
        },
        "feature_names": CADENCE_FEATURES,
        "baselines": {
            f"0x{code:02x}": {
                "count": baseline.count, "mean": baseline.expected_iat,
                "median": baseline.median_iat, "std": baseline.std_iat,
                "cv": baseline.cv, "scale": baseline.scale,
            } for code, baseline in dataset.baselines.items()
        },
        "cusum": {
            "allowance": 0.5,
            "thresholds": {f"0x{code:02x}": value for code, value in dataset.thresholds.items()},
            "calibration": "TRAIN pure-Normal 99th percentile, method=higher",
        },
        "random_forest": {
            "n_estimators": 300, "class_weight": "balanced",
            "random_state": SEED, "n_jobs": -1,
            "probability_threshold": PROBABILITY_THRESHOLD,
        },
        "audit": dataset.audit,
        "validation_metrics": evaluate(validation_cohort),
        "test_metrics": evaluate(_cohort(dataset, dataset.test)) if score_test else {
            "status": "NOT RUN"
        },
        "limitations": [
            "Response function code is an egress-visible proxy for an unseen query type.",
            "Source is dataset grouping metadata and is not a model input.",
            "One labelled testbed does not establish universal DoS detectability.",
        ],
    }
    return result


def write_result(result: dict, path: Path = RESULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    result = run_experiment()
    write_result(result)
    print(json.dumps(result, indent=2))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
