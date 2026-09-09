#!/usr/bin/env python3
"""Frozen preparation and explicitly guarded TEST scoring for EXP-0008."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from exp0008_cadence_features import (
    DOS_CATEGORY, EGRESS_DESTINATION, GUARD_WINDOWS, MIN_FRAMES_PER_WINDOW,
    WINDOW_SECONDS,
    BlockData, CadenceWindow, PreTestArtifacts,
    build_scoring_windows, load_pretest_split, prepare_pretest_artifacts,
)
from features_txt import FrameRecord, iter_records

SEED = 0
PROBABILITY_THRESHOLD = 0.5
FROZEN_TEST_CONFIRMATION = "SCORE-EXP-0008-TEST-ONCE"
PRETEST_RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0008_pretest.json"
)
FINAL_RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0008_cadence.json"
)


def make_classifier() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=SEED, n_jobs=-1,
    )


def _cohort(windows: Sequence[CadenceWindow]) -> np.ndarray:
    return np.array([
        index for index, window in enumerate(windows)
        if window.is_pure_normal or window.contains_dos
    ], dtype=int)


def _labels(windows: Sequence[CadenceWindow], indices: np.ndarray) -> np.ndarray:
    return np.array([int(windows[index].contains_dos) for index in indices], dtype=int)


def _matrix(windows: Sequence[CadenceWindow], names: Sequence[str]) -> np.ndarray:
    return np.array([
        [window.features[name] for name in names] for window in windows
    ], dtype=float)


def train_classifier(artifacts: PreTestArtifacts) -> RandomForestClassifier:
    cohort = _cohort(artifacts.train_windows)
    classifier = make_classifier()
    classifier.fit(
        _matrix(artifacts.train_windows, artifacts.feature_names)[cohort],
        _labels(artifacts.train_windows, cohort),
    )
    return classifier


def classifier_fingerprint(classifier: RandomForestClassifier) -> str:
    """Hash frozen hyperparameters and learned forest arrays semantically."""
    digest = hashlib.sha256()
    parameters = {
        "n_estimators": classifier.n_estimators,
        "class_weight": classifier.class_weight,
        "random_state": classifier.random_state,
        "n_jobs": classifier.n_jobs,
        "n_features_in": int(classifier.n_features_in_),
        "classes": classifier.classes_.tolist(),
    }
    digest.update(json.dumps(parameters, sort_keys=True).encode("utf-8"))
    for estimator in classifier.estimators_:
        tree = estimator.tree_
        for array in (
            tree.children_left, tree.children_right, tree.feature,
            tree.threshold, tree.value, tree.n_node_samples,
            tree.weighted_n_node_samples,
        ):
            contiguous = np.ascontiguousarray(array)
            digest.update(contiguous.dtype.str.encode("ascii"))
            digest.update(str(contiguous.shape).encode("ascii"))
            digest.update(contiguous.tobytes())
    return digest.hexdigest()


def _baseline_output(artifacts: PreTestArtifacts) -> dict:
    return {
        f"0x{response_type:02x}": {
            "count": baseline.count, "mean": baseline.expected_iat,
            "median": baseline.median_iat, "std": baseline.std_iat,
            "cv": baseline.cv, "scale": baseline.scale,
        } for response_type, baseline in artifacts.baselines.items()
    }


def _counts(windows: Sequence[CadenceWindow]) -> dict[str, int]:
    cohort = _cohort(windows)
    labels = _labels(windows, cohort)
    return {
        "windows": len(windows), "cohort": len(cohort),
        "normal": int((labels == 0).sum()), "dos": int((labels == 1).sum()),
        "excluded_other_attack": int(len(windows) - len(cohort)),
    }


def _evaluate(
    windows: Sequence[CadenceWindow], names: Sequence[str],
    classifier: RandomForestClassifier,
) -> dict:
    cohort = _cohort(windows)
    labels = _labels(windows, cohort)
    matrix = _matrix(windows, names)[cohort]
    probabilities = classifier.predict_proba(matrix)[:, 1]
    rf_predictions = (probabilities >= PROBABILITY_THRESHOLD).astype(int)
    cusum_predictions = np.array([
        int(windows[index].features["cusum_alarm_count_total"] > 0)
        for index in cohort
    ], dtype=int)
    return {
        "detector_a_cusum": binary_metrics(labels, cusum_predictions),
        "detector_b_random_forest": binary_metrics(labels, rf_predictions),
    }


def binary_metrics(labels: np.ndarray, predictions: np.ndarray) -> dict[str, float | int]:
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0,
    )
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def prepare_experiment(
    records: Iterable[FrameRecord] | None = None,
) -> tuple[dict, PreTestArtifacts, RandomForestClassifier]:
    """Fit and report frozen TRAIN/VALIDATION artifacts without scoring TEST."""
    artifacts = prepare_pretest_artifacts(records)
    classifier = train_classifier(artifacts)
    result = {
        "status": "IMPLEMENTED/TESTED — TEST NOT RUN",
        "experiment": "EXP-0008",
        "scope": {
            "direction": "egress only", "destination": EGRESS_DESTINATION,
            "split_id": artifacts.inputs.split_id,
            "split_membership_sha256": artifacts.inputs.split_membership_sha256,
            "cadence_source": 3,
            "cohort": "DoS-containing versus pure-Normal five-second windows",
            "total_egress_frames": artifacts.inputs.total_egress_frames,
            "total_emitted_windows": artifacts.inputs.total_emitted_windows,
        },
        "split_window_counts": {
            "train": artifacts.inputs.train_window_count,
            "validation": artifacts.inputs.validation_window_count,
            "test_unopened": artifacts.inputs.test_window_count,
        },
        "response_types": [f"0x{item:02x}" for item in artifacts.response_types],
        "audit": dict(artifacts.audit),
        "baselines": _baseline_output(artifacts),
        "cusum": {
            "allowance": 0.5,
            "thresholds": {
                f"0x{response_type:02x}": threshold
                for response_type, threshold in artifacts.thresholds.items()
            },
            "calibration": (
                "TRAIN pure-Normal window maxima, 99th percentile method=higher; "
                "same label-independent replay as inference"
            ),
        },
        "random_forest": {
            "n_estimators": 300, "class_weight": "balanced",
            "random_state": SEED, "n_jobs": -1,
            "probability_threshold": PROBABILITY_THRESHOLD,
            "semantic_fingerprint_sha256": classifier_fingerprint(classifier),
        },
        "feature_names": list(artifacts.feature_names),
        "train_counts": _counts(artifacts.train_windows),
        "validation_counts": _counts(artifacts.validation_windows),
        "validation_metrics": _evaluate(
            artifacts.validation_windows, artifacts.feature_names, classifier,
        ),
        "test_metrics": {"status": "NOT RUN"},
        "limitations": [
            "Response type is an egress-visible proxy for an unseen query type.",
            "Source is dataset grouping metadata and is not a model input.",
            "The labelled attack is not established as a classic volumetric flood.",
            "One labelled testbed cannot establish universal DoS detectability.",
        ],
    }
    return result, artifacts, classifier


def _test_block(records: Iterable[FrameRecord] | None = None) -> BlockData:
    """Materialize post-manifest TEST values only inside the guarded score path."""
    split = load_pretest_split()
    egress = sorted(
        (
            record for record in (iter_records() if records is None else records)
            if record.destination == EGRESS_DESTINATION
            and math.floor(record.timestamp / WINDOW_SECONDS) > split.final_pretest_bucket_id
        ),
        key=lambda record: (record.timestamp, record.record_index),
    )
    buckets: dict[int, list[FrameRecord]] = {}
    for record in egress:
        buckets.setdefault(math.floor(record.timestamp / WINDOW_SECONDS), []).append(record)
    emitted = tuple(sorted(
        bucket for bucket, values in buckets.items()
        if len(values) >= MIN_FRAMES_PER_WINDOW
    ))
    if len(emitted) <= 2 * GUARD_WINDOWS:
        return BlockData("test", (), (), {})
    selected = emitted[2 * GUARD_WINDOWS:]
    selected_set = set(selected)
    test_records = tuple(
        record for record in egress
        if math.floor(record.timestamp / WINDOW_SECONDS) in selected_set
    )
    categories = {
        bucket: frozenset(record.categorized_attack for record in buckets[bucket])
        for bucket in selected
    }
    return BlockData("test", test_records, selected, categories)


def score_frozen_test_once(
    confirmation: str, records: Iterable[FrameRecord] | None = None,
) -> dict:
    if confirmation != FROZEN_TEST_CONFIRMATION:
        raise PermissionError(
            "frozen TEST scoring requires the exact explicit confirmation token"
        )
    materialized = None if records is None else tuple(records)
    pretest, artifacts, classifier = prepare_experiment(materialized)
    test = _test_block(materialized)
    test_windows = build_scoring_windows(
        test, artifacts.type_map, artifacts.baselines, artifacts.thresholds,
    )
    result = dict(pretest)
    result.update({
        "status": "VALIDATED — ONE FROZEN TEST PASS",
        "split_window_counts": {
            **pretest["split_window_counts"], "test_unopened": None,
            "test": len(test_windows),
        },
        "test_counts": _counts(test_windows),
        "test_metrics": _evaluate(test_windows, artifacts.feature_names, classifier),
        "comparison_context": {
            "EXP-0004": (
                "egress-only; different 136 dominant-DoS-window category row; "
                "context only"
            ),
            "EXP-0005b": (
                "OUT OF SCOPE — bidirectional; different observation boundary; "
                "context only"
            ),
        },
    })
    return result


def write_result_atomic(result: Mapping, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--score-frozen-test", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.score_frozen_test:
        result = score_frozen_test_once(args.confirm)
        path = FINAL_RESULT_PATH
    else:
        result, _, _ = prepare_experiment()
        path = PRETEST_RESULT_PATH
    write_result_atomic(result, path)
    print(json.dumps(result, indent=2))
    print(f"\n[result -> {path}]")


if __name__ == "__main__":
    main()
