#!/usr/bin/env python3
"""TRAIN+VALIDATION-only forward block CV for EXP-0012b."""
from __future__ import annotations

import json
import math
import os
import platform
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from statistics import mean, pstdev, pvariance
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence

import numpy as np
from imblearn.over_sampling import BorderlineSMOTE

from exp0008_cadence import _cohort, _labels, _matrix, binary_metrics
from exp0008_cadence_features import (
    CUSUM_ALLOWANCE, DOS_CATEGORY, EGRESS_DESTINATION, BlockData, CadenceBaseline,
    CadenceWindow, _baseline, _normal_gaps, build_scoring_windows,
    discover_response_types, feature_names_for, partition_pretest_inputs, replay_cusum,
)
from exp0009_variants import make_random_forest
from exp0012_features import LAG_FEATURE_NAMES, augment_sequences
from features_txt import FrameRecord

FOLDS = 5
SEGMENTS = FOLDS + 1
GUARD_WINDOWS = 1
PROBABILITY_THRESHOLD = 0.50
MEAN_PRECISION_FLOOR = 0.80
RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0012b_block_cv.json"
)
METRIC_NAMES = ("precision", "recall", "f1", "fpr")


@dataclass(frozen=True)
class Segment:
    number: int
    positions: tuple[int, ...]
    block: BlockData


@dataclass(frozen=True)
class Fold:
    number: int
    train_segments: tuple[Segment, ...]
    validation_segment: Segment


@dataclass(frozen=True)
class PreTestTimeline:
    buckets: tuple[int, ...]
    records: tuple[FrameRecord, ...]
    categories: Mapping[int, frozenset[int]]
    total_egress_frames: int
    total_emitted_windows: int
    test_window_count_unopened: int | None
    split_id: str = "synthetic-unspecified"
    split_membership_sha256: str = "synthetic-unspecified"


def prepare_pretest_timeline(
    records: Iterable[FrameRecord] | None = None,
) -> PreTestTimeline:
    """Materialize only the established TRAIN and VALIDATION partitions."""
    inputs = partition_pretest_inputs(records)
    buckets = inputs.train.emitted_buckets + inputs.validation.emitted_buckets
    categories = {
        **dict(inputs.train.categories), **dict(inputs.validation.categories),
    }
    pretest_records = tuple(sorted(
        (*inputs.train.records, *inputs.validation.records),
        key=lambda item: (item.timestamp, item.record_index),
    ))
    if any(item.destination != EGRESS_DESTINATION for item in pretest_records):
        raise ValueError("EXP-0012b accepts egress-only records")
    return PreTestTimeline(
        buckets=buckets, records=pretest_records,
        categories=MappingProxyType(categories),
        total_egress_frames=inputs.total_egress_frames,
        total_emitted_windows=inputs.train_window_count + inputs.validation_window_count,
        test_window_count_unopened=inputs.test_window_count,
        split_id=inputs.split_id,
        split_membership_sha256=inputs.split_membership_sha256,
    )


def stratified_contiguous_boundaries(
    categories: Sequence[frozenset[int]],
    segments: int = SEGMENTS,
) -> tuple[int, ...]:
    """Place contiguous cuts at positive-count quantiles without shuffling rows."""
    positives = [index for index, values in enumerate(categories) if DOS_CATEGORY in values]
    if len(positives) < segments:
        raise ValueError(f"need at least {segments} DoS windows for {segments} segments")
    boundaries = [0]
    for part in range(1, segments):
        positive_offset = math.ceil(part * len(positives) / segments) - 1
        left_positive = positives[positive_offset]
        right_positive = positives[positive_offset + 1]
        cut = (left_positive + right_positive + 1) // 2
        cut = max(boundaries[-1] + 2 * GUARD_WINDOWS + 1, cut)
        if cut >= len(categories) - (segments - part) * (2 * GUARD_WINDOWS + 1):
            raise ValueError("positive-stratified cuts cannot preserve guards and segments")
        boundaries.append(cut)
    boundaries.append(len(categories))
    return tuple(boundaries)


def _make_block(
    timeline: PreTestTimeline, number: int, positions: Sequence[int], name: str,
) -> BlockData:
    buckets = tuple(timeline.buckets[position] for position in positions)
    bucket_set = set(buckets)
    return BlockData(
        name=name,
        records=tuple(
            item for item in timeline.records
            if math.floor(item.timestamp / 5.0) in bucket_set
        ),
        emitted_buckets=buckets,
        categories=MappingProxyType({
            bucket: timeline.categories[bucket] for bucket in buckets
        }),
    )


def build_forward_folds(timeline: PreTestTimeline) -> tuple[tuple[Fold, ...], dict]:
    category_rows = tuple(timeline.categories[bucket] for bucket in timeline.buckets)
    boundaries = stratified_contiguous_boundaries(category_rows)
    segments: list[Segment] = []
    guards: set[int] = set()
    for boundary in boundaries[1:-1]:
        guards.update((boundary - 1, boundary))
    for number, (start, stop) in enumerate(zip(boundaries, boundaries[1:]), start=1):
        usable_start = start + (GUARD_WINDOWS if start else 0)
        usable_stop = stop - (GUARD_WINDOWS if stop < len(category_rows) else 0)
        positions = tuple(range(usable_start, usable_stop))
        segments.append(Segment(
            number=number, positions=positions,
            block=_make_block(timeline, number, positions, f"segment-{number}"),
        ))
    folds = tuple(
        Fold(number=index, train_segments=tuple(segments[:index]),
             validation_segment=segments[index])
        for index in range(1, SEGMENTS)
    )
    return folds, {
        "boundaries": list(boundaries),
        "guard_positions": sorted(guards),
        "guard_bucket_indices": [timeline.buckets[index] for index in sorted(guards)],
        "segments": [_segment_counts(item) for item in segments],
    }


def _segment_counts(segment: Segment) -> dict:
    categories = [segment.block.categories[bucket] for bucket in segment.block.emitted_buckets]
    normal = sum(values == frozenset({0}) for values in categories)
    dos = sum(DOS_CATEGORY in values for values in categories)
    return {
        "segment": segment.number,
        "position_start": segment.positions[0] if segment.positions else None,
        "position_stop_exclusive": segment.positions[-1] + 1 if segment.positions else None,
        "windows": len(categories), "normal": normal, "dos": dos,
        "other_or_mixed_excluded_from_binary_cohort": len(categories) - normal - dos,
    }


def _pooled_baselines(
    train_segments: Sequence[Segment], type_map: Mapping,
) -> Mapping[int, CadenceBaseline]:
    pooled: dict[int, list[float]] = {
        response_type: [] for response_type in sorted(set(type_map.values()))
    }
    for segment in train_segments:
        gaps = _normal_gaps(segment.block, type_map)
        for response_type in pooled:
            pooled[response_type].extend(gaps[response_type])
    return MappingProxyType({
        response_type: _baseline(response_type, gaps)
        for response_type, gaps in pooled.items() if gaps
    })


def _pooled_thresholds(
    train_segments: Sequence[Segment], type_map: Mapping,
    baselines: Mapping[int, CadenceBaseline],
) -> Mapping[int, float]:
    maxima = {response_type: [] for response_type in baselines}
    for segment in train_segments:
        replay = replay_cusum(segment.block, type_map, baselines)
        for response_type in baselines:
            for bucket in segment.block.emitted_buckets:
                if segment.block.categories[bucket] != frozenset({0}):
                    continue
                events = replay.get(bucket, {}).get(response_type, ())
                maxima[response_type].append(max(
                    (event["cusum"] for event in events), default=0.0,
                ))
    return MappingProxyType({
        response_type: max(
            CUSUM_ALLOWANCE,
            float(np.quantile(values, 0.99, method="higher")),
        ) for response_type, values in maxima.items()
    })


def _discover_fold_types(train_segments: Sequence[Segment]) -> Mapping:
    shapes: dict = {}
    for segment in train_segments:
        shapes.update(discover_response_types(segment.block))
    return MappingProxyType(dict(sorted(shapes.items())))


def _build_fold_windows(
    fold: Fold,
) -> tuple[tuple[CadenceWindow, ...], tuple[CadenceWindow, ...], Mapping]:
    type_map = _discover_fold_types(fold.train_segments)
    baselines = _pooled_baselines(fold.train_segments, type_map)
    thresholds = _pooled_thresholds(fold.train_segments, type_map, baselines)
    training_sequences = tuple(
        build_scoring_windows(segment.block, type_map, baselines, thresholds)
        for segment in fold.train_segments
    )
    validation_sequence = build_scoring_windows(
        fold.validation_segment.block, type_map, baselines, thresholds,
    )
    train_augmented, train_history_excluded = augment_sequences(training_sequences)
    validation_augmented, validation_history_excluded = augment_sequences(
        (validation_sequence,),
    )
    return train_augmented, validation_augmented, {
        "type_shapes": [list(shape) for shape in type_map],
        "baselines": {
            f"0x{key:02x}": {
                "count": value.count, "mean": value.expected_iat,
                "median": value.median_iat, "std": value.std_iat, "cv": value.cv,
            } for key, value in baselines.items()
        },
        "cusum_thresholds": {
            f"0x{key:02x}": value for key, value in thresholds.items()
        },
        "train_history_excluded": train_history_excluded,
        "validation_history_excluded": validation_history_excluded,
    }


def _paired_matrices(
    train: Sequence[CadenceWindow], validation: Sequence[CadenceWindow],
    original_names: Sequence[str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    train_indices = _cohort(train)
    validation_indices = _cohort(validation)
    y_train = _labels(train, train_indices)
    y_validation = _labels(validation, validation_indices)
    names_y = (*original_names, *LAG_FEATURE_NAMES)
    return (
        _matrix(train, original_names)[train_indices],
        _matrix(validation, original_names)[validation_indices],
        _matrix(train, names_y)[train_indices],
        _matrix(validation, names_y)[validation_indices],
        y_train, y_validation,
    )


def evaluate_configuration(
    x_train: np.ndarray, y_train: np.ndarray,
    x_validation: np.ndarray, y_validation: np.ndarray,
) -> tuple[dict, dict]:
    sampler = BorderlineSMOTE(
        sampling_strategy="auto", k_neighbors=5, random_state=0,
    )
    resampled_x, resampled_y = sampler.fit_resample(x_train, y_train)
    model = make_random_forest(class_weight=None)
    model.set_params(max_depth=None, min_samples_leaf=1)
    model.fit(resampled_x, resampled_y)
    probabilities = model.predict_proba(x_validation)[:, 1]
    predictions = (probabilities >= PROBABILITY_THRESHOLD).astype(int)
    return binary_metrics(y_validation, predictions), {
        "input_rows": len(y_train),
        "input_normal": int((y_train == 0).sum()),
        "input_dos": int((y_train == 1).sum()),
        "resampled_rows": len(resampled_y),
        "resampled_normal": int((resampled_y == 0).sum()),
        "resampled_dos": int((resampled_y == 1).sum()),
    }


def aggregate_metrics(rows: Sequence[Mapping]) -> dict:
    return {
        metric: {
            "mean": mean(float(row[metric]) for row in rows),
            "population_variance": pvariance(float(row[metric]) for row in rows),
            "population_std": pstdev(float(row[metric]) for row in rows),
        } for metric in METRIC_NAMES
    }


def select_configuration(aggregates: Mapping[str, Mapping]) -> dict:
    feasible = [
        name for name in ("X", "Y")
        if aggregates[name]["precision"]["mean"] >= MEAN_PRECISION_FLOOR
    ]
    candidates = feasible or ["X", "Y"]

    def rank(name: str) -> tuple[float, ...]:
        values = aggregates[name]
        if feasible:
            return (
                values["recall"]["mean"], values["f1"]["mean"],
                values["precision"]["mean"], -values["fpr"]["mean"],
                -values["recall"]["population_variance"],
                float(name == "X"),
            )
        return (
            values["f1"]["mean"], values["recall"]["mean"],
            values["precision"]["mean"], -values["fpr"]["mean"],
            -values["recall"]["population_variance"],
            float(name == "X"),
        )

    winner = max(candidates, key=rank)
    return {
        "winner": winner,
        "precision_floor": MEAN_PRECISION_FLOOR,
        "precision_floor_satisfied": bool(feasible),
        "feasible_configurations": feasible,
        "rule": (
            "feasible mean precision >= 0.80; maximize mean recall, mean F1, "
            "mean precision, lower mean FPR, lower recall variance; exact tie X. "
            "If neither feasible, maximize mean F1 then the remaining criteria."
        ),
        "recommendation": (
            "Configuration Y may proceed to one later explicitly authorized frozen TEST"
            if winner == "Y" else
            "Retain already-tested EXP-0011b Configuration X; do not rerun frozen TEST"
        ),
    }


def run_block_cv(records: Iterable[FrameRecord] | None = None) -> dict:
    """Evaluate EXP-0012b using TRAIN+VALIDATION only; TEST is never materialized."""
    materialized = None if records is None else tuple(records)
    timeline = prepare_pretest_timeline(materialized)
    folds, layout = build_forward_folds(timeline)
    rows = {"X": [], "Y": []}
    original_names: tuple[str, ...] | None = None
    fold_reports = []
    for fold in folds:
        train, validation, preprocessing = _build_fold_windows(fold)
        if original_names is None:
            response_types = tuple(
                int(name, 16) for name in preprocessing["baselines"]
            )
            original_names = feature_names_for(response_types)
        x_train, x_validation, y_train_x, y_validation_x, labels_train, labels_validation = (
            _paired_matrices(train, validation, original_names)
        )
        metrics_x, counts_x = evaluate_configuration(
            x_train, labels_train, x_validation, labels_validation,
        )
        metrics_y, counts_y = evaluate_configuration(
            y_train_x, labels_train, y_validation_x, labels_validation,
        )
        rows["X"].append(metrics_x)
        rows["Y"].append(metrics_y)
        fold_reports.append({
            "fold": fold.number,
            "train_segments": [item.number for item in fold.train_segments],
            "validation_segment": fold.validation_segment.number,
            "train_position_stop": max(
                position for segment in fold.train_segments for position in segment.positions
            ),
            "validation_position_start": fold.validation_segment.positions[0],
            "preprocessing": preprocessing,
            "validation_cohort": {
                "rows": len(labels_validation),
                "normal": int((labels_validation == 0).sum()),
                "dos": int((labels_validation == 1).sum()),
            },
            "X": {"metrics": metrics_x, "training": counts_x},
            "Y": {"metrics": metrics_y, "training": counts_y},
        })
    assert original_names is not None
    aggregates = {name: aggregate_metrics(metrics) for name, metrics in rows.items()}
    selection = select_configuration(aggregates)
    return {
        "status": "VALIDATED — TRAIN+VALIDATION BLOCK CV ONLY; TEST NOT RUN",
        "experiment": "EXP-0012b",
        "scope": {
            "direction": "egress only", "destination": EGRESS_DESTINATION,
            "pretest_egress_frames_through_validation_end": timeline.total_egress_frames,
            "pretest_emitted_windows": timeline.total_emitted_windows,
            "test_window_count_unopened": timeline.test_window_count_unopened,
        },
        "integrity": {
            "test_materialized": False,
            "split_id": timeline.split_id,
            "split_membership_sha256": timeline.split_membership_sha256,
            "partition_source": "exact tracked TRAIN/VALIDATION bucket membership",
            "cv_population": "existing TRAIN+VALIDATION only",
            "fold_style": "five-fold contiguous past-only expanding",
            "guard_windows_each_boundary_side": GUARD_WINDOWS,
            "threshold_sweep": False,
            "probability_threshold": PROBABILITY_THRESHOLD,
            "history_windows": 5,
            "same_or_future_lag_inputs": False,
            "payload_or_availability_features": [],
        },
        "layout": layout,
        "configurations": {
            "X": {"feature_count": len(original_names), "features": list(original_names)},
            "Y": {
                "feature_count": len(original_names) + len(LAG_FEATURE_NAMES),
                "features": [*original_names, *LAG_FEATURE_NAMES],
            },
            "common": {
                "sampler": "BorderlineSMOTE",
                "sampling_strategy": "auto", "k_neighbors": 5,
                "m_neighbors": 10, "kind": "borderline-1",
                "sampler_random_state": 0,
                "model": "RandomForestClassifier", "n_estimators": 300,
                "class_weight": None, "random_state": 0, "n_jobs": -1,
                "max_depth": None, "min_samples_leaf": 1,
            },
        },
        "folds": fold_reports,
        "aggregates": aggregates,
        "selection": selection,
        "comparison_context": {
            "EXP-0011b_single_validation": {
                "precision": 0.9636363636363636,
                "recall": 0.5221674876847291,
                "f1": 0.6773162939297125,
                "fpr": 0.0008244023083264633,
            },
            "EXP-0011b_frozen_test": {
                "precision": 0.9122807017543859,
                "recall": 0.2694300518134715,
                "f1": 0.416,
                "fpr": 0.001040149781568546,
            },
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "scikit_learn": version("scikit-learn"),
            "imbalanced_learn": version("imbalanced-learn"),
        },
        "limitations": [
            "Positive-stratified boundaries improve balance but cannot equalize contiguous temporal regimes.",
            "Early forward folds use materially less training data than later folds.",
            "One labelled testbed cannot establish universal DoS detectability.",
            "The labelled attack is not established as a classic volumetric flood.",
        ],
    }


def _json_ready(value):
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_ready(item) for item in value]
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


def main() -> None:
    result = run_block_cv()
    write_result_atomic(result)
    print(json.dumps(_json_ready(result), indent=2))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
