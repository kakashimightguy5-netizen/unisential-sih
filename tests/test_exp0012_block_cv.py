"""Temporal-split, fold isolation, and selection tests for EXP-0012."""
from types import MappingProxyType

import numpy as np
import pytest

import exp0012_block_cv as experiment
from exp0008_cadence_features import BlockData, CadenceBaseline, CadenceWindow


def timeline(size=120):
    buckets = tuple(range(size))
    categories = MappingProxyType({
        bucket: frozenset({6}) if bucket % 6 == 3 else frozenset({0})
        for bucket in buckets
    })
    return experiment.PreTestTimeline(
        buckets=buckets, records=(), categories=categories,
        total_egress_frames=0, total_emitted_windows=size,
        test_window_count_unopened=30,
    )


def aggregate(precision, recall, f1, fpr, recall_variance=0.0):
    return {
        "precision": {"mean": precision, "population_variance": 0.0},
        "recall": {"mean": recall, "population_variance": recall_variance},
        "f1": {"mean": f1, "population_variance": 0.0},
        "fpr": {"mean": fpr, "population_variance": 0.0},
    }


def test_forward_folds_are_contiguous_guarded_disjoint_and_past_only():
    folds, report = experiment.build_forward_folds(timeline())
    assert len(folds) == 5
    validation_positions = []
    for fold in folds:
        training = [position for segment in fold.train_segments for position in segment.positions]
        validation = list(fold.validation_segment.positions)
        assert validation == list(range(validation[0], validation[-1] + 1))
        assert max(training) < min(validation)
        validation_positions.extend(validation)
        assert experiment._segment_counts(fold.validation_segment)["dos"] > 0
    assert len(validation_positions) == len(set(validation_positions))
    guards = set(report["guard_positions"])
    assert guards
    assert not guards.intersection(validation_positions)
    assert all(
        not guards.intersection(segment.positions)
        for fold in folds for segment in (*fold.train_segments, fold.validation_segment)
    )


def test_boundary_selection_reports_failure_when_too_few_positives():
    categories = [frozenset({0}) for _ in range(30)]
    categories[2] = frozenset({6})
    with pytest.raises(ValueError, match="at least 6 DoS"):
        experiment.stratified_contiguous_boundaries(categories)


def test_fold_preprocessing_uses_training_segments_only(monkeypatch):
    train_block = BlockData("train", (), tuple(range(8)), MappingProxyType({i: frozenset({0}) for i in range(8)}))
    validation_block = BlockData("validation", (), tuple(range(20, 28)), MappingProxyType({i: frozenset({6}) for i in range(20, 28)}))
    fold = experiment.Fold(
        number=1,
        train_segments=(experiment.Segment(1, tuple(range(8)), train_block),),
        validation_segment=experiment.Segment(2, tuple(range(20, 28)), validation_block),
    )
    calls = []
    type_map = MappingProxyType({(3, 0, 23, 18, 0): 3, (16, 0, 8, -1, 0): 16})
    baselines = MappingProxyType({
        3: CadenceBaseline(3, 10, 2.0, 2.0, 0.5, 0.25),
        16: CadenceBaseline(16, 10, 2.0, 2.0, 0.5, 0.25),
    })
    thresholds = MappingProxyType({3: 1.0, 16: 1.0})
    monkeypatch.setattr(experiment, "_discover_fold_types", lambda segments: calls.append(("types", tuple(s.number for s in segments))) or type_map)
    monkeypatch.setattr(experiment, "_pooled_baselines", lambda segments, mapping: calls.append(("baselines", tuple(s.number for s in segments))) or baselines)
    monkeypatch.setattr(experiment, "_pooled_thresholds", lambda segments, mapping, values: calls.append(("thresholds", tuple(s.number for s in segments))) or thresholds)

    def build(block, *args):
        calls.append(("build", block.name))
        return tuple(CadenceWindow(
            bucket_index=bucket,
            features=MappingProxyType({
                "func_03_deviation_mean": 0.0,
                "func_10_deviation_mean": 0.0,
            }), categories=block.categories[bucket],
        ) for bucket in block.emitted_buckets)

    monkeypatch.setattr(experiment, "build_scoring_windows", build)
    experiment._build_fold_windows(fold)
    assert calls[:3] == [("types", (1,)), ("baselines", (1,)), ("thresholds", (1,))]
    assert calls[3:] == [("build", "train"), ("build", "validation")]


def test_resampling_is_train_only_and_validation_remains_unchanged(monkeypatch):
    seen = {}

    class Sampler:
        def __init__(self, **kwargs):
            seen["sampler_parameters"] = kwargs

        def fit_resample(self, matrix, labels):
            seen["resample_matrix"] = matrix.copy()
            return matrix, labels

    class Model:
        def set_params(self, **kwargs):
            seen["model_parameters"] = kwargs

        def fit(self, matrix, labels):
            seen["fit_rows"] = len(matrix)

        def predict_proba(self, matrix):
            seen["validation_matrix"] = matrix.copy()
            probability = np.full(len(matrix), 0.5)
            return np.column_stack((1 - probability, probability))

    monkeypatch.setattr(experiment, "BorderlineSMOTE", Sampler)
    monkeypatch.setattr(experiment, "make_random_forest", lambda class_weight: Model())
    x_train = np.arange(20, dtype=float).reshape(10, 2)
    y_train = np.array([0, 1] * 5)
    x_validation = np.array([[100.0, 101.0], [102.0, 103.0]])
    before = x_validation.copy()
    metrics, counts = experiment.evaluate_configuration(
        x_train, y_train, x_validation, np.array([0, 1]),
    )
    assert np.array_equal(seen["resample_matrix"], x_train)
    assert np.array_equal(seen["validation_matrix"], before)
    assert np.array_equal(x_validation, before)
    assert seen["sampler_parameters"] == {
        "sampling_strategy": "auto", "k_neighbors": 5, "random_state": 0,
    }
    assert seen["model_parameters"] == {"max_depth": None, "min_samples_leaf": 1}
    assert counts["input_rows"] == 10
    assert metrics["tn"] + metrics["fp"] == 1
    assert metrics["fn"] + metrics["tp"] == 1


def test_metric_aggregation_and_preregistered_selection_rule():
    rows = [
        {"precision": 0.8, "recall": 0.2, "f1": 0.32, "fpr": 0.1},
        {"precision": 1.0, "recall": 0.4, "f1": 0.57, "fpr": 0.0},
    ]
    summary = experiment.aggregate_metrics(rows)
    assert summary["recall"]["mean"] == pytest.approx(0.3)
    assert summary["recall"]["population_variance"] == pytest.approx(0.01)
    selected = experiment.select_configuration({
        "X": aggregate(0.9, 0.3, 0.45, 0.01),
        "Y": aggregate(0.8, 0.4, 0.50, 0.02),
    })
    assert selected["winner"] == "Y"
    assert selected["precision_floor_satisfied"]
    tied = experiment.select_configuration({
        "X": aggregate(0.8, 0.4, 0.5, 0.01),
        "Y": aggregate(0.8, 0.4, 0.5, 0.01),
    })
    assert tied["winner"] == "X"
    fallback = experiment.select_configuration({
        "X": aggregate(0.7, 0.5, 0.4, 0.02),
        "Y": aggregate(0.7, 0.4, 0.5, 0.01),
    })
    assert fallback["winner"] == "Y"
    assert not fallback["precision_floor_satisfied"]


def test_module_has_no_frozen_test_path_or_scorer():
    assert not hasattr(experiment, "score_frozen_test_once")
    assert "test" not in experiment.RESULT_PATH.name
    assert experiment.PROBABILITY_THRESHOLD == 0.50
    assert experiment.FOLDS == 5
