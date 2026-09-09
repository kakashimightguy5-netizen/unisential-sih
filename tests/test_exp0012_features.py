"""Causality and boundary tests for EXP-0012 lag/trend features."""
from dataclasses import replace
from types import MappingProxyType

import pytest

from exp0008_cadence_features import CadenceWindow
from exp0012_features import HISTORY_WINDOWS, LAG_FEATURE_NAMES, augment_sequence, augment_sequences


def window(index, value_03, value_10=0.0):
    return CadenceWindow(
        bucket_index=index,
        features=MappingProxyType({
            "func_03_deviation_mean": float(value_03),
            "func_10_deviation_mean": float(value_10),
            "existing": float(index),
        }),
        categories=frozenset({0}),
    )


def test_lags_trends_use_exactly_five_prior_windows():
    rows = tuple(window(index, index, index * 2) for index in range(7))
    augmented, excluded = augment_sequence(rows)
    assert excluded == HISTORY_WINDOWS == 5
    first = augmented[0]
    assert first.bucket_index == 5
    assert [first.features[f"func_03_deviation_lag_{lag}"] for lag in range(1, 6)] == [4, 3, 2, 1, 0]
    assert first.features["func_03_deviation_prior_5_slope"] == pytest.approx(1.0)
    assert first.features["func_03_deviation_prior_5_direction"] == 1.0
    assert first.features["func_03_deviation_prior_5_variance"] == pytest.approx(2.0)
    assert first.features["func_10_deviation_prior_5_slope"] == pytest.approx(2.0)
    assert len(LAG_FEATURE_NAMES) == 16


def test_current_and_future_mutation_cannot_change_current_lag_vector():
    rows = tuple(window(index, index) for index in range(8))
    changed = list(rows)
    changed[5] = window(5, 99_999)
    changed[6] = window(6, -99_999)
    left, _ = augment_sequence(rows)
    right, _ = augment_sequence(tuple(changed))
    left_at_five = next(item for item in left if item.bucket_index == 5)
    right_at_five = next(item for item in right if item.bucket_index == 5)
    assert {
        name: left_at_five.features[name] for name in LAG_FEATURE_NAMES
    } == {
        name: right_at_five.features[name] for name in LAG_FEATURE_NAMES
    }
    assert left_at_five.features["func_03_deviation_mean"] != right_at_five.features["func_03_deviation_mean"]


def test_independent_sequences_reset_history_and_exclude_each_prefix():
    first = tuple(window(index, index) for index in range(7))
    second = tuple(window(100 + index, 100 + index) for index in range(6))
    augmented, excluded = augment_sequences((first, second))
    assert excluded == 10
    assert [item.bucket_index for item in augmented] == [5, 6, 105]
    last = augmented[-1]
    assert last.features["func_03_deviation_lag_1"] == 104
    assert last.features["func_03_deviation_lag_5"] == 100
    assert all(name in last.features for name in LAG_FEATURE_NAMES)
