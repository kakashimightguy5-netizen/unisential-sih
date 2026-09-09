"""Synthetic tests for EXP-0007 cadence feature calculations."""
from dataclasses import replace

import numpy as np
import pytest

from cadence_features import (
    CADENCE_FEATURES, CUSUM_ALLOWANCE, CadenceBaseline, _event_values,
    _normal_gaps, _replay_raw_cusum, _thresholds, response_type,
)
from features_txt import FrameRecord


def record(index, timestamp, *, function=3, source=3, destination=1, category=0):
    shape = {3: (23, 18), 16: (8, -1)}[function]
    return FrameRecord(
        record_index=index, frame_id=index, address=4, function_code=function,
        frame_len_bytes=shape[0], is_request=0, start_register=-1,
        quantity=-1, byte_count=shape[1], length_anomaly=0,
        rare_function_code=0, crc_ok=0, interarrival_seconds=0.0,
        message_entropy_bits_per_byte=0.0, categorized_attack=category,
        specific_attack=0, source=source, destination=destination,
        timestamp=timestamp,
    )


def baseline(function=3, expected=2.0, deviation=0.5):
    return CadenceBaseline(function, 10, expected, expected, deviation, deviation / expected)


def test_response_type_enforces_egress_source_and_parser_certain_shape():
    valid = record(1, 1.0)
    assert response_type(valid) == 3
    assert response_type(replace(valid, destination=3)) is None
    assert response_type(replace(valid, source=2)) is None
    assert response_type(replace(valid, frame_len_bytes=8)) is None
    assert response_type(record(2, 2.0, function=16)) == 16


def test_per_type_normal_gaps_are_independent_and_reset_on_attack():
    rows = [
        record(1, 0.2, function=3), record(2, 0.3, function=16),
        record(3, 2.2, function=3), record(4, 4.3, function=16),
        record(5, 5.2, function=3, category=6),
        record(6, 10.2, function=3), record(7, 12.2, function=3),
    ]
    emitted = [0, 1, 2]
    categories = {0: frozenset({0}), 1: frozenset({6}), 2: frozenset({0})}
    gaps = _normal_gaps(rows, emitted, categories, np.array([0, 1, 2]), lambda r: r.function_code)
    assert gaps[3] == pytest.approx([2.0, 2.0])
    assert gaps[16] == pytest.approx([4.0])


def test_event_deviation_and_missed_cycle_are_hand_calculated():
    values = _event_values(6.1, baseline())
    assert values["deviation"] == pytest.approx(4.1)
    assert values["positive_z"] == pytest.approx(8.2)
    assert values["missed_cycles"] == 2
    assert _event_values(1.8, baseline())["positive_z"] == 0


def test_cusum_replay_records_crossing_then_resets():
    rows = [record(1, 0.1), record(2, 2.1), record(3, 5.1), record(4, 7.1)]
    values = _replay_raw_cusum(
        rows, [0, 1], np.array([0, 1]), {3: baseline(), 16: baseline(16)},
        {3: 1.0, 16: 1.0},
    )
    crossing = values[1][3][0]
    assert crossing["cusum"] == pytest.approx(1.5)
    assert crossing["alarm"] == 1.0
    assert crossing["cusum_end"] == 0.0
    assert values[1][3][1]["cusum"] == 0.0


def test_threshold_uses_train_normal_higher_quantile():
    rows = [record(i, timestamp) for i, timestamp in enumerate((0.1, 2.1, 5.1, 9.1), 1)]
    thresholds = _thresholds(
        rows, [0, 1], {0: frozenset({0}), 1: frozenset({0})}, np.array([0, 1]),
        {3: baseline(), 16: baseline(16)},
    )
    assert thresholds[3] >= CUSUM_ALLOWANCE
    assert thresholds[16] == CUSUM_ALLOWANCE


def test_model_feature_names_exclude_forbidden_metadata():
    forbidden = ("destination", "category", "label", "timestamp", "bucket")
    assert not any(word in name for name in CADENCE_FEATURES for word in forbidden)
    assert not any(name == "source" or name.startswith("source_") for name in CADENCE_FEATURES)
